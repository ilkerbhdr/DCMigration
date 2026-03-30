"""Tek arka plan thread ile monitor oturumu yönetimi.

İki katmanlı polling:
- Hızlı poll (her N sn): show interfaces status → status değişikliği
- Derin poll (her 60 sn): LLDP + MAC + VLAN + errors → tüm alanlar
- Port connected'a geçince → o switch için anında derin poll

Tüm istemciler aynı SSH bağlantılarını paylaşır.
Değişiklikler DB'ye yazılır + SSE event queue'ya eklenir.
"""
import json
import queue
import threading
import time
from datetime import datetime

from netmiko import NetmikoTimeoutException, NetmikoAuthenticationException

from port_monitor import create_connection, get_hostname, get_port_statuses, compute_diff, try_reconnect
from switch_collector import collect_deep_data
from database import (
    db_create_session, db_end_session, db_get_active_session,
    db_add_change, db_update_monitor_state, db_log_event,
    db_upsert_live_ports_bulk, db_update_live_port_status,
)
from webhook_notifier import send_notification

# Global state
_session_lock = threading.Lock()
_active_thread = None
_active_session_id = None
_event_queues = []
_queues_lock = threading.Lock()

# Deep poll tetikleme
_deep_poll_trigger = threading.Event()
DEEP_POLL_INTERVAL = 60  # saniye


def start_session(jobs, interval=3, firewall=None):
    """Monitor oturumunu başlatır (arka plan thread).

    Args:
        jobs: [{"host": ip, "username": ..., "password": ..., "port": 22}]
        interval: Hızlı poll aralığı (saniye)
        firewall: Optional {"host", "username", "password", "port"} for ARP lookup

    Returns:
        session_id veya None (zaten aktifse)
    """
    global _active_thread, _active_session_id

    with _session_lock:
        if _active_thread and _active_thread.is_alive():
            return None

        switch_list = [{"host": j["host"]} for j in jobs]
        session_id = db_create_session(switch_list, interval)
        _active_session_id = session_id

        _deep_poll_trigger.clear()

        _active_thread = threading.Thread(
            target=_poll_loop,
            args=(session_id, jobs, interval, firewall),
            daemon=True,
        )
        _active_thread.start()

        return session_id


def stop_session():
    global _active_thread, _active_session_id

    with _session_lock:
        sid = _active_session_id
        _active_session_id = None
        _active_thread = None

    if sid:
        db_end_session(sid)
        db_log_event("monitor_stop", {"session_id": sid})
        _broadcast_event("stopped", {"session_id": sid})


def get_active_session_id():
    return _active_session_id


def is_active():
    return _active_thread is not None and _active_thread.is_alive()


def trigger_deep_poll_now():
    """Tüm switch'ler için anında derin poll tetikler."""
    _deep_poll_trigger.set()


def register_client():
    q = queue.Queue(maxsize=500)
    with _queues_lock:
        _event_queues.append(q)
    return q


def unregister_client(q):
    with _queues_lock:
        if q in _event_queues:
            _event_queues.remove(q)


def broadcast_event(event_type, data):
    """Tüm bağlı SSE istemcilerine event gönderir (public API)."""
    payload = json.dumps(data, ensure_ascii=False)
    msg = f"event: {event_type}\ndata: {payload}\n\n"

    with _queues_lock:
        dead = []
        for q in _event_queues:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _event_queues.remove(q)


# Internal alias
_broadcast_event = broadcast_event


def _poll_loop(session_id, jobs, interval, firewall=None):
    """Ana polling döngüsü — iki katmanlı."""
    switches = []

    # --- Bağlantıları kur ---
    for job in jobs:
        host = job["host"]
        dev_type = job.get("device_type", "arista_eos")
        try:
            conn = create_connection(host, job["username"], job["password"], job["port"], dev_type)
            hostname = get_hostname(conn)
            current = get_port_statuses(conn, dev_type)

            sw = {
                "host": host,
                "username": job["username"],
                "password": job["password"],
                "port": job["port"],
                "device_type": dev_type,
                "conn": conn,
                "hostname": hostname,
                "previous": current,
                "alive": True,
                "last_deep_poll": 0,
            }
            switches.append(sw)

            db_update_monitor_state(session_id, host, hostname, json.dumps(current, ensure_ascii=False))

            # İlk snapshot — live_ports'a da yaz
            initial_ports = []
            for port_name, info in current.items():
                initial_ports.append({
                    "port": port_name,
                    "status": info["status"],
                    "description": info.get("description", ""),
                    "port_type": info.get("port_type", ""),
                })
            db_upsert_live_ports_bulk(session_id, host, hostname, initial_ports)

            _broadcast_event("snapshot", {
                "host": host, "hostname": hostname,
                "timestamp": datetime.now().isoformat(), "ports": current,
            })

        except NetmikoTimeoutException:
            _broadcast_event("switch_error", {"host": host, "error": f"SSH zaman aşımı — {host}:{job['port']}"})
        except NetmikoAuthenticationException:
            _broadcast_event("switch_error", {"host": host, "error": f"Kimlik doğrulama hatası — {host}"})
        except Exception as e:
            _broadcast_event("switch_error", {"host": host, "error": f"Bağlantı hatası — {host}: {str(e)}"})

    if not switches:
        _broadcast_event("error", {"error": "Hiçbir switch'e bağlanılamadı."})
        db_end_session(session_id)
        return

    _broadcast_event("connected", {
        "count": len(switches),
        "hosts": [s["hostname"] for s in switches],
        "timestamp": datetime.now().isoformat(),
    })

    db_log_event("monitor_start", {
        "session_id": session_id,
        "switches": [s["hostname"] for s in switches],
        "interval": interval,
    })

    # ARP tablosu (firewall varsa)
    arp_table = {}
    if firewall and firewall.get("host"):
        try:
            from firewall_collector import collect_arp_table
            arp_table = collect_arp_table(
                firewall["host"], firewall["username"],
                firewall["password"], int(firewall.get("port", 22)),
            )
            _broadcast_event("info", {"message": f"Firewall ARP: {len(arp_table)} kayıt alındı."})
        except Exception as e:
            _broadcast_event("switch_error", {"host": firewall["host"], "error": f"Firewall hatası: {str(e)}"})

    # --- Polling döngüsü ---
    poll_count = 0

    try:
        while _active_session_id == session_id:
            time.sleep(interval)
            if _active_session_id != session_id:
                break

            poll_count += 1
            now_ts = time.time()
            all_changes = []
            global_summary = {"total": 0, "connected": 0, "notconnect": 0, "disabled": 0}
            deep_poll_triggered = _deep_poll_trigger.is_set()
            if deep_poll_triggered:
                _deep_poll_trigger.clear()

            for sw in switches:
                if not sw["alive"]:
                    continue

                host = sw["host"]

                # --- Hızlı poll ---
                try:
                    dt = sw.get("device_type", "arista_eos")
                    current = get_port_statuses(sw["conn"], dt)
                except Exception as e:
                    _broadcast_event("connection_lost", {
                        "host": host, "hostname": sw["hostname"],
                        "error": str(e), "timestamp": datetime.now().isoformat(),
                    })
                    try:
                        sw["conn"].disconnect()
                    except Exception:
                        pass

                    dt = sw.get("device_type", "arista_eos")
                    new_conn = try_reconnect(host, sw["username"], sw["password"], sw["port"], dt)
                    if new_conn is None:
                        sw["alive"] = False
                        db_update_monitor_state(session_id, host, sw["hostname"], "{}", alive=False)
                        _broadcast_event("switch_error", {"host": host, "error": f"Yeniden bağlanılamadı — {host}"})
                    else:
                        sw["conn"] = new_conn
                        sw["previous"] = get_port_statuses(new_conn, dt)
                        _broadcast_event("connection_restored", {
                            "host": host, "hostname": sw["hostname"],
                            "timestamp": datetime.now().isoformat(),
                        })
                    continue

                # Status diff
                changes = compute_diff(sw["previous"], current)
                needs_immediate_deep = False

                if changes:
                    for ch in changes:
                        ch["host"] = host
                        ch["hostname"] = sw["hostname"]
                        change_id = db_add_change(
                            session_id, host, sw["hostname"],
                            ch["port"], ch.get("description", ""), ch.get("port_type", ""),
                            ch["from_status"], ch["to_status"],
                        )
                        ch["id"] = change_id

                        # live_ports status güncelle
                        db_update_live_port_status(
                            session_id, host, ch["port"],
                            ch["to_status"], ch.get("description", ""), ch.get("port_type", ""),
                        )

                        # connected'a geçen port → derin poll tetikle
                        if ch["to_status"].lower() == "connected":
                            needs_immediate_deep = True

                    all_changes.extend(changes)

                # Summary
                for p in current.values():
                    global_summary["total"] += 1
                    sl = p["status"].lower()
                    if sl == "connected":
                        global_summary["connected"] += 1
                    elif sl in ("notconnect", "noconnpresent", "notpresent"):
                        global_summary["notconnect"] += 1
                    elif sl == "disabled":
                        global_summary["disabled"] += 1

                db_update_monitor_state(session_id, host, sw["hostname"], json.dumps(current, ensure_ascii=False))
                sw["previous"] = current

                # --- Derin poll (periyodik veya tetiklenmiş) ---
                should_deep = (
                    deep_poll_triggered or
                    needs_immediate_deep or
                    (now_ts - sw["last_deep_poll"]) >= DEEP_POLL_INTERVAL
                )

                if should_deep:
                    try:
                        _run_deep_poll(session_id, sw, arp_table)
                        sw["last_deep_poll"] = now_ts
                    except Exception as e:
                        _broadcast_event("switch_error", {
                            "host": host,
                            "error": f"Derin poll hatası: {str(e)}",
                        })

            # Broadcast changes
            if all_changes:
                _broadcast_event("change", {
                    "timestamp": datetime.now().isoformat(),
                    "changes": all_changes,
                    "poll_number": poll_count,
                })

                down_ports = [c for c in all_changes if "notconnect" in c.get("to_status", "").lower()]
                up_ports = [c for c in all_changes if c.get("to_status", "").lower() == "connected"]
                if down_ports:
                    lines = [f"🔴 {c.get('hostname', c['host'])} — {c['port']} DOWN ({c.get('description', '')})" for c in down_ports]
                    send_notification("Port Down Tespit Edildi", "\n".join(lines), "danger")
                if up_ports:
                    lines = [f"🟢 {c.get('hostname', c['host'])} — {c['port']} UP ({c.get('description', '')})" for c in up_ports]
                    send_notification("Port Up Tespit Edildi", "\n".join(lines), "good")

            # Heartbeat
            alive_count = sum(1 for s in switches if s["alive"])
            _broadcast_event("poll", {
                "timestamp": datetime.now().isoformat(),
                "poll_number": poll_count,
                "summary": global_summary,
                "alive_switches": alive_count,
                "total_switches": len(switches),
            })

            if alive_count == 0:
                _broadcast_event("error", {"error": "Tüm switch bağlantıları kesildi."})
                break

    finally:
        for sw in switches:
            try:
                sw["conn"].disconnect()
            except Exception:
                pass
        if _active_session_id == session_id:
            db_end_session(session_id)


def _run_deep_poll(session_id, sw, arp_table):
    """Tek bir switch için derin poll çalıştırır: LLDP, MAC, VLAN, errors."""
    host = sw["host"]
    hostname = sw["hostname"]
    now = datetime.now().isoformat()

    dt = sw.get("device_type", "arista_eos")
    deep = collect_deep_data(sw["conn"], dt)

    # Mevcut port status'larını al
    current = sw["previous"]  # son hızlı poll'dan

    enriched_ports = {}
    port_rows = []

    for port_name, info in current.items():
        is_connected = info["status"].lower() == "connected"

        lldp = deep["lldp"].get(port_name, "") if is_connected else ""
        macs = deep["mac"].get(port_name, "") if is_connected else ""
        vlan = deep["vlan"].get(port_name, "")
        sfp = deep.get("sfp", {}).get(port_name, "")
        err_info = deep["errors"].get(port_name, {})
        err_count = err_info.get("total_errors", 0) if isinstance(err_info, dict) else 0

        # ARP → IP
        ip_address = ""
        dns_hostname = ""
        if macs and arp_table:
            from firewall_collector import normalize_mac
            mac_list = [m.strip() for m in macs.split(",")]
            ips = []
            for mac in mac_list:
                normalized = normalize_mac(mac)
                ip = arp_table.get(normalized, "")
                ips.append(ip)
            ip_address = ", ".join(ips)

            # DNS lookup
            if ip_address:
                from dns_resolver import _reverse_lookup
                dns_parts = []
                for ip in ips:
                    if ip:
                        dns_parts.append(_reverse_lookup(ip))
                    else:
                        dns_parts.append("")
                dns_hostname = ", ".join(dns_parts)

        # Port-Channel member bilgisi
        po_members_str = ""
        if port_name.startswith("Po") and port_name in deep.get("po_members", {}):
            po_members_str = ", ".join(deep["po_members"][port_name])

        port_data = {
            "port": port_name,
            "status": info["status"],
            "description": info.get("description", ""),
            "port_type": info.get("port_type", ""),
            "sfp_type": sfp,
            "vlan": vlan,
            "lldp_neighbor": lldp,
            "mac_addresses": macs,
            "ip_address": ip_address,
            "dns_hostname": dns_hostname,
            "error_counters": err_count,
            "po_members": po_members_str,
            "last_deep_poll": now,
        }

        port_rows.append(port_data)
        enriched_ports[port_name] = port_data

    # DB'ye toplu yaz
    db_upsert_live_ports_bulk(session_id, host, hostname, port_rows)

    # Broadcast
    _broadcast_event("live_update", {
        "host": host,
        "hostname": hostname,
        "timestamp": now,
        "ports": enriched_ports,
    })
