import csv
import io
import ipaddress
import json
import os
import time
from datetime import datetime

from flask import Flask, Blueprint, render_template, request, jsonify, send_file, Response
from netmiko import NetmikoTimeoutException, NetmikoAuthenticationException

from switch_collector import collect_port_info
from excel_exporter import export_to_excel
from firewall_collector import collect_arp_table, enrich_ports_with_arp
from dns_resolver import resolve_hostnames
from port_monitor import create_connection, get_hostname, get_port_statuses
from database import (
    init_db,
    db_get_profiles, db_save_profile, db_delete_profile,
    db_get_webhooks, db_save_webhook, db_delete_webhook, db_toggle_webhook,
    db_log_event, db_get_audit_log, db_clear_audit_log,
    db_save_baseline, db_get_baselines, db_get_baseline, db_delete_baseline,
    db_get_active_session, db_get_last_session, db_get_changes, db_tag_change, db_bulk_tag,
    db_save_snapshot, db_get_snapshots, db_get_snapshot, db_get_monitor_state,
    db_get_live_ports, db_tag_live_port,
    db_get_setting, db_set_setting,
    db_get_switch_groups, db_save_switch_group, db_delete_switch_group,
    db_save_sfp_snapshot, db_get_sfp_snapshots, db_get_sfp_snapshot, db_delete_sfp_snapshot,
)
from monitor_session import (
    start_session, stop_session, is_active, get_active_session_id,
    register_client, unregister_client, trigger_deep_poll_now,
    broadcast_event,
)
from webhook_notifier import test_webhook

app = Flask(__name__, static_url_path="/migration/static")
bp = Blueprint("migration", __name__, url_prefix="/migration")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
EXPORT_DIR = os.path.join(DATA_DIR, "exports")


@app.after_request
def add_response_headers(response):
    """Proxy uyumluluğu için response header'ları."""
    response.headers["X-Accel-Buffering"] = "no"
    return response


# --------------- IP Range helper ---------------

def expand_ip_range(ip_text):
    ip_text = ip_text.strip()
    if not ip_text:
        return []
    if "," in ip_text:
        all_ips = []
        for segment in ip_text.split(","):
            all_ips.extend(_expand_single_range(segment.strip()))
        return all_ips
    return _expand_single_range(ip_text)


def _expand_single_range(ip_text):
    ip_text = ip_text.strip()
    if not ip_text:
        return []
    if "-" not in ip_text:
        return [ip_text]

    parts = ip_text.split("-", 1)
    start_str = parts[0].strip()
    end_str = parts[1].strip()

    try:
        start_ip = ipaddress.IPv4Address(start_str)
    except ipaddress.AddressValueError:
        return [ip_text]

    if "." not in end_str:
        try:
            end_octet = int(end_str)
        except ValueError:
            return [ip_text]
        prefix = ".".join(start_str.split(".")[:-1])
        end_ip = ipaddress.IPv4Address(f"{prefix}.{end_octet}")
    else:
        try:
            end_ip = ipaddress.IPv4Address(end_str)
        except ipaddress.AddressValueError:
            return [ip_text]

    if end_ip < start_ip:
        return [ip_text]

    count = int(end_ip) - int(start_ip) + 1
    if count > 256:
        return [ip_text]

    return [str(ipaddress.IPv4Address(int(start_ip) + i)) for i in range(count)]


def _resolve_credentials(entry, profiles_dict):
    """Entry'den credential çözümler. Returns (username, password, port, device_type)."""
    profile_name = entry.get("profile", "").strip()
    ssh_port = int(entry.get("port") or 0)
    device_type = entry.get("device_type", "")

    if profile_name and profile_name in profiles_dict:
        prof = profiles_dict[profile_name]
        username = prof["username"]
        password = prof["password"]
        if ssh_port == 0:
            ssh_port = prof.get("port", 22)
        if not device_type:
            device_type = prof.get("device_type", "arista_eos")
    else:
        username = entry.get("username", "").strip()
        password = entry.get("password", "")
        if ssh_port == 0:
            ssh_port = 22

    if not device_type:
        device_type = "arista_eos"

    return username, password, ssh_port, device_type


# --------------- SSE Helper ---------------

def _sse_event(event_type, data):
    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event_type}\ndata: {payload}\n\n"


# --------------- Routes ---------------

@bp.route("/")
def index():
    return render_template("dashboard.html")


@bp.route("/port-mapping")
def collect_page():
    return render_template("index.html")


@bp.route("/monitor")
def monitor_page():
    return render_template("monitor.html")


@bp.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")


@bp.route("/live")
def live_page():
    return render_template("live.html")


@bp.route("/topology")
def topology_page():
    return render_template("topology.html")


@bp.route("/sfp")
def sfp_page():
    return render_template("sfp.html")


@bp.route("/api/topology/data", methods=["GET"])
def topology_data():
    """Topoloji verisi döndürür — baseline veya live session'dan."""
    source = request.args.get("source", "last")

    if source == "baseline":
        bid = int(request.args.get("id", 0))
        bl = db_get_baseline(bid)
        if not bl:
            return jsonify({"error": "Baseline bulunamadı."}), 404
        return jsonify({"ports": bl.get("ports", []), "topology": bl.get("topology", [])})

    elif source == "live":
        session_id = request.args.get("session_id") or get_active_session_id()
        if not session_id:
            last = db_get_last_session()
            session_id = last["id"] if last else None
        if not session_id:
            return jsonify({"ports": [], "topology": []})

        ports = db_get_live_ports(int(session_id))
        topology = []
        for p in ports:
            lldp = p.get("lldp_neighbor", "")
            if not lldp:
                continue
            import re
            m = re.match(r"^(.+?)\s*\((.+)\)$", lldp)
            if m:
                topology.append({
                    "switch": p.get("hostname", p.get("host", "")),
                    "host": p.get("host", ""),
                    "local_port": p.get("port", ""),
                    "neighbor_device": m.group(1).strip(),
                    "neighbor_port": m.group(2).strip(),
                })
        return jsonify({"ports": [dict(p) for p in ports], "topology": topology})

    return jsonify({"error": "source=baseline veya source=live kullanın. 'last' için localStorage."}), 400


# --------------- Profil CRUD (DB) ---------------

@bp.route("/api/profiles", methods=["GET"])
def get_profiles():
    return jsonify(db_get_profiles())


@bp.route("/api/profiles", methods=["POST"])
def create_profile():
    data = request.get_json()
    name = data.get("name", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    port = int(data.get("port", 22))
    device_type = data.get("device_type", "arista_eos")

    if not name or not username or not password:
        return jsonify({"error": "Profil adı, kullanıcı adı ve şifre zorunludur."}), 400

    profiles = db_save_profile(name, username, password, port, device_type)
    return jsonify({"message": "Profil kaydedildi.", "profiles": profiles})


@bp.route("/api/profiles/<name>", methods=["DELETE"])
def delete_profile(name):
    profiles = db_delete_profile(name)
    return jsonify({"message": "Profil silindi.", "profiles": profiles})


# --------------- Veri Toplama (SSE) ---------------

@bp.route("/collect", methods=["POST"])
def collect():
    data = request.get_json()
    entries = data.get("switches", [])

    if not entries:
        return jsonify({"error": "En az bir switch bilgisi giriniz."}), 400

    fw_data = data.get("firewall", {})

    def generate():
        profiles = {p["name"]: p for p in db_get_profiles()}

        all_ports = []
        all_topology = []
        errors = []

        ip_jobs = []
        for entry in entries:
            ip_text = entry.get("host", "").strip()
            if not ip_text:
                continue
            username, password, port, device_type = _resolve_credentials(entry, profiles)
            ip_list = expand_ip_range(ip_text)
            for host in ip_list:
                ip_jobs.append({"host": host, "username": username, "password": password, "port": port, "device_type": device_type})

        total_switches = len(ip_jobs)
        has_firewall = bool(fw_data and fw_data.get("host", "").strip())
        total_steps = total_switches + (2 if has_firewall else 0) + 1

        for idx, job in enumerate(ip_jobs):
            host = job["host"]
            step = idx + 1

            yield _sse_event("progress", {
                "step": step, "totalSteps": total_steps, "phase": "switch",
                "message": f"Switch bağlantısı: {host}", "detail": f"{step}/{total_switches} switch",
            })

            if not job["username"] or not job["password"]:
                err = {"host": host, "error": "Kullanıcı adı ve şifre zorunludur."}
                errors.append(err)
                yield _sse_event("switch_error", err)
                continue
            try:
                result = collect_port_info(host, job["username"], job["password"], job["port"], job.get("device_type", "arista_eos"))
                all_ports.extend(result["ports"])
                for t in result.get("topology", []):
                    t["switch"] = result["hostname"]
                    t["host"] = host
                all_topology.extend(result.get("topology", []))
                yield _sse_event("switch_ok", {"host": host, "port_count": len(result["ports"])})
            except NetmikoTimeoutException:
                err = {"host": host, "error": f"SSH zaman aşımı — {host}:{job['port']}"}
                errors.append(err)
                yield _sse_event("switch_error", err)
            except NetmikoAuthenticationException:
                err = {"host": host, "error": f"Kimlik doğrulama hatası — {host}"}
                errors.append(err)
                yield _sse_event("switch_error", err)
            except Exception as e:
                err = {"host": host, "error": f"Hata — {host}: {str(e)}"}
                errors.append(err)
                yield _sse_event("switch_error", err)

        if not all_ports:
            yield _sse_event("error", {"error": "Hiçbir switch'ten veri alınamadı.", "details": errors})
            return

        if has_firewall:
            fw_host = fw_data.get("host", "").strip()
            fw_username = fw_data.get("username", "").strip()
            fw_password = fw_data.get("password", "")
            fw_port = int(fw_data.get("port") or 22)
            fw_device_type = fw_data.get("device_type", "paloalto_panos")

            yield _sse_event("progress", {
                "step": total_switches + 1, "totalSteps": total_steps, "phase": "firewall",
                "message": f"Firewall ARP: {fw_host}", "detail": "MAC → IP eşleştirmesi",
            })

            try:
                arp_table = collect_arp_table(fw_host, fw_username, fw_password, fw_port, fw_device_type)
                enrich_ports_with_arp(all_ports, arp_table)
                yield _sse_event("switch_ok", {"host": fw_host, "port_count": len(arp_table)})
            except Exception as e:
                err = {"host": fw_host, "error": f"Firewall hatası: {str(e)}"}
                errors.append(err)
                yield _sse_event("switch_error", err)

            unique_ips = set()
            for p in all_ports:
                for ip in p.get("ip_address", "").split(","):
                    ip = ip.strip()
                    if ip:
                        unique_ips.add(ip)

            yield _sse_event("progress", {
                "step": total_switches + 2, "totalSteps": total_steps, "phase": "dns",
                "message": f"DNS lookup ({len(unique_ips)} IP)", "detail": "Paralel çözümleme",
            })

            try:
                resolve_hostnames(all_ports)
            except Exception as e:
                errors.append({"host": "DNS", "error": str(e)})

        yield _sse_event("progress", {
            "step": total_steps, "totalSteps": total_steps, "phase": "excel",
            "message": "Excel oluşturuluyor", "detail": f"{len(all_ports)} port",
        })

        filepath = export_to_excel(all_ports, EXPORT_DIR)
        filename = os.path.basename(filepath)

        db_log_event("collect", {
            "switches": len(ip_jobs), "ports": len(all_ports),
            "errors": len(errors), "filename": filename,
        })

        yield _sse_event("done", {
            "filename": filename, "total_ports": len(all_ports),
            "ports": all_ports, "topology": all_topology, "errors": errors,
        })

    return Response(generate(), mimetype="text/event-stream")


@bp.route("/download/<filename>")
def download(filename):
    safe = os.path.basename(filename)
    filepath = os.path.join(EXPORT_DIR, safe)
    if not os.path.exists(filepath):
        return jsonify({"error": "Dosya bulunamadı."}), 404
    return send_file(filepath, as_attachment=True, download_name=safe,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


# --------------- Monitor (DB-backed, tek oturum) ---------------

@bp.route("/api/monitor/start", methods=["POST"])
def monitor_start():
    """Arka plan thread ile monitor başlatır. Tüm istemciler /stream'den dinler."""
    data = request.get_json()
    switch_entries = data.get("switches", [])
    interval = max(1, min(30, int(data.get("interval", 3))))

    if not switch_entries:
        return jsonify({"error": "En az bir switch bilgisi giriniz."}), 400

    if is_active():
        return jsonify({"error": "already_active", "session_id": get_active_session_id(),
                         "message": "Zaten aktif bir izleme oturumu var. Önce durdurun veya stream'e bağlanın."})

    profiles = {p["name"]: p for p in db_get_profiles()}
    jobs = []
    for entry in switch_entries:
        host = entry.get("host", "").strip()
        if not host:
            continue
        username, password, ssh_port, device_type = _resolve_credentials(entry, profiles)
        if not username or not password:
            continue
        ip_list = expand_ip_range(host)
        for ip in ip_list:
            jobs.append({"host": ip, "username": username, "password": password, "port": ssh_port, "device_type": device_type})

    if not jobs:
        return jsonify({"error": "Geçerli switch bilgisi bulunamadı."}), 400

    # Firewall bilgisi (opsiyonel — ARP için)
    fw_data = data.get("firewall")
    firewall = None
    if fw_data and fw_data.get("host", "").strip():
        fw_profile = fw_data.get("profile", "").strip()
        if fw_profile and fw_profile in profiles:
            fp = profiles[fw_profile]
            fw_username = fp["username"]
            fw_password = fw_data.get("password", "").strip() or fp["password"]
            fw_port = int(fw_data.get("port") or fp.get("port", 22))
        else:
            fw_username = fw_data.get("username", "").strip()
            fw_password = fw_data.get("password", "")
            fw_port = int(fw_data.get("port", 22))
        if fw_username and fw_password:
            firewall = {"host": fw_data["host"].strip(), "username": fw_username,
                        "password": fw_password, "port": fw_port}

    session_id = start_session(jobs, interval, firewall=firewall)
    if session_id is None:
        return jsonify({"error": "already_active", "message": "Aktif oturum mevcut."})

    return jsonify({"session_id": session_id, "message": "İzleme başlatıldı."})


@bp.route("/api/monitor/stop", methods=["POST"])
def monitor_stop():
    stop_session()
    return jsonify({"message": "İzleme durduruldu."})


@bp.route("/api/monitor/status", methods=["GET"])
def monitor_status():
    """Aktif oturum durumunu döndürür. Aktif yoksa son session bilgisini de verir."""
    session_id = get_active_session_id()
    if session_id and is_active():
        return jsonify({"active": True, "session_id": session_id})
    # Aktif session yok — son session'ı döndür (veriler hâlâ DB'de)
    last = db_get_last_session()
    if last:
        return jsonify({"active": False, "session_id": None, "last_session_id": last["id"]})
    return jsonify({"active": False, "session_id": None, "last_session_id": None})


@bp.route("/api/monitor/stream")
def monitor_stream():
    """SSE stream — tüm istemciler buradan dinler."""
    if not is_active():
        return jsonify({"error": "Aktif izleme oturumu yok."}), 400

    q = register_client()

    def generate():
        try:
            # İlk bağlantıda mevcut state'i gönder
            session_id = get_active_session_id()
            if session_id:
                states = db_get_monitor_state(session_id)
                for s in states:
                    yield _sse_event("snapshot", {
                        "host": s["host"], "hostname": s["hostname"],
                        "timestamp": datetime.now().isoformat(), "ports": s["ports"],
                    })

                # Mevcut change log
                changes = db_get_changes(session_id, limit=500)
                if changes:
                    yield _sse_event("history", {"changes": changes})

            while True:
                try:
                    msg = q.get(timeout=30)
                    yield msg
                except Exception:
                    # Timeout — heartbeat gönder
                    yield _sse_event("heartbeat", {"timestamp": datetime.now().isoformat()})
        except GeneratorExit:
            pass
        finally:
            unregister_client(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})


@bp.route("/api/monitor/changes", methods=["GET"])
def monitor_changes():
    """Aktif veya belirtilen session'ın change log'unu döndürür."""
    session_id = request.args.get("session_id") or get_active_session_id()
    if not session_id:
        return jsonify([])
    since_id = int(request.args.get("since_id", 0))
    changes = db_get_changes(int(session_id), since_id)
    return jsonify(changes)


@bp.route("/api/monitor/tag", methods=["POST"])
def monitor_tag():
    """Tek bir change'e tag atar."""
    data = request.get_json()
    change_id = data.get("change_id")
    tag = data.get("tag", "")
    if not change_id:
        return jsonify({"error": "change_id zorunludur."}), 400
    db_tag_change(int(change_id), tag)
    return jsonify({"message": "Tag kaydedildi."})


@bp.route("/api/monitor/bulk-tag", methods=["POST"])
def monitor_bulk_tag():
    """Toplu etiketleme."""
    data = request.get_json()
    tag = data.get("tag", "")
    scope = data.get("scope", "untagged")
    session_id = data.get("session_id") or get_active_session_id()
    if not session_id or not tag:
        return jsonify({"error": "session_id ve tag zorunludur."}), 400
    count = db_bulk_tag(int(session_id), tag, scope)
    return jsonify({"message": f"{count} değişikliğe etiket uygulandı.", "count": count})


@bp.route("/api/monitor/snapshot", methods=["POST"])
def monitor_snapshot():
    """Anlık durumu snapshot olarak kaydeder."""
    data = request.get_json()
    label = data.get("label", f"Snapshot {datetime.now().strftime('%H:%M:%S')}")
    session_id = data.get("session_id") or get_active_session_id()
    if not session_id:
        return jsonify({"error": "Aktif oturum yok."}), 400

    states = db_get_monitor_state(int(session_id))
    snapshot_data = {s["host"]: {"hostname": s["hostname"], "ports": s["ports"]} for s in states}
    snap_id = db_save_snapshot(int(session_id), label, snapshot_data)
    return jsonify({"id": snap_id, "label": label, "message": "Snapshot kaydedildi."})


@bp.route("/api/monitor/snapshots", methods=["GET"])
def monitor_snapshots():
    session_id = request.args.get("session_id") or get_active_session_id()
    return jsonify(db_get_snapshots(int(session_id) if session_id else None))


@bp.route("/api/monitor/snapshot/<int:snap_id>", methods=["GET"])
def monitor_snapshot_detail(snap_id):
    snap = db_get_snapshot(snap_id)
    if not snap:
        return jsonify({"error": "Snapshot bulunamadı."}), 404
    return jsonify(snap)


@bp.route("/api/monitor/state", methods=["GET"])
def monitor_state():
    """Güncel port durumlarını döndürür."""
    session_id = request.args.get("session_id") or get_active_session_id()
    if not session_id:
        return jsonify([])
    return jsonify(db_get_monitor_state(int(session_id)))


@bp.route("/api/monitor/export-log", methods=["POST"])
def export_change_log():
    """Değişiklik logunu CSV olarak döndürür."""
    data = request.get_json()
    session_id = data.get("session_id") or get_active_session_id()

    changes = db_get_changes(int(session_id), limit=10000) if session_id else data.get("changes", [])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Zaman", "Switch", "Port", "Description", "Tip", "Eski Durum", "Yeni Durum", "Etiket"])

    for c in changes:
        writer.writerow([
            c.get("timestamp", ""),
            c.get("hostname", c.get("host", "")),
            c.get("port", ""),
            c.get("description", ""),
            c.get("port_type", ""),
            c.get("from_status", ""),
            c.get("to_status", ""),
            c.get("tag", ""),
        ])

    csv_bytes = output.getvalue().encode("utf-8-sig")
    return Response(csv_bytes, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=port_changes.csv"})


# --------------- Live Table API ---------------

@bp.route("/api/live/ports", methods=["GET"])
def get_live_ports_route():
    """Tüm canlı port verilerini döndürür."""
    session_id = request.args.get("session_id") or get_active_session_id()
    if not session_id:
        return jsonify([])
    host = request.args.get("host")
    return jsonify(db_get_live_ports(int(session_id), host))


@bp.route("/api/live/deep-poll", methods=["POST"])
def trigger_deep_poll_route():
    """Manuel derin poll tetikler."""
    if not is_active():
        return jsonify({"error": "Aktif izleme oturumu yok."}), 400
    trigger_deep_poll_now()
    return jsonify({"message": "Derin poll tetiklendi."})


@bp.route("/api/live/tag", methods=["POST"])
def tag_live_port():
    """Live port'a etiket atar. Kalıcı — poll'lar üzerine yazmaz."""
    data = request.get_json()
    host = data.get("host", "").strip()
    port = data.get("port", "").strip()
    tag = data.get("tag", "")
    session_id = data.get("session_id") or get_active_session_id()

    if not host or not port or not session_id:
        return jsonify({"error": "host, port ve session_id zorunludur."}), 400

    db_tag_live_port(int(session_id), host, port, tag)

    # Tüm istemcilere broadcast et
    broadcast_event("tag_update", {"host": host, "port": port, "tag": tag})

    return jsonify({"message": "Etiket kaydedildi.", "host": host, "port": port, "tag": tag})


@bp.route("/api/live/export", methods=["POST"])
def export_live_excel():
    """Live table verilerini Excel olarak döndürür."""
    session_id = request.args.get("session_id") or get_active_session_id()
    if not session_id:
        return jsonify({"error": "Aktif oturum yok."}), 400

    ports = db_get_live_ports(int(session_id))
    if not ports:
        return jsonify({"error": "Veri yok."}), 400

    # live_ports formatını export_to_excel formatına çevir
    all_ports = []
    for p in ports:
        all_ports.append({
            "switch": p.get("hostname") or p.get("host", ""),
            "port": p.get("port", ""),
            "description": p.get("description", ""),
            "status": p.get("status", ""),
            "vlan": p.get("vlan", ""),
            "port_type": p.get("port_type", ""),
            "lldp_neighbor": p.get("lldp_neighbor", ""),
            "mac_addresses": p.get("mac_addresses", ""),
            "ip_address": p.get("ip_address", ""),
            "hostname": p.get("dns_hostname", ""),
            "error_counters": p.get("error_counters", 0),
            "po_members": p.get("po_members", ""),
            "tag": p.get("tag", ""),
        })

    filepath = export_to_excel(all_ports, EXPORT_DIR)
    filename = os.path.basename(filepath)
    return jsonify({"filename": filename})


# --------------- Baseline (DB) ---------------

@bp.route("/api/baseline/save", methods=["POST"])
def save_baseline():
    data = request.get_json()
    label = data.get("label", "").strip() or f"Baseline {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    ports = data.get("ports", [])
    topology = data.get("topology", [])

    if not ports:
        return jsonify({"error": "Kaydedilecek port verisi yok."}), 400

    summary = {
        "total": len(ports),
        "connected": sum(1 for p in ports if p.get("status", "").lower() == "connected"),
        "notconnect": sum(1 for p in ports if "notconnect" in p.get("status", "").lower()),
    }

    db_save_baseline(label, ports, topology, summary)
    db_log_event("baseline_save", {"label": label, "ports": len(ports)})

    return jsonify({"message": "Baseline kaydedildi.", "label": label})


@bp.route("/api/baseline/list", methods=["GET"])
def list_baselines():
    return jsonify(db_get_baselines())


@bp.route("/api/baseline/<int:baseline_id>", methods=["GET"])
def get_baseline_route(baseline_id):
    bl = db_get_baseline(baseline_id)
    if not bl:
        return jsonify({"error": "Baseline bulunamadı."}), 404
    return jsonify(bl)


@bp.route("/api/baseline/<int:baseline_id>", methods=["DELETE"])
def delete_baseline_route(baseline_id):
    db_delete_baseline(baseline_id)
    return jsonify({"message": "Baseline silindi."})


@bp.route("/api/baseline/diff", methods=["POST"])
def diff_baselines():
    data = request.get_json()
    id1 = int(data.get("id1", 0))
    id2 = int(data.get("id2", 0))

    bl1 = db_get_baseline(id1)
    bl2 = db_get_baseline(id2)

    if not bl1 or not bl2:
        return jsonify({"error": "Baseline bulunamadı."}), 404

    ports1 = {f"{p['switch']}::{p['port']}": p for p in bl1.get("ports", [])}
    ports2 = {f"{p['switch']}::{p['port']}": p for p in bl2.get("ports", [])}
    all_keys = set(list(ports1.keys()) + list(ports2.keys()))

    changes = []
    for key in sorted(all_keys):
        p1 = ports1.get(key)
        p2 = ports2.get(key)

        if not p1:
            changes.append({"switch": p2["switch"], "port": p2["port"], "type": "new",
                            "detail": f"Yeni (status: {p2.get('status', '?')})",
                            "before_status": "—", "after_status": p2.get("status", "?")})
        elif not p2:
            changes.append({"switch": p1["switch"], "port": p1["port"], "type": "removed",
                            "detail": "Kaldırıldı", "before_status": p1.get("status", "?"), "after_status": "—"})
        else:
            diffs = []
            if p1.get("status", "") != p2.get("status", ""):
                diffs.append(f"Status: {p1.get('status')} → {p2.get('status')}")
            if p1.get("vlan", "") != p2.get("vlan", ""):
                diffs.append(f"VLAN: {p1.get('vlan', '')} → {p2.get('vlan', '')}")
            if p1.get("lldp_neighbor", "") != p2.get("lldp_neighbor", ""):
                diffs.append(f"LLDP: {p1.get('lldp_neighbor', '') or '—'} → {p2.get('lldp_neighbor', '') or '—'}")
            if diffs:
                changes.append({"switch": p1["switch"], "port": p1["port"], "type": "changed",
                                "detail": " | ".join(diffs),
                                "before_status": p1.get("status", "?"), "after_status": p2.get("status", "?")})

    topo1 = {f"{t.get('switch', '')}::{t['local_port']}": t for t in bl1.get("topology", [])}
    topo2 = {f"{t.get('switch', '')}::{t['local_port']}": t for t in bl2.get("topology", [])}
    topo_changes = []
    for key in sorted(set(list(topo1.keys()) + list(topo2.keys()))):
        t1, t2 = topo1.get(key), topo2.get(key)
        if not t1 and t2:
            topo_changes.append({"switch": t2.get("switch", ""), "port": t2["local_port"], "type": "new",
                                 "detail": f"Yeni: {t2['neighbor_device']} ({t2['neighbor_port']})"})
        elif t1 and not t2:
            topo_changes.append({"switch": t1.get("switch", ""), "port": t1["local_port"], "type": "removed",
                                 "detail": f"Kayıp: {t1['neighbor_device']} ({t1['neighbor_port']})"})
        elif t1 and t2 and (t1["neighbor_device"] != t2["neighbor_device"] or t1["neighbor_port"] != t2["neighbor_port"]):
            topo_changes.append({"switch": t1.get("switch", ""), "port": t1["local_port"], "type": "changed",
                                 "detail": f"{t1['neighbor_device']}→{t2['neighbor_device']}"})

    db_log_event("baseline_diff", {"id1": id1, "id2": id2, "changes": len(changes)})

    return jsonify({
        "label1": bl1["label"], "label2": bl2["label"],
        "changes": changes, "topology_changes": topo_changes,
        "summary1": bl1.get("summary", {}), "summary2": bl2.get("summary", {}),
    })


# --------------- Settings (key-value) ---------------

@bp.route("/api/settings/<key>", methods=["GET"])
def get_setting(key):
    value = db_get_setting(key)
    return jsonify({"key": key, "value": value})


@bp.route("/api/settings/<key>", methods=["POST"])
def set_setting(key):
    data = request.get_json()
    db_set_setting(key, data.get("value"))
    return jsonify({"message": "Ayar kaydedildi."})


# --------------- Switch Groups ---------------

@bp.route("/api/switch-groups", methods=["GET"])
def get_switch_groups():
    return jsonify(db_get_switch_groups())


@bp.route("/api/switch-groups", methods=["POST"])
def create_switch_group():
    data = request.get_json()
    name = data.get("name", "").strip()
    switches = data.get("switches", [])

    if not name:
        return jsonify({"error": "Grup adı zorunludur."}), 400
    if not switches:
        return jsonify({"error": "En az bir switch giriniz."}), 400

    groups = db_save_switch_group(name, switches)
    db_log_event("switch_group_save", {"name": name, "count": len(switches)})
    return jsonify({"message": "Grup kaydedildi.", "groups": groups})


@bp.route("/api/switch-groups/<name>", methods=["DELETE"])
def delete_switch_group(name):
    groups = db_delete_switch_group(name)
    return jsonify({"message": "Grup silindi.", "groups": groups})


# --------------- Dashboard ---------------

@bp.route("/api/dashboard/summary", methods=["POST"])
def dashboard_summary():
    data = request.get_json()
    switch_entries = data.get("switches", [])
    profiles = {p["name"]: p for p in db_get_profiles()}

    results = []
    for entry in switch_entries:
        host = entry.get("host", "").strip()
        if not host:
            continue

        username, password, ssh_port, device_type = _resolve_credentials(entry, profiles)
        if not username or not password:
            continue

        ip_list = expand_ip_range(host)
        for ip in ip_list:
            try:
                conn = create_connection(ip, username, password, ssh_port, device_type)
                hostname = get_hostname(conn)
                statuses = get_port_statuses(conn, device_type)
                conn.disconnect()

                summary = {"total": 0, "connected": 0, "notconnect": 0, "disabled": 0}
                for p in statuses.values():
                    summary["total"] += 1
                    sl = p["status"].lower()
                    if sl == "connected":
                        summary["connected"] += 1
                    elif sl in ("notconnect", "noconnpresent", "notpresent"):
                        summary["notconnect"] += 1
                    elif sl == "disabled":
                        summary["disabled"] += 1

                results.append({"host": ip, "hostname": hostname, "status": "ok", "summary": summary})
            except Exception as e:
                results.append({"host": ip, "hostname": ip, "status": "error", "error": str(e), "summary": {}})

    return jsonify(results)


# --------------- Audit Log (DB) ---------------

@bp.route("/api/audit-log", methods=["GET"])
def get_audit_log():
    limit = int(request.args.get("limit", 200))
    event_type = request.args.get("type", None)
    return jsonify(db_get_audit_log(limit, event_type))


@bp.route("/api/audit-log/clear", methods=["POST"])
def clear_audit_log():
    db_clear_audit_log()
    return jsonify({"message": "Audit log temizlendi."})


# --------------- Webhook (DB) ---------------

@bp.route("/api/webhooks", methods=["GET"])
def list_webhooks():
    return jsonify(db_get_webhooks())


@bp.route("/api/webhooks", methods=["POST"])
def create_webhook():
    data = request.get_json()
    name = data.get("name", "").strip()
    url = data.get("url", "").strip()
    hook_type = data.get("type", "generic")
    enabled = data.get("enabled", True)

    if not name or not url:
        return jsonify({"error": "Ad ve URL zorunludur."}), 400

    hooks = db_save_webhook(name, url, hook_type, enabled)
    db_log_event("webhook_add", {"name": name, "type": hook_type})
    return jsonify({"message": "Webhook eklendi.", "webhooks": hooks})


@bp.route("/api/webhooks/<name>", methods=["DELETE"])
def delete_webhook(name):
    hooks = db_delete_webhook(name)
    return jsonify({"message": "Webhook silindi.", "webhooks": hooks})


@bp.route("/api/webhooks/<name>/test", methods=["POST"])
def test_webhook_route(name):
    success, detail = test_webhook(name)
    return jsonify({"success": success, "detail": detail})


# --------------- SFP Check ---------------

@bp.route("/api/sfp/collect", methods=["POST"])
def sfp_collect():
    """Switch'lerden SFP envanter bilgisi toplar."""
    data = request.get_json()
    switch_entries = data.get("switches", [])
    profiles = {p["name"]: p for p in db_get_profiles()}

    results = []
    errors = []

    for entry in switch_entries:
        host = entry.get("host", "").strip()
        if not host:
            continue
        username, password, ssh_port, device_type = _resolve_credentials(entry, profiles)
        if not username or not password:
            continue

        ip_list = expand_ip_range(host)
        for ip in ip_list:
            try:
                conn = create_connection(ip, username, password, ssh_port, device_type)
                hostname = get_hostname(conn)
                statuses = get_port_statuses(conn, device_type)
                conn.disconnect()

                for port_name, info in statuses.items():
                    sfp = info.get("sfp_type", "")
                    results.append({
                        "switch": hostname,
                        "host": ip,
                        "port": port_name,
                        "sfp_type": sfp,
                        "status": info["status"],
                        "port_type": info["port_type"],
                        "description": info.get("description", ""),
                    })
            except Exception as e:
                errors.append({"host": ip, "error": str(e)})

    return jsonify({"data": results, "errors": errors})


@bp.route("/api/sfp/snapshot", methods=["POST"])
def sfp_save_snapshot():
    """SFP envanter snapshot'ı kaydeder."""
    data = request.get_json()
    label = data.get("label", "").strip() or f"SFP Snapshot {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    sfp_data = data.get("data", [])

    if not sfp_data:
        return jsonify({"error": "Kaydedilecek SFP verisi yok."}), 400

    db_save_sfp_snapshot(label, sfp_data)
    db_log_event("sfp_snapshot", {"label": label, "count": len(sfp_data)})
    return jsonify({"message": "SFP snapshot kaydedildi.", "label": label})


@bp.route("/api/sfp/snapshots", methods=["GET"])
def sfp_list_snapshots():
    return jsonify(db_get_sfp_snapshots())


@bp.route("/api/sfp/snapshot/<int:snap_id>", methods=["GET"])
def sfp_get_snapshot(snap_id):
    snap = db_get_sfp_snapshot(snap_id)
    if not snap:
        return jsonify({"error": "Snapshot bulunamadı."}), 404
    return jsonify(snap)


@bp.route("/api/sfp/snapshot/<int:snap_id>", methods=["DELETE"])
def sfp_delete_snapshot(snap_id):
    db_delete_sfp_snapshot(snap_id)
    return jsonify({"message": "Snapshot silindi."})


@bp.route("/api/sfp/diff", methods=["POST"])
def sfp_diff():
    """İki SFP snapshot'ını karşılaştırır."""
    data = request.get_json()
    id1 = int(data.get("id1", 0))
    id2 = int(data.get("id2", 0))

    s1 = db_get_sfp_snapshot(id1)
    s2 = db_get_sfp_snapshot(id2)
    if not s1 or not s2:
        return jsonify({"error": "Snapshot bulunamadı."}), 404

    # Key: switch::port
    map1 = {f"{d['switch']}::{d['port']}": d for d in s1["data"]}
    map2 = {f"{d['switch']}::{d['port']}": d for d in s2["data"]}
    all_keys = sorted(set(list(map1.keys()) + list(map2.keys())))

    changes = []
    for key in all_keys:
        p1 = map1.get(key)
        p2 = map2.get(key)

        if p1 and not p2:
            changes.append({"switch": p1["switch"], "port": p1["port"], "type": "removed",
                            "before": p1.get("sfp_type", ""), "after": "—",
                            "description": p1.get("description", "")})
        elif not p1 and p2:
            changes.append({"switch": p2["switch"], "port": p2["port"], "type": "new",
                            "before": "—", "after": p2.get("sfp_type", ""),
                            "description": p2.get("description", "")})
        elif p1 and p2 and p1.get("sfp_type", "") != p2.get("sfp_type", ""):
            changes.append({"switch": p1["switch"], "port": p1["port"], "type": "changed",
                            "before": p1.get("sfp_type", ""), "after": p2.get("sfp_type", ""),
                            "description": p1.get("description", "")})

    return jsonify({
        "label1": s1["label"], "label2": s2["label"],
        "total1": len(s1["data"]), "total2": len(s2["data"]),
        "changes": changes,
    })


# --------------- Blueprint Register + Root Redirect ---------------

app.register_blueprint(bp)


@app.route("/")
def root_redirect():
    from flask import redirect
    return redirect("/migration/")


# --------------- Startup ---------------

if __name__ == "__main__":
    init_db()
    os.makedirs(EXPORT_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
