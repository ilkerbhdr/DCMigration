"""SQLite veritabanı modülü — tüm kalıcı veri burada.

Thread-safe: check_same_thread=False + threading.Lock.
DB dosyası: data/port_map.db
"""
import json
import os
import sqlite3
import threading
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "port_map.db")

_lock = threading.RLock()


def get_connection():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Tabloları oluştur + eski JSON dosyalarını migrate et."""
    conn = get_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                port INTEGER DEFAULT 22,
                device_type TEXT DEFAULT 'arista_eos',
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS webhooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                url TEXT NOT NULL,
                type TEXT DEFAULT 'generic',
                enabled INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT (datetime('now')),
                event_type TEXT NOT NULL,
                detail_json TEXT DEFAULT '{}',
                user TEXT DEFAULT 'system'
            );

            CREATE TABLE IF NOT EXISTS baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                timestamp TEXT DEFAULT (datetime('now')),
                data_json TEXT NOT NULL,
                topology_json TEXT DEFAULT '[]',
                summary_json TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS monitor_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT DEFAULT (datetime('now')),
                ended_at TEXT,
                switch_list TEXT NOT NULL,
                interval_sec INTEGER DEFAULT 3,
                status TEXT DEFAULT 'active'
            );

            CREATE TABLE IF NOT EXISTS port_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                timestamp TEXT DEFAULT (datetime('now')),
                host TEXT NOT NULL,
                hostname TEXT,
                port TEXT NOT NULL,
                description TEXT DEFAULT '',
                port_type TEXT DEFAULT '',
                from_status TEXT NOT NULL,
                to_status TEXT NOT NULL,
                tag TEXT DEFAULT '',
                FOREIGN KEY (session_id) REFERENCES monitor_sessions(id)
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                label TEXT NOT NULL,
                timestamp TEXT DEFAULT (datetime('now')),
                data_json TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES monitor_sessions(id)
            );

            CREATE TABLE IF NOT EXISTS monitor_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                hostname TEXT,
                ports_json TEXT DEFAULT '{}',
                last_poll TEXT,
                alive INTEGER DEFAULT 1,
                FOREIGN KEY (session_id) REFERENCES monitor_sessions(id),
                UNIQUE(session_id, host)
            );

            CREATE TABLE IF NOT EXISTS live_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                hostname TEXT DEFAULT '',
                port TEXT NOT NULL,
                description TEXT DEFAULT '',
                status TEXT DEFAULT '',
                port_type TEXT DEFAULT '',
                vlan TEXT DEFAULT '',
                lldp_neighbor TEXT DEFAULT '',
                mac_addresses TEXT DEFAULT '',
                ip_address TEXT DEFAULT '',
                dns_hostname TEXT DEFAULT '',
                error_counters INTEGER DEFAULT 0,
                po_members TEXT DEFAULT '',
                tag TEXT DEFAULT '',
                last_status_change TEXT,
                last_deep_poll TEXT,
                FOREIGN KEY (session_id) REFERENCES monitor_sessions(id),
                UNIQUE(session_id, host, port)
            );

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value_json TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS switch_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                switches_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS sfp_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                timestamp TEXT DEFAULT (datetime('now')),
                data_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_changes_session ON port_changes(session_id);
            CREATE INDEX IF NOT EXISTS idx_changes_timestamp ON port_changes(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_live_session ON live_ports(session_id);
            CREATE INDEX IF NOT EXISTS idx_live_host ON live_ports(session_id, host);
        """)
        conn.commit()

        # Schema migration — mevcut tablolara yeni sütun ekle
        _migrate_schema(conn)

        conn.commit()
    finally:
        conn.close()

    _migrate_json_files()


def _migrate_schema(conn):
    """Mevcut tablolara eksik sütunları ekler (ALTER TABLE)."""
    migrations = [
        ("live_ports", "tag", "TEXT DEFAULT ''"),
        ("live_ports", "po_members", "TEXT DEFAULT ''"),
        ("live_ports", "sfp_type", "TEXT DEFAULT ''"),
        ("profiles", "device_type", "TEXT DEFAULT 'arista_eos'"),
    ]
    for table, col, col_type in migrations:
        try:
            conn.execute(f"SELECT {col} FROM {table} LIMIT 1")
        except Exception:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
            except Exception:
                pass


# ===================== MIGRATION =====================

def _migrate_json_files():
    """Eski JSON dosyalarını DB'ye aktar (sadece DB boşsa)."""
    _migrate_profiles()
    _migrate_webhooks()
    _migrate_audit_log()
    _migrate_baselines()


def _migrate_profiles():
    path = os.path.join(BASE_DIR, "profiles.json")
    if not os.path.exists(path):
        return
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM profiles").fetchone()[0]
        if count > 0:
            return
        with open(path, "r", encoding="utf-8") as f:
            profiles = json.load(f)
        for p in profiles:
            conn.execute(
                "INSERT OR IGNORE INTO profiles (name, username, password, port) VALUES (?, ?, ?, ?)",
                (p["name"], p["username"], p["password"], p.get("port", 22)),
            )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def _migrate_webhooks():
    path = os.path.join(BASE_DIR, "webhooks.json")
    if not os.path.exists(path):
        return
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM webhooks").fetchone()[0]
        if count > 0:
            return
        with open(path, "r", encoding="utf-8") as f:
            hooks = json.load(f)
        for h in hooks:
            conn.execute(
                "INSERT OR IGNORE INTO webhooks (name, url, type, enabled) VALUES (?, ?, ?, ?)",
                (h["name"], h["url"], h.get("type", "generic"), 1 if h.get("enabled", True) else 0),
            )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def _migrate_audit_log():
    path = os.path.join(BASE_DIR, "audit_log.json")
    if not os.path.exists(path):
        return
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        if count > 0:
            return
        with open(path, "r", encoding="utf-8") as f:
            entries = json.load(f)
        for e in entries:
            conn.execute(
                "INSERT INTO audit_log (timestamp, event_type, detail_json, user) VALUES (?, ?, ?, ?)",
                (e.get("timestamp", ""), e.get("type", ""), json.dumps(e.get("detail", {}), ensure_ascii=False), e.get("user", "system")),
            )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def _migrate_baselines():
    bl_dir = os.path.join(BASE_DIR, "baselines")
    if not os.path.isdir(bl_dir):
        return
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM baselines").fetchone()[0]
        if count > 0:
            return
        for fname in sorted(os.listdir(bl_dir)):
            if not fname.endswith(".json"):
                continue
            filepath = os.path.join(bl_dir, fname)
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            conn.execute(
                "INSERT INTO baselines (label, timestamp, data_json, topology_json, summary_json) VALUES (?, ?, ?, ?, ?)",
                (
                    data.get("label", fname),
                    data.get("timestamp", ""),
                    json.dumps(data.get("ports", []), ensure_ascii=False),
                    json.dumps(data.get("topology", []), ensure_ascii=False),
                    json.dumps(data.get("summary", {}), ensure_ascii=False),
                ),
            )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


# ===================== PROFILES =====================

def db_get_profiles():
    with _lock:
        conn = get_connection()
        try:
            rows = conn.execute("SELECT * FROM profiles ORDER BY name").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def db_save_profile(name, username, password, port=22, device_type="arista_eos"):
    with _lock:
        conn = get_connection()
        try:
            conn.execute(
                """INSERT INTO profiles (name, username, password, port, device_type)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET username=?, password=?, port=?, device_type=?""",
                (name, username, password, port, device_type, username, password, port, device_type),
            )
            conn.commit()
            return db_get_profiles()
        finally:
            conn.close()


def db_delete_profile(name):
    with _lock:
        conn = get_connection()
        try:
            conn.execute("DELETE FROM profiles WHERE name=?", (name,))
            conn.commit()
            return db_get_profiles()
        finally:
            conn.close()


# ===================== WEBHOOKS =====================

def db_get_webhooks():
    with _lock:
        conn = get_connection()
        try:
            rows = conn.execute("SELECT * FROM webhooks ORDER BY name").fetchall()
            return [{"name": r["name"], "url": r["url"], "type": r["type"], "enabled": bool(r["enabled"])} for r in rows]
        finally:
            conn.close()


def db_save_webhook(name, url, hook_type="generic", enabled=True):
    with _lock:
        conn = get_connection()
        try:
            conn.execute(
                """INSERT INTO webhooks (name, url, type, enabled)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET url=?, type=?, enabled=?""",
                (name, url, hook_type, 1 if enabled else 0, url, hook_type, 1 if enabled else 0),
            )
            conn.commit()
            return db_get_webhooks()
        finally:
            conn.close()


def db_delete_webhook(name):
    with _lock:
        conn = get_connection()
        try:
            conn.execute("DELETE FROM webhooks WHERE name=?", (name,))
            conn.commit()
            return db_get_webhooks()
        finally:
            conn.close()


def db_toggle_webhook(name, enabled):
    with _lock:
        conn = get_connection()
        try:
            conn.execute("UPDATE webhooks SET enabled=? WHERE name=?", (1 if enabled else 0, name))
            conn.commit()
            return db_get_webhooks()
        finally:
            conn.close()


# ===================== AUDIT LOG =====================

def db_log_event(event_type, detail, user="system"):
    with _lock:
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO audit_log (timestamp, event_type, detail_json, user) VALUES (?, ?, ?, ?)",
                (datetime.now().isoformat(), event_type, json.dumps(detail, ensure_ascii=False) if isinstance(detail, dict) else json.dumps({"message": str(detail)}), user),
            )
            conn.commit()
        finally:
            conn.close()


def db_get_audit_log(limit=200, event_type=None):
    with _lock:
        conn = get_connection()
        try:
            if event_type:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE event_type=? ORDER BY id DESC LIMIT ?",
                    (event_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            return [{"timestamp": r["timestamp"], "type": r["event_type"], "detail": json.loads(r["detail_json"]), "user": r["user"]} for r in rows]
        finally:
            conn.close()


def db_clear_audit_log():
    with _lock:
        conn = get_connection()
        try:
            conn.execute("DELETE FROM audit_log")
            conn.commit()
        finally:
            conn.close()


# ===================== BASELINES =====================

def db_save_baseline(label, ports, topology=None, summary=None):
    with _lock:
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO baselines (label, timestamp, data_json, topology_json, summary_json) VALUES (?, ?, ?, ?, ?)",
                (
                    label,
                    datetime.now().isoformat(),
                    json.dumps(ports, ensure_ascii=False),
                    json.dumps(topology or [], ensure_ascii=False),
                    json.dumps(summary or {}, ensure_ascii=False),
                ),
            )
            conn.commit()
        finally:
            conn.close()


def db_get_baselines():
    with _lock:
        conn = get_connection()
        try:
            rows = conn.execute("SELECT id, label, timestamp, summary_json FROM baselines ORDER BY id DESC").fetchall()
            return [{"id": r["id"], "label": r["label"], "timestamp": r["timestamp"], "summary": json.loads(r["summary_json"])} for r in rows]
        finally:
            conn.close()


def db_get_baseline(baseline_id):
    with _lock:
        conn = get_connection()
        try:
            r = conn.execute("SELECT * FROM baselines WHERE id=?", (baseline_id,)).fetchone()
            if not r:
                return None
            return {
                "id": r["id"], "label": r["label"], "timestamp": r["timestamp"],
                "ports": json.loads(r["data_json"]),
                "topology": json.loads(r["topology_json"]),
                "summary": json.loads(r["summary_json"]),
            }
        finally:
            conn.close()


def db_delete_baseline(baseline_id):
    with _lock:
        conn = get_connection()
        try:
            conn.execute("DELETE FROM baselines WHERE id=?", (baseline_id,))
            conn.commit()
        finally:
            conn.close()


# ===================== MONITOR SESSIONS =====================

def db_create_session(switch_list, interval):
    with _lock:
        conn = get_connection()
        try:
            # Önceki session'ın ID'sini al (etiketleri taşımak için)
            prev = conn.execute("SELECT id FROM monitor_sessions ORDER BY id DESC LIMIT 1").fetchone()
            prev_id = prev[0] if prev else None

            # Önceki aktif session'ı kapat
            conn.execute("UPDATE monitor_sessions SET status='ended', ended_at=datetime('now') WHERE status='active'")
            cur = conn.execute(
                "INSERT INTO monitor_sessions (switch_list, interval_sec) VALUES (?, ?)",
                (json.dumps(switch_list, ensure_ascii=False), interval),
            )
            new_id = cur.lastrowid

            # Önceki session'dan etiketleri yeni session'a taşı
            if prev_id:
                conn.execute("""
                    INSERT OR IGNORE INTO live_ports (session_id, host, hostname, port, tag)
                    SELECT ?, host, hostname, port, tag
                    FROM live_ports
                    WHERE session_id=? AND tag!='' AND tag IS NOT NULL
                """, (new_id, prev_id))

            conn.commit()
            return new_id
        finally:
            conn.close()


def db_end_session(session_id):
    with _lock:
        conn = get_connection()
        try:
            conn.execute("UPDATE monitor_sessions SET status='ended', ended_at=datetime('now') WHERE id=?", (session_id,))
            conn.commit()
        finally:
            conn.close()


def db_get_active_session():
    with _lock:
        conn = get_connection()
        try:
            r = conn.execute("SELECT * FROM monitor_sessions WHERE status='active' ORDER BY id DESC LIMIT 1").fetchone()
            return dict(r) if r else None
        finally:
            conn.close()


def db_get_last_session():
    """Son session'ı döndürür (aktif veya ended)."""
    with _lock:
        conn = get_connection()
        try:
            r = conn.execute("SELECT * FROM monitor_sessions ORDER BY id DESC LIMIT 1").fetchone()
            return dict(r) if r else None
        finally:
            conn.close()


# ===================== PORT CHANGES =====================

def db_add_change(session_id, host, hostname, port, description, port_type, from_status, to_status):
    with _lock:
        conn = get_connection()
        try:
            cur = conn.execute(
                """INSERT INTO port_changes (session_id, timestamp, host, hostname, port, description, port_type, from_status, to_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, datetime.now().isoformat(), host, hostname, port, description, port_type, from_status, to_status),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def db_tag_change(change_id, tag):
    with _lock:
        conn = get_connection()
        try:
            conn.execute("UPDATE port_changes SET tag=? WHERE id=?", (tag, change_id))
            conn.commit()
        finally:
            conn.close()


def db_bulk_tag(session_id, tag, scope="untagged"):
    """Toplu etiketleme. scope: untagged, last5, last10, alldown, all"""
    with _lock:
        conn = get_connection()
        try:
            if scope == "untagged":
                conn.execute("UPDATE port_changes SET tag=? WHERE session_id=? AND (tag IS NULL OR tag='')", (tag, session_id))
            elif scope == "last5":
                conn.execute("UPDATE port_changes SET tag=? WHERE id IN (SELECT id FROM port_changes WHERE session_id=? ORDER BY id DESC LIMIT 5)", (tag, session_id))
            elif scope == "last10":
                conn.execute("UPDATE port_changes SET tag=? WHERE id IN (SELECT id FROM port_changes WHERE session_id=? ORDER BY id DESC LIMIT 10)", (tag, session_id))
            elif scope == "alldown":
                conn.execute("UPDATE port_changes SET tag=? WHERE session_id=? AND LOWER(to_status) LIKE '%notconnect%'", (tag, session_id))
            else:
                conn.execute("UPDATE port_changes SET tag=? WHERE session_id=?", (tag, session_id))
            count = conn.execute("SELECT changes()").fetchone()[0]
            conn.commit()
            return count
        finally:
            conn.close()


def db_get_changes(session_id, since_id=0, limit=500):
    with _lock:
        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM port_changes WHERE session_id=? AND id>? ORDER BY id DESC LIMIT ?",
                (session_id, since_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ===================== MONITOR STATE =====================

def db_update_monitor_state(session_id, host, hostname, ports_json, alive=True):
    with _lock:
        conn = get_connection()
        try:
            conn.execute(
                """INSERT INTO monitor_state (session_id, host, hostname, ports_json, last_poll, alive)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(session_id, host) DO UPDATE SET hostname=?, ports_json=?, last_poll=?, alive=?""",
                (session_id, host, hostname, ports_json, datetime.now().isoformat(), 1 if alive else 0,
                 hostname, ports_json, datetime.now().isoformat(), 1 if alive else 0),
            )
            conn.commit()
        finally:
            conn.close()


def db_get_monitor_state(session_id):
    with _lock:
        conn = get_connection()
        try:
            rows = conn.execute("SELECT * FROM monitor_state WHERE session_id=?", (session_id,)).fetchall()
            return [{"host": r["host"], "hostname": r["hostname"], "ports": json.loads(r["ports_json"]), "alive": bool(r["alive"])} for r in rows]
        finally:
            conn.close()


# ===================== SNAPSHOTS =====================

def db_save_snapshot(session_id, label, data):
    with _lock:
        conn = get_connection()
        try:
            cur = conn.execute(
                "INSERT INTO snapshots (session_id, label, timestamp, data_json) VALUES (?, ?, ?, ?)",
                (session_id, label, datetime.now().isoformat(), json.dumps(data, ensure_ascii=False)),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def db_get_snapshots(session_id=None):
    with _lock:
        conn = get_connection()
        try:
            if session_id:
                rows = conn.execute("SELECT id, session_id, label, timestamp FROM snapshots WHERE session_id=? ORDER BY id DESC", (session_id,)).fetchall()
            else:
                rows = conn.execute("SELECT id, session_id, label, timestamp FROM snapshots ORDER BY id DESC LIMIT 50").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def db_get_snapshot(snapshot_id):
    with _lock:
        conn = get_connection()
        try:
            r = conn.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
            if not r:
                return None
            return {"id": r["id"], "label": r["label"], "timestamp": r["timestamp"], "data": json.loads(r["data_json"])}
        finally:
            conn.close()


# ===================== LIVE PORTS =====================

def db_upsert_live_ports_bulk(session_id, host, hostname, ports_list):
    """Bir switch'in tüm portlarını toplu günceller.

    Args:
        ports_list: [{"port": "Et1", "status": "connected", "description": ..., ...}]
    """
    with _lock:
        conn = get_connection()
        try:
            for p in ports_list:
                conn.execute(
                    """INSERT INTO live_ports
                       (session_id, host, hostname, port, description, status, port_type, sfp_type,
                        vlan, lldp_neighbor, mac_addresses, ip_address, dns_hostname,
                        error_counters, po_members, last_status_change, last_deep_poll)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(session_id, host, port) DO UPDATE SET
                        hostname=excluded.hostname,
                        description=CASE WHEN excluded.description!='' THEN excluded.description ELSE live_ports.description END,
                        status=CASE WHEN excluded.status!='' THEN excluded.status ELSE live_ports.status END,
                        port_type=CASE WHEN excluded.port_type!='' THEN excluded.port_type ELSE live_ports.port_type END,
                        sfp_type=CASE WHEN excluded.sfp_type!='' THEN excluded.sfp_type ELSE live_ports.sfp_type END,
                        vlan=CASE WHEN excluded.vlan!='' THEN excluded.vlan ELSE live_ports.vlan END,
                        lldp_neighbor=CASE WHEN excluded.lldp_neighbor!='' THEN excluded.lldp_neighbor ELSE live_ports.lldp_neighbor END,
                        mac_addresses=CASE WHEN excluded.mac_addresses!='' THEN excluded.mac_addresses ELSE live_ports.mac_addresses END,
                        ip_address=CASE WHEN excluded.ip_address!='' THEN excluded.ip_address ELSE live_ports.ip_address END,
                        dns_hostname=CASE WHEN excluded.dns_hostname!='' THEN excluded.dns_hostname ELSE live_ports.dns_hostname END,
                        error_counters=excluded.error_counters,
                        po_members=CASE WHEN excluded.po_members!='' THEN excluded.po_members ELSE live_ports.po_members END,
                        last_status_change=CASE WHEN excluded.status!=live_ports.status AND excluded.status!='' THEN excluded.last_status_change ELSE live_ports.last_status_change END,
                        last_deep_poll=CASE WHEN excluded.last_deep_poll!='' THEN excluded.last_deep_poll ELSE live_ports.last_deep_poll END
                    """,
                    (
                        session_id, host, hostname, p.get("port", ""),
                        p.get("description", ""), p.get("status", ""), p.get("port_type", ""), p.get("sfp_type", ""),
                        p.get("vlan", ""), p.get("lldp_neighbor", ""), p.get("mac_addresses", ""),
                        p.get("ip_address", ""), p.get("dns_hostname", ""),
                        p.get("error_counters", 0), p.get("po_members", ""),
                        p.get("last_status_change", ""), p.get("last_deep_poll", ""),
                    ),
                )
            conn.commit()
        finally:
            conn.close()


def db_update_live_port_status(session_id, host, port, status, description="", port_type=""):
    """Tek bir portun sadece status/desc/type alanlarını günceller (hızlı poll)."""
    with _lock:
        conn = get_connection()
        try:
            now = datetime.now().isoformat()
            conn.execute(
                """INSERT INTO live_ports (session_id, host, port, status, description, port_type, last_status_change)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(session_id, host, port) DO UPDATE SET
                    status=excluded.status,
                    description=CASE WHEN excluded.description!='' THEN excluded.description ELSE live_ports.description END,
                    port_type=CASE WHEN excluded.port_type!='' THEN excluded.port_type ELSE live_ports.port_type END,
                    last_status_change=CASE WHEN excluded.status!=live_ports.status THEN ? ELSE live_ports.last_status_change END
                """,
                (session_id, host, port, status, description, port_type, now, now),
            )
            conn.commit()
        finally:
            conn.close()


def db_get_live_ports(session_id, host=None):
    """Tüm canlı port verilerini döndürür."""
    with _lock:
        conn = get_connection()
        try:
            if host:
                rows = conn.execute(
                    "SELECT * FROM live_ports WHERE session_id=? AND host=? ORDER BY host, port",
                    (session_id, host),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM live_ports WHERE session_id=? ORDER BY host, port",
                    (session_id,),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def db_tag_live_port(session_id, host, port, tag):
    """Tek bir live port'a etiket atar. Kalıcı — poll'lar üzerine yazmaz."""
    with _lock:
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE live_ports SET tag=? WHERE session_id=? AND host=? AND port=?",
                (tag, session_id, host, port),
            )
            conn.commit()
        finally:
            conn.close()


def db_clear_live_ports(session_id):
    """Session'a ait tüm live port verilerini temizler."""
    with _lock:
        conn = get_connection()
        try:
            conn.execute("DELETE FROM live_ports WHERE session_id=?", (session_id,))
            conn.commit()
        finally:
            conn.close()


# ===================== APP SETTINGS =====================

def db_get_setting(key, default=None):
    """Uygulama ayarını döndürür."""
    with _lock:
        conn = get_connection()
        try:
            r = conn.execute("SELECT value_json FROM app_settings WHERE key=?", (key,)).fetchone()
            if r:
                return json.loads(r[0])
            return default
        finally:
            conn.close()


def db_set_setting(key, value):
    """Uygulama ayarını kaydeder."""
    with _lock:
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO app_settings (key, value_json) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value_json=?",
                (key, json.dumps(value, ensure_ascii=False), json.dumps(value, ensure_ascii=False)),
            )
            conn.commit()
        finally:
            conn.close()


# ===================== SWITCH GROUPS =====================

def db_get_switch_groups():
    with _lock:
        conn = get_connection()
        try:
            rows = conn.execute("SELECT * FROM switch_groups ORDER BY name").fetchall()
            return [{"id": r["id"], "name": r["name"], "switches": json.loads(r["switches_json"]), "created_at": r["created_at"]} for r in rows]
        finally:
            conn.close()


def db_save_switch_group(name, switches):
    """Switch grubu kaydet veya güncelle.

    Args:
        name: Grup adı (ör: "4.Kat Spine Switchleri")
        switches: [{"host": "192.168.1.10-15", "profile": "DC-Admin", "port": 22}]
    """
    with _lock:
        conn = get_connection()
        try:
            conn.execute(
                """INSERT INTO switch_groups (name, switches_json) VALUES (?, ?)
                   ON CONFLICT(name) DO UPDATE SET switches_json=?""",
                (name, json.dumps(switches, ensure_ascii=False), json.dumps(switches, ensure_ascii=False)),
            )
            conn.commit()
            return db_get_switch_groups()
        finally:
            conn.close()


def db_delete_switch_group(name):
    with _lock:
        conn = get_connection()
        try:
            conn.execute("DELETE FROM switch_groups WHERE name=?", (name,))
            conn.commit()
            return db_get_switch_groups()
        finally:
            conn.close()


# ===================== SFP SNAPSHOTS =====================

def db_save_sfp_snapshot(label, data):
    with _lock:
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO sfp_snapshots (label, timestamp, data_json) VALUES (?, ?, ?)",
                (label, datetime.now().isoformat(), json.dumps(data, ensure_ascii=False)),
            )
            conn.commit()
        finally:
            conn.close()


def db_get_sfp_snapshots():
    with _lock:
        conn = get_connection()
        try:
            rows = conn.execute("SELECT id, label, timestamp FROM sfp_snapshots ORDER BY id DESC").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def db_get_sfp_snapshot(snapshot_id):
    with _lock:
        conn = get_connection()
        try:
            r = conn.execute("SELECT * FROM sfp_snapshots WHERE id=?", (snapshot_id,)).fetchone()
            if not r:
                return None
            return {"id": r["id"], "label": r["label"], "timestamp": r["timestamp"], "data": json.loads(r["data_json"])}
        finally:
            conn.close()


def db_delete_sfp_snapshot(snapshot_id):
    with _lock:
        conn = get_connection()
        try:
            conn.execute("DELETE FROM sfp_snapshots WHERE id=?", (snapshot_id,))
            conn.commit()
        finally:
            conn.close()
