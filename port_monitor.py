import re
import time
from datetime import datetime

from netmiko import ConnectHandler, NetmikoTimeoutException

from switch_collector import find_column_positions, parse_status_line, determine_port_type


def create_connection(host, username, password, port=22, device_type="arista_eos"):
    """Persistent SSH bağlantısı oluşturur (keepalive aktif).

    Desteklenen device_type: arista_eos, cisco_nxos

    Returns:
        ConnectHandler instance (açık bağlantı)
    """
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 30,
        "keepalive": 10,
    }
    return ConnectHandler(**device)


def get_hostname(connection):
    """Switch hostname'ini döndürür."""
    output = connection.send_command("show hostname")
    for line in output.strip().splitlines():
        if ":" in line:
            return line.split(":", 1)[1].strip()
        if line.strip():
            return line.strip()
    return connection.host


def get_port_statuses(connection, device_type="arista_eos"):
    """'show interfaces status' / 'show interface status' çalıştırıp port durumlarını döndürür.

    Hafif ve hızlı — sadece 1 komut. Tipik <1sn.
    Arista ve Cisco Nexus destekler.

    Returns:
        dict: {port_name: {"status": str, "description": str, "port_type": str, "sfp_type": str}}
    """
    # Cisco Nexus: "show interface status" (tekil), Arista: "show interfaces status" (çoğul)
    cmd = "show interface status" if device_type == "cisco_nxos" else "show interfaces status"
    # Cisco Nexus interface regex
    intf_regex = r"(Eth|mgmt|Po)" if device_type == "cisco_nxos" else r"(Et|Ma|Po)"

    output = connection.send_command(cmd)
    result = {}

    lines = output.strip().splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if "Port" in line and "Status" in line:
            header_idx = i
            break

    if header_idx is None:
        return result

    header_line = lines[header_idx]
    col_positions = find_column_positions(header_line)

    name_start = col_positions.get("Name", -1)
    status_start = col_positions.get("Status", -1)

    for line in lines[header_idx + 1:]:
        if not line.strip() or line.startswith("-"):
            continue

        parsed = parse_status_line(line, col_positions, header_line, intf_regex=intf_regex)
        if not parsed:
            continue

        intf_name, status, media_type = parsed
        port_type = determine_port_type(intf_name, media_type)

        description = ""
        if name_start >= 0 and status_start > name_start:
            description = line[name_start:status_start].strip()

        result[intf_name] = {
            "status": status,
            "description": description,
            "port_type": port_type,
            "sfp_type": media_type.strip() if media_type else "",
        }

    return result


def compute_diff(previous, current):
    """İki port snapshot'ı karşılaştırır, değişenleri döndürür.

    Args:
        previous: {port_name: {status, description, port_type}}
        current:  aynı format

    Returns:
        list: [{port, description, port_type, from_status, to_status}]
    """
    changes = []

    for port_name, cur_info in current.items():
        prev_info = previous.get(port_name)
        if prev_info is None:
            # Yeni port eklendi (nadiren olur)
            continue

        if prev_info["status"] != cur_info["status"]:
            changes.append({
                "port": port_name,
                "description": cur_info["description"],
                "port_type": cur_info["port_type"],
                "from_status": prev_info["status"],
                "to_status": cur_info["status"],
            })

    return changes


def try_reconnect(host, username, password, port=22, device_type="arista_eos", max_retries=3):
    """SSH bağlantısı koptuğunda yeniden bağlanmayı dener.

    Returns:
        ConnectHandler veya None (tüm denemeler başarısız)
    """
    for attempt in range(max_retries):
        try:
            wait_time = 2 ** attempt  # 1, 2, 4 saniye
            time.sleep(wait_time)
            return create_connection(host, username, password, port, device_type)
        except Exception:
            continue
    return None
