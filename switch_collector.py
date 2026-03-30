import re
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException


def collect_port_info(host, username, password, port=22, device_type="arista_eos"):
    """Switch'e SSH ile bağlanıp port bilgilerini toplar.

    Args:
        host: Switch IP adresi
        username: SSH kullanıcı adı
        password: SSH şifre
        port: SSH port (varsayılan 22)
        device_type: "arista_eos" veya "cisco_nxos"
    """
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 30,
    }

    connection = ConnectHandler(**device)
    try:
        hostname = _get_hostname(connection)

        if device_type == "cisco_nxos":
            status_data = _parse_interfaces_status_nexus(connection)
            desc_data = {}  # Nexus: description is part of interface status Name column
            lldp_data = _parse_lldp_neighbors_nexus(connection)
            mac_data = _parse_mac_address_table_nexus(connection)
            vlan_data = _parse_vlan_for_ports_nexus(connection)
            error_data = _parse_error_counters_nexus(connection)
            topology_data = _parse_lldp_topology_nexus(connection)
            po_members = _parse_port_channel_members_nexus(connection)
        else:
            status_data = _parse_interfaces_status(connection)
            desc_data = _parse_interfaces_description(connection)
            lldp_data = _parse_lldp_neighbors(connection)
            mac_data = _parse_mac_address_table(connection)
            vlan_data = _parse_vlan_for_ports(connection)
            error_data = _parse_error_counters(connection)
            topology_data = _parse_lldp_topology(connection)
            po_members = _parse_port_channel_members(connection)

        ports = []
        for intf_name, info in status_data.items():
            description = desc_data.get(intf_name, "")
            is_connected = info["status"].lower() == "connected"
            lldp_neighbor = lldp_data.get(intf_name, "") if is_connected else ""
            mac_addresses = mac_data.get(intf_name, "") if is_connected else ""
            port_entry = {
                "switch": hostname,
                "port": intf_name,
                "description": description,
                "status": info["status"],
                "port_type": info["port_type"],
                "sfp_type": info.get("sfp_type", ""),
                "lldp_neighbor": lldp_neighbor,
                "mac_addresses": mac_addresses,
                "vlan": vlan_data.get(intf_name, ""),
                "error_counters": error_data.get(intf_name, {}).get("total_errors", 0),
                "error_detail": error_data.get(intf_name, {}).get("detail", ""),
            }
            # Port-Channel member bilgisi
            if intf_name.startswith("Po") and intf_name in po_members:
                members = po_members[intf_name]
                port_entry["po_members"] = ", ".join(members) if isinstance(members, list) else members
            ports.append(port_entry)

        return {"hostname": hostname, "ports": ports, "topology": topology_data, "error": None}
    finally:
        connection.disconnect()


def collect_deep_data(connection, device_type="arista_eos"):
    """Mevcut persistent bağlantı üzerinden derin veri toplar (LLDP, MAC, VLAN, errors).

    Monitor session'dan çağrılır. Bağlantıyı açıp kapatmaz.

    Args:
        connection: Aktif netmiko bağlantısı
        device_type: "arista_eos" veya "cisco_nxos"

    Returns:
        dict: {"lldp": {port: neighbor}, "mac": {port: macs}, "vlan": {port: vlan}, "errors": {port: {total_errors, detail}}}
    """
    if device_type == "cisco_nxos":
        status_data = _parse_interfaces_status_nexus(connection)
        sfp_map = {port: info.get("sfp_type", "") for port, info in status_data.items()}
        return {
            "lldp": _parse_lldp_neighbors_nexus(connection),
            "mac": _parse_mac_address_table_nexus(connection),
            "vlan": _parse_vlan_for_ports_nexus(connection),
            "errors": _parse_error_counters_nexus(connection),
            "po_members": _parse_port_channel_members_nexus(connection),
            "sfp": sfp_map,
        }

    status_data = _parse_interfaces_status(connection)
    sfp_map = {port: info.get("sfp_type", "") for port, info in status_data.items()}

    return {
        "lldp": _parse_lldp_neighbors(connection),
        "mac": _parse_mac_address_table(connection),
        "vlan": _parse_vlan_for_ports(connection),
        "errors": _parse_error_counters(connection),
        "po_members": _parse_port_channel_members(connection),
        "sfp": sfp_map,
    }


# ============================================================================
# Arista EOS Parsers
# ============================================================================


def _get_hostname(connection):
    """Switch hostname'ini döndürür."""
    output = connection.send_command("show hostname")
    # "Hostname: switch-name" veya sadece hostname
    for line in output.strip().splitlines():
        if ":" in line:
            return line.split(":", 1)[1].strip()
        if line.strip():
            return line.strip()
    return connection.host


def _parse_interfaces_status(connection):
    """'show interfaces status' çıktısını parse eder."""
    output = connection.send_command("show interfaces status")
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
    # Kolon pozisyonlarını bul
    col_positions = find_column_positions(header_line)

    for line in lines[header_idx + 1 :]:
        if not line.strip() or line.startswith("-"):
            continue

        parsed = parse_status_line(line, col_positions, header_line)
        if parsed:
            intf_name, status, media_type = parsed
            port_type = determine_port_type(intf_name, media_type)
            result[intf_name] = {
                "status": status,
                "port_type": port_type,
                "sfp_type": media_type.strip() if media_type else "",
            }

    return result


def find_column_positions(header_line):
    """Header satırındaki kolon başlangıç pozisyonlarını bulur."""
    columns = ["Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type"]
    positions = {}
    for col in columns:
        idx = header_line.find(col)
        if idx >= 0:
            positions[col] = idx
    return positions


def parse_status_line(line, col_positions, header_line, intf_regex=None):
    """show interfaces status satırını parse eder."""
    if not line.strip():
        return None

    # Port adını al (ilk boşluğa kadar)
    parts = line.split()
    if not parts:
        return None
    intf_name = parts[0]

    # Fiziksel portlar + Port-Channel
    pattern = intf_regex or r"(Et|Ma|Po)"
    if not re.match(pattern, intf_name):
        return None

    # Status kolonunu bul
    status = ""
    if "Status" in col_positions:
        status_start = col_positions["Status"]
        # Bir sonraki kolonun başlangıcını bul
        next_col_start = None
        for col in ["Vlan", "Duplex", "Speed", "Type"]:
            if col in col_positions and col_positions[col] > status_start:
                next_col_start = col_positions[col]
                break
        if next_col_start:
            status = line[status_start:next_col_start].strip()
        else:
            status = line[status_start:].strip()

    # Type kolonunu bul
    media_type = ""
    if "Type" in col_positions:
        type_start = col_positions["Type"]
        media_type = line[type_start:].strip()

    return intf_name, status, media_type


def determine_port_type(intf_name, media_type):
    """Port tipini belirler: Bakır, Fiber veya Bilinmiyor."""
    if intf_name.startswith("Ma") or intf_name.startswith("mgmt"):
        return "Bakır"
    if intf_name.startswith("Po"):
        return "Port-Channel"

    media_lower = media_type.lower() if media_type else ""

    copper_keywords = [
        "baset", "base-t", "rj45", "copper", "1000t", "100t", "10t",
        "10/100/1000", "cat5", "cat6", "twinax",
    ]
    fiber_keywords = [
        "sfp", "qsfp", "xfp", "base-sr", "base-lr", "base-er",
        "base-zr", "base-lx", "base-sx", "base-bx", "cwdm", "dwdm",
        "aoc", "fiber", "optic", "base-x",
    ]

    for keyword in copper_keywords:
        if keyword in media_lower:
            return "Bakır"

    for keyword in fiber_keywords:
        if keyword in media_lower:
            return "Fiber"

    if media_type and media_type.strip() not in ("", "N/A", "Unknown", "--"):
        # Bilinmeyen bir tip varsa olduğu gibi göster
        return media_type

    return "Bilinmiyor"


def _parse_interfaces_description(connection):
    """'show interfaces description' çıktısını parse eder ve description döndürür."""
    output = connection.send_command("show interfaces description")
    result = {}

    lines = output.strip().splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if "Interface" in line and "Description" in line:
            header_idx = i
            break

    if header_idx is None:
        return result

    header_line = lines[header_idx]
    desc_start = header_line.find("Description")
    if desc_start < 0:
        desc_start = header_line.find("description")

    for line in lines[header_idx + 1 :]:
        if not line.strip() or line.startswith("-"):
            continue

        parts = line.split()
        if not parts:
            continue

        intf_name = parts[0]
        if not re.match(r"(Et|Ma)", intf_name):
            continue

        description = ""
        if desc_start >= 0 and len(line) > desc_start:
            description = line[desc_start:].strip()

        result[intf_name] = description

    return result


def _parse_lldp_neighbors(connection):
    """'show lldp neighbors' çıktısını parse eder.

    Returns:
        dict: {interface_name: "neighbor_device (neighbor_port)"} şeklinde.
    """
    output = connection.send_command("show lldp neighbors")
    result = {}

    lines = output.strip().splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if "Port" in line and "Neighbor" in line:
            header_idx = i
            break

    if header_idx is None:
        return result

    header_line = lines[header_idx]

    # Kolon pozisyonlarını bul
    col_names = ["Port", "Neighbor Device ID", "Neighbor Port ID", "TTL"]
    positions = {}
    for col in col_names:
        idx = header_line.find(col)
        if idx >= 0:
            positions[col] = idx

    for line in lines[header_idx + 1 :]:
        if not line.strip() or line.startswith("-"):
            continue

        parts = line.split()
        if not parts:
            continue

        intf_name = parts[0]
        if not re.match(r"(Et|Ma)", intf_name):
            continue

        neighbor_device = ""
        neighbor_port = ""

        if "Neighbor Device ID" in positions:
            start = positions["Neighbor Device ID"]
            end = positions.get("Neighbor Port ID", len(line))
            neighbor_device = line[start:end].strip()

        if "Neighbor Port ID" in positions:
            start = positions["Neighbor Port ID"]
            end = positions.get("TTL", len(line))
            neighbor_port = line[start:end].strip()

        if neighbor_device:
            display = neighbor_device
            if neighbor_port:
                display += f" ({neighbor_port})"
            result[intf_name] = display

    return result


def _parse_mac_address_table(connection):
    """'show mac address-table' çıktısını parse eder.

    Returns:
        dict: {interface_name: "mac1, mac2, ..."} şeklinde.
    """
    output = connection.send_command("show mac address-table")
    result = {}

    lines = output.strip().splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if "Mac Address" in line and "Ports" in line:
            header_idx = i
            break

    if header_idx is None:
        return result

    header_line = lines[header_idx]

    # Kolon pozisyonlarını bul
    col_names = ["Vlan", "Mac Address", "Type", "Ports", "Moves"]
    positions = {}
    for col in col_names:
        idx = header_line.find(col)
        if idx >= 0:
            positions[col] = idx

    port_mac_map = {}  # {intf_name: [mac1, mac2, ...]}

    for line in lines[header_idx + 1 :]:
        if not line.strip() or line.startswith("-"):
            continue

        # Ports kolonunu bul (Moves kolonuna kadar)
        port_name = ""
        mac_addr = ""

        if "Ports" in positions:
            start = positions["Ports"]
            end = positions.get("Moves", len(line))
            port_name = line[start:end].strip()

        if "Mac Address" in positions:
            start = positions["Mac Address"]
            end = positions.get("Type", len(line))
            mac_addr = line[start:end].strip()

        if not port_name or not mac_addr:
            continue

        if not re.match(r"(Et|Ma|Po)", port_name):
            continue

        if port_name not in port_mac_map:
            port_mac_map[port_name] = []
        port_mac_map[port_name].append(mac_addr)

    # Listeyi virgülle birleştir
    for intf_name, macs in port_mac_map.items():
        result[intf_name] = ", ".join(macs)

    return result


def _parse_vlan_for_ports(connection):
    """'show interfaces status' çıktısından port VLAN bilgisini çıkarır.

    Returns:
        dict: {interface_name: vlan_str} — ör: {"Et1": "100", "Et2": "trunk"}
    """
    output = connection.send_command("show interfaces status")
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

    vlan_start = col_positions.get("Vlan", -1)
    if vlan_start < 0:
        return result

    # Vlan'dan sonraki kolon
    duplex_start = col_positions.get("Duplex", len(header_line))

    for line in lines[header_idx + 1:]:
        if not line.strip() or line.startswith("-"):
            continue
        parts = line.split()
        if not parts:
            continue
        intf_name = parts[0]
        if not re.match(r"(Et|Ma)", intf_name):
            continue

        vlan_str = ""
        if vlan_start >= 0 and len(line) > vlan_start:
            vlan_str = line[vlan_start:duplex_start].strip()

        result[intf_name] = vlan_str

    return result


def _parse_error_counters(connection):
    """'show interfaces counters errors' çıktısını parse eder.

    Returns:
        dict: {interface_name: {"in_errors": int, "out_errors": int, "total_errors": int}}
    """
    output = connection.send_command("show interfaces counters errors")
    result = {}

    lines = output.strip().splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if "Port" in line and ("InErrors" in line or "FCS" in line or "Align" in line):
            header_idx = i
            break

    if header_idx is None:
        return result

    header_line = lines[header_idx]

    for line in lines[header_idx + 1:]:
        if not line.strip() or line.startswith("-"):
            continue
        parts = line.split()
        if not parts:
            continue
        intf_name = parts[0]
        if not re.match(r"(Et|Ma)", intf_name):
            continue

        # Sayısal değerleri topla (port adından sonraki tüm sayılar)
        numbers = []
        for p in parts[1:]:
            try:
                numbers.append(int(p))
            except ValueError:
                continue

        total = sum(numbers)
        result[intf_name] = {
            "total_errors": total,
            "detail": " / ".join(str(n) for n in numbers) if numbers else "0",
        }

    return result


def _parse_lldp_topology(connection):
    """LLDP komşuluklarından uplink/topology verisini çıkarır.

    Returns:
        list: [{"local_port": str, "neighbor_device": str, "neighbor_port": str}]
    """
    output = connection.send_command("show lldp neighbors")
    result = []

    lines = output.strip().splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if "Port" in line and "Neighbor" in line:
            header_idx = i
            break

    if header_idx is None:
        return result

    header_line = lines[header_idx]
    col_names = ["Port", "Neighbor Device ID", "Neighbor Port ID", "TTL"]
    positions = {}
    for col in col_names:
        idx = header_line.find(col)
        if idx >= 0:
            positions[col] = idx

    for line in lines[header_idx + 1:]:
        if not line.strip() or line.startswith("-"):
            continue
        parts = line.split()
        if not parts:
            continue
        intf_name = parts[0]
        if not re.match(r"(Et|Ma)", intf_name):
            continue

        neighbor_device = ""
        neighbor_port = ""

        if "Neighbor Device ID" in positions:
            start = positions["Neighbor Device ID"]
            end = positions.get("Neighbor Port ID", len(line))
            neighbor_device = line[start:end].strip()

        if "Neighbor Port ID" in positions:
            start = positions["Neighbor Port ID"]
            end = positions.get("TTL", len(line))
            neighbor_port = line[start:end].strip()

        if neighbor_device:
            result.append({
                "local_port": intf_name,
                "neighbor_device": neighbor_device,
                "neighbor_port": neighbor_port,
            })

    return result


def _parse_port_channel_members(connection):
    """'show port-channel dense' çıktısını parse eder.

    Arista EOS formatı (dense):
       Port-Channel       Protocol    Ports
      ------------------ -------------- ------------------------------------------
       Po1(U)             LACP(a)     Et31/1(PG+) Et32/1(PG+)
       Po10(U)            LACP(a)     Et1/1(PG+) Et2/1(PG+) PEt1/1(P) PEt2/1(P)

       Po11(U)            LACP(a)     Et3/1(PG+) Et4/1(PG+) PEt3/1(P) PEt4/1(P)

    - PEt = Peer Ethernet (MLAG peer) → atlanır, sadece Et alınır
    - Port-Channel satırları birden fazla satıra yayılabilir (devam satırları)

    Returns:
        dict: {"Po1": ["Et31/1", "Et32/1"], "Po10": ["Et1/1", "Et2/1"]}
    """
    try:
        output = connection.send_command("show port-channel dense")
    except Exception:
        # Fallback: show port-channel summary
        try:
            output = connection.send_command("show port-channel summary")
        except Exception:
            return {}

    result = {}
    lines = output.strip().splitlines()
    current_po = None

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("-") or stripped.startswith("Port-Channel") or \
           stripped.startswith("Number") or stripped.startswith("Flags") or stripped.startswith("a ") or \
           stripped.startswith("F ") or stripped.startswith("U ") or stripped.startswith("+ ") or \
           stripped.startswith("P ") or stripped.startswith("I ") or stripped.startswith("C ") or \
           stripped.startswith("E ") or stripped.startswith("Group"):
            continue

        # Yeni Po satırı mı?
        po_match = re.match(r"\s*(Po\d+)\(", line)
        if po_match:
            current_po = po_match.group(1)
            if current_po not in result:
                result[current_po] = []

        # Bu satırdaki tüm Et portlarını topla (PEt hariç)
        if current_po:
            # Et31/1(PG+) formatını yakala, PEt'yi atlat
            members = re.findall(r"(?<![P])(Et\d+(?:/\d+)*)\(", line)
            # Eğer regex çalışmazsa fallback: token bazlı
            if not members:
                for token in stripped.split():
                    m = re.match(r"(Et\d+(?:/\d+)*)\(", token)
                    if m:
                        members.append(m.group(1))
            result[current_po].extend(members)

    # Boş olanları temizle, listeyi string'e çevir
    return {po: ", ".join(members) for po, members in result.items() if members}


# ============================================================================
# Cisco Nexus NX-OS Parsers
# ============================================================================


def _parse_interfaces_status_nexus(connection):
    """Nexus 'show interface status' çıktısını parse eder.

    Nexus output format:
        Port          Name               Status    Vlan      Duplex  Speed   Type
        Eth1/1        SERVER-01          connected 100       full    10G     10Gbase-SR
        Eth1/2        SERVER-02          notconnect 100      auto    auto    10Gbase-SR
        mgmt0         MGMT               connected routed    full    1000    --
        Po1           UPLINK-SPINE       connected trunk     full    40G     --

    Returns:
        dict: {port: {"status": str, "port_type": str, "sfp_type": str}}
    """
    try:
        output = connection.send_command("show interface status")
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

        for line in lines[header_idx + 1:]:
            if not line.strip() or line.startswith("-"):
                continue

            parts = line.split()
            if not parts:
                continue

            intf_name = parts[0]

            # Nexus interface regex: Eth, mgmt, Po
            if not re.match(r"(Eth|mgmt|Po)", intf_name):
                continue

            # Status kolonunu bul
            status = ""
            if "Status" in col_positions:
                status_start = col_positions["Status"]
                next_col_start = None
                for col in ["Vlan", "Duplex", "Speed", "Type"]:
                    if col in col_positions and col_positions[col] > status_start:
                        next_col_start = col_positions[col]
                        break
                if next_col_start:
                    status = line[status_start:next_col_start].strip()
                else:
                    status = line[status_start:].strip()

            # Type kolonunu bul
            media_type = ""
            if "Type" in col_positions:
                type_start = col_positions["Type"]
                media_type = line[type_start:].strip()

            port_type = determine_port_type(intf_name, media_type)
            result[intf_name] = {
                "status": status,
                "port_type": port_type,
                "sfp_type": media_type.strip() if media_type else "",
            }

        return result
    except Exception:
        return {}


def _parse_lldp_neighbors_nexus(connection):
    """Nexus 'show lldp neighbors' + 'show cdp neighbors' çıktısını parse eder.

    LLDP first, then CDP for ports not already covered by LLDP (deduplication).

    Returns:
        dict: {interface_name: "neighbor_device (neighbor_port)"}
    """
    result = {}

    # --- LLDP parsing ---
    try:
        lldp_output = connection.send_command("show lldp neighbors")
        lines = lldp_output.strip().splitlines()

        header_idx = None
        for i, line in enumerate(lines):
            if "Device ID" in line and "Local Intf" in line:
                header_idx = i
                break

        if header_idx is not None:
            header_line = lines[header_idx]
            col_names = ["Device ID", "Local Intf", "Hold-time", "Capability", "Port ID"]
            positions = {}
            for col in col_names:
                idx = header_line.find(col)
                if idx >= 0:
                    positions[col] = idx

            for line in lines[header_idx + 1:]:
                if not line.strip() or line.startswith("-"):
                    continue
                parts = line.split()
                if not parts:
                    continue

                # Extract fields by column position
                device_id = ""
                local_intf = ""
                port_id = ""

                if "Device ID" in positions:
                    start = positions["Device ID"]
                    end = positions.get("Local Intf", len(line))
                    device_id = line[start:end].strip()

                if "Local Intf" in positions:
                    start = positions["Local Intf"]
                    end = positions.get("Hold-time", len(line))
                    local_intf = line[start:end].strip()

                if "Port ID" in positions:
                    start = positions["Port ID"]
                    port_id = line[start:].strip()

                if device_id and local_intf and re.match(r"(Eth|mgmt|Po)", local_intf):
                    display = device_id
                    if port_id:
                        display += f" ({port_id})"
                    result[local_intf] = display
    except Exception:
        pass

    # --- CDP parsing (only ports not already in LLDP result) ---
    try:
        cdp_output = connection.send_command("show cdp neighbors")
        lines = cdp_output.strip().splitlines()

        header_idx = None
        for i, line in enumerate(lines):
            if "Device-ID" in line and "Local Intrfce" in line:
                header_idx = i
                break

        if header_idx is not None:
            header_line = lines[header_idx]
            col_names = ["Device-ID", "Local Intrfce", "Hldtme", "Capability", "Platform", "Port ID"]
            positions = {}
            for col in col_names:
                idx = header_line.find(col)
                if idx >= 0:
                    positions[col] = idx

            for line in lines[header_idx + 1:]:
                if not line.strip() or line.startswith("-"):
                    continue
                parts = line.split()
                if not parts:
                    continue

                device_id = ""
                local_intf = ""
                port_id = ""

                if "Device-ID" in positions:
                    start = positions["Device-ID"]
                    end = positions.get("Local Intrfce", len(line))
                    device_id = line[start:end].strip()

                if "Local Intrfce" in positions:
                    start = positions["Local Intrfce"]
                    end = positions.get("Hldtme", len(line))
                    local_intf = line[start:end].strip()

                if "Port ID" in positions:
                    start = positions["Port ID"]
                    port_id = line[start:].strip()

                if device_id and local_intf and re.match(r"(Eth|mgmt|Po)", local_intf):
                    # Deduplication: only add if not already from LLDP
                    if local_intf not in result:
                        display = device_id
                        if port_id:
                            display += f" ({port_id})"
                        result[local_intf] = display
    except Exception:
        pass

    return result


def _parse_lldp_topology_nexus(connection):
    """Nexus LLDP + CDP komşuluklarından topology verisini çıkarır.

    LLDP first, then CDP-only neighbors (deduplication by local_port).

    Returns:
        list: [{"local_port": str, "neighbor_device": str, "neighbor_port": str}]
    """
    result = []
    seen_local_ports = set()

    # --- LLDP parsing ---
    try:
        lldp_output = connection.send_command("show lldp neighbors")
        lines = lldp_output.strip().splitlines()

        header_idx = None
        for i, line in enumerate(lines):
            if "Device ID" in line and "Local Intf" in line:
                header_idx = i
                break

        if header_idx is not None:
            header_line = lines[header_idx]
            col_names = ["Device ID", "Local Intf", "Hold-time", "Capability", "Port ID"]
            positions = {}
            for col in col_names:
                idx = header_line.find(col)
                if idx >= 0:
                    positions[col] = idx

            for line in lines[header_idx + 1:]:
                if not line.strip() or line.startswith("-"):
                    continue
                parts = line.split()
                if not parts:
                    continue

                device_id = ""
                local_intf = ""
                port_id = ""

                if "Device ID" in positions:
                    start = positions["Device ID"]
                    end = positions.get("Local Intf", len(line))
                    device_id = line[start:end].strip()

                if "Local Intf" in positions:
                    start = positions["Local Intf"]
                    end = positions.get("Hold-time", len(line))
                    local_intf = line[start:end].strip()

                if "Port ID" in positions:
                    start = positions["Port ID"]
                    port_id = line[start:].strip()

                if device_id and local_intf and re.match(r"(Eth|mgmt|Po)", local_intf):
                    result.append({
                        "local_port": local_intf,
                        "neighbor_device": device_id,
                        "neighbor_port": port_id,
                    })
                    seen_local_ports.add(local_intf)
    except Exception:
        pass

    # --- CDP parsing (only ports not already from LLDP) ---
    try:
        cdp_output = connection.send_command("show cdp neighbors")
        lines = cdp_output.strip().splitlines()

        header_idx = None
        for i, line in enumerate(lines):
            if "Device-ID" in line and "Local Intrfce" in line:
                header_idx = i
                break

        if header_idx is not None:
            header_line = lines[header_idx]
            col_names = ["Device-ID", "Local Intrfce", "Hldtme", "Capability", "Platform", "Port ID"]
            positions = {}
            for col in col_names:
                idx = header_line.find(col)
                if idx >= 0:
                    positions[col] = idx

            for line in lines[header_idx + 1:]:
                if not line.strip() or line.startswith("-"):
                    continue
                parts = line.split()
                if not parts:
                    continue

                device_id = ""
                local_intf = ""
                port_id = ""

                if "Device-ID" in positions:
                    start = positions["Device-ID"]
                    end = positions.get("Local Intrfce", len(line))
                    device_id = line[start:end].strip()

                if "Local Intrfce" in positions:
                    start = positions["Local Intrfce"]
                    end = positions.get("Hldtme", len(line))
                    local_intf = line[start:end].strip()

                if "Port ID" in positions:
                    start = positions["Port ID"]
                    port_id = line[start:].strip()

                if device_id and local_intf and re.match(r"(Eth|mgmt|Po)", local_intf):
                    if local_intf not in seen_local_ports:
                        result.append({
                            "local_port": local_intf,
                            "neighbor_device": device_id,
                            "neighbor_port": port_id,
                        })
                        seen_local_ports.add(local_intf)
    except Exception:
        pass

    return result


def _parse_mac_address_table_nexus(connection):
    """Nexus 'show mac address-table' çıktısını parse eder.

    Nexus output format:
       VLAN     MAC Address      Type      age     Secure NTFY Ports
    ---------+-----------------+--------+---------+------+----+------------------
    *    100     aabb.ccdd.eeff   dynamic  0         F    F    Eth1/1
    *    200     1122.3344.5566   dynamic  0         F    F    Eth1/2
    G    -       7cad.74c8.d747   static   -         F    F    sup-eth1(R)

    Returns:
        dict: {port: "mac1, mac2, ..."}
    """
    try:
        output = connection.send_command("show mac address-table")
        result = {}
        port_mac_map = {}  # {intf_name: [mac1, mac2, ...]}

        lines = output.strip().splitlines()

        for line in lines:
            stripped = line.strip()
            # Skip empty lines, separator lines, header lines, legend lines
            if not stripped:
                continue
            if stripped.startswith("-") or "+" in stripped[:20]:
                continue
            if "VLAN" in stripped and "MAC Address" in stripped:
                continue
            if stripped.startswith("Legend") or stripped.startswith("Note"):
                continue

            # Skip legend entries (single letter + space + description patterns)
            # e.g., "* - primary entry" or "G - Gateway MAC"
            if re.match(r"^[A-Z*+\-]\s+[-–—]", stripped):
                continue

            # Parse data lines: first char may be *, G, +, etc. or space
            # Format: [flag] VLAN MAC Type age Secure NTFY Ports
            # Use regex to extract MAC and port
            mac_match = re.search(r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})", line)
            if not mac_match:
                continue

            mac_addr = mac_match.group(1)

            # Extract port name - it's the last token on the line
            parts = line.split()
            if not parts:
                continue

            port_name = parts[-1]

            # Only include Eth and Po ports, skip sup-eth, vPC peer-link, etc.
            if not re.match(r"(Eth|mgmt|Po)", port_name):
                continue

            if port_name not in port_mac_map:
                port_mac_map[port_name] = []
            port_mac_map[port_name].append(mac_addr)

        for intf_name, macs in port_mac_map.items():
            result[intf_name] = ", ".join(macs)

        return result
    except Exception:
        return {}


def _parse_vlan_for_ports_nexus(connection):
    """Nexus 'show interface status' çıktısından port VLAN bilgisini çıkarır.

    Returns:
        dict: {interface_name: vlan_str} — ör: {"Eth1/1": "100", "Po1": "trunk"}
    """
    try:
        output = connection.send_command("show interface status")
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

        vlan_start = col_positions.get("Vlan", -1)
        if vlan_start < 0:
            return result

        duplex_start = col_positions.get("Duplex", len(header_line))

        for line in lines[header_idx + 1:]:
            if not line.strip() or line.startswith("-"):
                continue
            parts = line.split()
            if not parts:
                continue
            intf_name = parts[0]
            if not re.match(r"(Eth|mgmt|Po)", intf_name):
                continue

            vlan_str = ""
            if vlan_start >= 0 and len(line) > vlan_start:
                vlan_str = line[vlan_start:duplex_start].strip()

            result[intf_name] = vlan_str

        return result
    except Exception:
        return {}


def _parse_error_counters_nexus(connection):
    """Nexus 'show interface counters errors' çıktısını parse eder.

    Returns:
        dict: {interface_name: {"total_errors": int, "detail": str}}
    """
    try:
        output = connection.send_command("show interface counters errors")
        result = {}

        lines = output.strip().splitlines()
        header_idx = None
        for i, line in enumerate(lines):
            # Nexus header varies, look for Port/Interface + error-related columns
            if ("Port" in line or "Interface" in line) and \
               ("Align" in line or "FCS" in line or "Xmit" in line or "Rcv" in line or "UnderSize" in line):
                header_idx = i
                break

        if header_idx is None:
            return result

        for line in lines[header_idx + 1:]:
            if not line.strip() or line.startswith("-"):
                continue
            parts = line.split()
            if not parts:
                continue
            intf_name = parts[0]
            if not re.match(r"(Eth|mgmt|Po)", intf_name):
                continue

            # Sum all numeric error columns
            numbers = []
            for p in parts[1:]:
                try:
                    numbers.append(int(p))
                except ValueError:
                    continue

            total = sum(numbers)
            result[intf_name] = {
                "total_errors": total,
                "detail": " / ".join(str(n) for n in numbers) if numbers else "0",
            }

        return result
    except Exception:
        return {}


def _parse_port_channel_members_nexus(connection):
    """Nexus 'show port-channel summary' çıktısını parse eder.

    Nexus output format:
        Group Port-       Type     Protocol  Member Ports
              Channel
        1     Po1(SU)     Eth      LACP      Eth1/49(P)    Eth1/50(P)
        10    Po10(SU)    Eth      LACP      Eth1/1(P)     Eth1/2(P)

    Returns:
        dict: {"Po1": "Eth1/49, Eth1/50", "Po10": "Eth1/1, Eth1/2"}
              Members as comma-separated string.
    """
    try:
        output = connection.send_command("show port-channel summary")
        result = {}

        lines = output.strip().splitlines()

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            # Skip header/legend lines
            if stripped.startswith("-") or stripped.startswith("Group") or \
               stripped.startswith("Channel") or stripped.startswith("Flags") or \
               stripped.startswith("D ") or stripped.startswith("I ") or \
               stripped.startswith("H ") or stripped.startswith("s ") or \
               stripped.startswith("S ") or stripped.startswith("P ") or \
               stripped.startswith("U ") or stripped.startswith("M "):
                continue

            # Look for Po name in the line: Po1(SU), Po10(SD), etc.
            po_match = re.search(r"(Po\d+)\([A-Za-z]+\)", line)
            if not po_match:
                continue

            po_name = po_match.group(1)

            # Extract all Eth member ports: Eth1/49(P), Eth1/50(P), etc.
            members = re.findall(r"(Eth\d+(?:/\d+)*)\([A-Za-z]+\)", line)

            # Filter out the Po reference itself if it somehow matched
            eth_members = [m for m in members if m.startswith("Eth")]

            if eth_members:
                result[po_name] = ", ".join(eth_members)

        return result
    except Exception:
        return {}
