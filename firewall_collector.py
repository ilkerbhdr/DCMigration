import re
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException


def normalize_mac(mac):
    """MAC adresini normalize eder (tüm ayırıcıları kaldırıp lowercase yapar).

    Desteklenen formatlar:
        e478.7637.b6fc      (Arista - xxxx.xxxx.xxxx)
        e4:78:76:37:b6:fc   (colon-separated - xx:xx:xx:xx:xx:xx)
        e4-78-76-37-b6-fc   (xx-xx-xx-xx-xx-xx)

    Returns:
        "e47876 37b6fc" gibi 12 karakterlik lowercase hex string
    """
    return re.sub(r"[.:\-]", "", mac.strip()).lower()


def collect_arp_table(host, username, password, port=22, device_type="paloalto_panos"):
    """Firewall'a SSH ile bağlanıp ARP tablosunu toplar.

    Desteklenen cihazlar:
        paloalto_panos: show arp all
        fortinet:       get system arp

    Returns:
        dict: {normalized_mac: ip_address} şeklinde.
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
        if device_type == "fortinet":
            output = connection.send_command("get system arp")
            return _parse_arp_output_fortigate(output)
        else:
            output = connection.send_command("show arp all")
            return _parse_arp_output(output)
    finally:
        connection.disconnect()


def _parse_arp_output(output):
    """'show arp all' çıktısını parse eder.

    Örnek çıktı (PAN-OS):
    maximum of entries supported :  8192
    default timeout:                1800

    total ARP entries in table : 150
    status: s - static, c - complete, e - expiring, i - incomplete

    interface         ip address      hw address        port  status ttl
    -----------------------------------------------------------------------
    ethernet1/1       192.168.1.1    e4:78:76:37:b6:fc eth1/1 c    1200
    ethernet1/1       192.168.1.2    aa:bb:cc:dd:ee:ff eth1/1 c    1500

    Returns:
        dict: {normalized_mac: ip_address}
    """
    result = {}

    lines = output.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("maximum") or \
           line.startswith("default") or line.startswith("total") or \
           line.startswith("status") or line.startswith("interface"):
            continue

        # ARP satırını parse et
        # Format: interface  ip_address  mac_address  port  status  ttl
        parts = line.split()
        if len(parts) < 4:
            continue

        ip_addr = parts[1]
        mac_addr = parts[2]

        # IP formatı kontrolü
        if not re.match(r"\d+\.\d+\.\d+\.\d+", ip_addr):
            continue

        # MAC formatı kontrolü (en az : veya . içermeli)
        if not re.search(r"[.:\-]", mac_addr):
            continue

        normalized = normalize_mac(mac_addr)
        if len(normalized) == 12:
            result[normalized] = ip_addr

    return result


def _parse_arp_output_fortigate(output):
    """FortiGate 'get system arp' çıktısını parse eder.

    Örnek çıktı:
    Address           Age(min)   Hardware Addr      Interface
    192.168.1.10      1          50:b7:c3:75:ea:dd  internal7
    192.168.1.20      0          28:f1:0e:03:2a:97  port1
    10.10.1.100       3          f4:f2:6d:37:b0:99  wan1

    Returns:
        dict: {normalized_mac: ip_address}
    """
    result = {}

    lines = output.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Address") or line.startswith("-"):
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        ip_addr = parts[0]
        mac_addr = parts[2]

        if not re.match(r"\d+\.\d+\.\d+\.\d+", ip_addr):
            continue

        if not re.search(r"[.:\-]", mac_addr):
            continue

        normalized = normalize_mac(mac_addr)
        if len(normalized) == 12:
            result[normalized] = ip_addr

    return result


def enrich_ports_with_arp(all_ports, arp_table):
    """Port listesindeki MAC adreslerini ARP tablosuyla eşleştirip IP ekler.

    Her port satırındaki mac_addresses alanını okur, ARP tablosunda arar,
    bulunan IP'leri aynı sırayla ip_address alanına yazar.

    Args:
        all_ports: List of port dicts (mac_addresses alanı olan)
        arp_table: {normalized_mac: ip_address} dict

    Returns:
        Güncellenmiş all_ports listesi (ip_address alanı eklenmiş)
    """
    for port in all_ports:
        mac_str = port.get("mac_addresses", "")
        if not mac_str:
            port["ip_address"] = ""
            continue

        macs = [m.strip() for m in mac_str.split(",")]
        ips = []
        for mac in macs:
            normalized = normalize_mac(mac)
            ip = arp_table.get(normalized, "")
            ips.append(ip)

        port["ip_address"] = ", ".join(ips)

    return all_ports
