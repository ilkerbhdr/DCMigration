import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def resolve_hostnames(all_ports, progress_callback=None):
    """Port listesindeki IP adreslerini paralel reverse DNS ile çözümler.

    Args:
        all_ports: List of port dicts (ip_address alanı olan)
        progress_callback: Opsiyonel fn(resolved_count, total_count) — ilerleme bildirimi

    Returns:
        Güncellenmiş all_ports listesi (hostname alanı eklenmiş)
    """
    # Tüm benzersiz IP'leri topla
    unique_ips = set()
    for port in all_ports:
        ip_str = port.get("ip_address", "")
        if not ip_str:
            continue
        for ip in ip_str.split(","):
            ip = ip.strip()
            if ip:
                unique_ips.add(ip)

    if not unique_ips:
        for port in all_ports:
            port["hostname"] = ""
        return all_ports

    # Paralel DNS çözümleme (max 20 thread)
    dns_cache = {}
    total = len(unique_ips)
    resolved = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_reverse_lookup, ip): ip for ip in unique_ips}
        for future in as_completed(futures):
            ip = futures[future]
            dns_cache[ip] = future.result()
            resolved += 1
            if progress_callback:
                progress_callback(resolved, total)

    # Sonuçları portlara eşle
    for port in all_ports:
        ip_str = port.get("ip_address", "")
        if not ip_str:
            port["hostname"] = ""
            continue

        ips = [ip.strip() for ip in ip_str.split(",")]
        hostnames = [dns_cache.get(ip, "") for ip in ips]
        port["hostname"] = ", ".join(hostnames)

    return all_ports


def _reverse_lookup(ip):
    """Tek bir IP için reverse DNS sorgusu yapar (1 sn timeout)."""
    try:
        socket.setdefaulttimeout(1)
        result = socket.gethostbyaddr(ip)
        return result[0] if result[0] else ""
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""
