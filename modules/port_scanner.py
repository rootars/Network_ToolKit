"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

import errno
import re
import socket
from colorama import Fore, Style
from modules.session_store import save as save_session
from modules.vendor import get_arp_table, mac_vendor
DEFAULT_TIMEOUT = 1.0
_IPV4_PATTERN = re.compile('^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$')

def _validate_ip(ip: str) -> bool:
    return bool(_IPV4_PATTERN.match(ip.strip()))

def _parse_ports(port_input: str) -> list[int]:
    raw = [part.strip() for part in port_input.split(',') if part.strip()]
    if not raw:
        raise ValueError('En az bir port girilmelidir.')
    ports: list[int] = []
    seen: set[int] = set()
    for part in raw:
        if not part.isdigit():
            raise ValueError(f"Geçersiz port: '{part}' (yalnızca 1-65535 arası sayı)")
        port = int(part)
        if port < 1 or port > 65535:
            raise ValueError(f'Geçersiz port aralığı: {port} (1-65535 olmalı)')
        if port not in seen:
            seen.add(port)
            ports.append(port)
    return ports

def _scan_port(host: str, port: int, timeout: float) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            return 'OPEN'
        if result == errno.ECONNREFUSED:
            return 'CLOSED'
        return 'FILTERED'
    except socket.timeout:
        return 'FILTERED'
    except OSError:
        return 'FILTERED'
    finally:
        sock.close()

def _status_color(status: str) -> str:
    colors = {'OPEN': Fore.GREEN, 'CLOSED': Fore.RED, 'FILTERED': Fore.YELLOW}
    return colors.get(status, Fore.WHITE)

def run() -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n=== Port Scanner ===' + Style.RESET_ALL)
    ip_input = input(Fore.WHITE + 'Port taraması yapmak istediğiniz IP adresi nedir?\n> ' + Style.RESET_ALL).strip()
    if not ip_input:
        print(Fore.RED + '[!] IP adresi boş bırakılamaz.' + Style.RESET_ALL)
        return
    if not _validate_ip(ip_input):
        print(Fore.RED + f'[!] Geçersiz IP adresi formatı: {ip_input}' + Style.RESET_ALL)
        return
    port_input = input(Fore.WHITE + 'Hangi portları taramak istiyorsunuz?\n' + 'Birden fazla port için virgül kullanınız.\n> ' + Style.RESET_ALL).strip()
    if not port_input:
        print(Fore.RED + '[!] Port listesi boş bırakılamaz.' + Style.RESET_ALL)
        return
    try:
        ports = _parse_ports(port_input)
    except ValueError as exc:
        print(Fore.RED + f'[!] {exc}' + Style.RESET_ALL)
        return
    print(Fore.CYAN + f'\n[*] Hedef: {ip_input} | Port sayısı: {len(ports)} | Timeout: {DEFAULT_TIMEOUT}s\n' + Style.RESET_ALL)
    results: list[dict[str, int | str]] = []
    for port in ports:
        status = _scan_port(ip_input, port, DEFAULT_TIMEOUT)
        results.append({'port': port, 'status': status})
        color = _status_color(status)
        print(color + f'[{status}] {port}' + Style.RESET_ALL)
    mac = get_arp_table().get(ip_input)
    vendor = mac_vendor(mac) if mac else None
    if mac:
        print(Fore.CYAN + f"\n[*] Cihaz: {vendor or 'Bilinmiyor'} (MAC {mac})" + Style.RESET_ALL)
    save_session('port_scan', {'target': ip_input, 'mac': mac, 'vendor': vendor, 'ports': ports, 'results': results})
    print(Fore.GREEN + '\n[+] Tarama tamamlandı.' + Style.RESET_ALL)
