"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from modules.session_store import save as save_session
from modules.vendor import get_arp_table, mac_vendor
DEFAULT_TIMEOUT = 1.0
MAX_HOSTS = 254
MAX_WORKERS = 50

def _parse_network(cidr_input: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(cidr_input.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f'Geçersiz network adresi: {cidr_input}') from exc
    if network.version != 4:
        raise ValueError('Yalnızca IPv4 network desteklenmektedir (ör. 192.168.1.0/24).')
    return network

def _build_ping_command(host: str, timeout: float) -> list[str]:
    system = platform.system()
    if system == 'Windows':
        return ['ping', '-n', '1', '-w', str(int(timeout * 1000)), host]
    return ['ping', '-c', '1', host]


def _ping_host(host: str, timeout: float) -> bool:
    cmd = _build_ping_command(host, timeout)
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False

def _scan_network(hosts: list[str], timeout: float) -> list[str]:
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(_ping_host, host, timeout): host for host in hosts}
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                if future.result():
                    alive.append(host)
            except Exception:
                pass
    alive.sort(key=lambda ip: ipaddress.IPv4Address(ip))
    return alive

def _identify_devices(hosts: list[str]) -> list[dict[str, str | None]]:
    arp_table = get_arp_table()
    devices: list[dict[str, str | None]] = []
    for host in hosts:
        mac = arp_table.get(host)
        devices.append({'ip': host, 'mac': mac, 'vendor': mac_vendor(mac) if mac else None})
    return devices

def run() -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n=== Ping Scanner ===' + Style.RESET_ALL)
    cidr_input = input(Fore.WHITE + 'Ping taraması yapmak istediğiniz network adresini giriniz.\n' + 'Örnek: 192.168.1.0/24\n> ' + Style.RESET_ALL).strip()
    if not cidr_input:
        print(Fore.RED + '[!] Network adresi boş bırakılamaz.' + Style.RESET_ALL)
        return
    try:
        network = _parse_network(cidr_input)
    except ValueError as exc:
        print(Fore.RED + f'[!] {exc}' + Style.RESET_ALL)
        return
    hosts = [str(ip) for ip in network.hosts()]
    if not hosts:
        print(Fore.RED + '[!] Taranacak host bulunamadı.' + Style.RESET_ALL)
        return
    if len(hosts) > MAX_HOSTS:
        print(Fore.RED + f'[!] Çok geniş ağ ({len(hosts)} host). Maksimum /24 ({MAX_HOSTS} host) desteklenir.' + Style.RESET_ALL)
        return
    ping_flag = '-n 1' if platform.system() == 'Windows' else '-c 1'
    print(
        Fore.CYAN
        + f'\n[*] Hedef: {network} | Host sayısı: {len(hosts)} | '
        f'OS: {platform.system()} | Ping: {ping_flag} | Timeout: {DEFAULT_TIMEOUT}s\n'
        + Style.RESET_ALL
    )
    print(Fore.CYAN + f"[*] Ping atılacak IP'ler: {hosts[0]} - {hosts[-1]}" + (' (ağ ve broadcast adresi hariç)' if network.prefixlen < 31 else '') + Style.RESET_ALL)
    print(Fore.YELLOW + f'[*] Tarama başlatıldı ({MAX_WORKERS} paralel ping), lütfen bekleyin...' + Style.RESET_ALL)
    alive_hosts = _scan_network(hosts, DEFAULT_TIMEOUT)
    print(Fore.CYAN + Style.BRIGHT + '\n' + '=' * 40)
    print('PING SCANNER SONUÇLARI')
    print('=' * 40 + Style.RESET_ALL + '\n')
    devices = _identify_devices(alive_hosts)
    if devices:
        for device in devices:
            mac = device['mac'] or '-'
            vendor = device['vendor'] or ('Bilinmiyor' if device['mac'] else '-')
            print(Fore.GREEN + f"[ALIVE] {device['ip']:<16}" + Fore.WHITE + f'{mac:<18} ' + Fore.CYAN + vendor + Style.RESET_ALL)
        if any((device['mac'] is None for device in devices)):
            print(Fore.YELLOW + '\n[*] MAC/marka yalnızca aynı yerel ağdaki cihazlar için bulunabilir.\n' + "    Router arkasındaki cihazlar için SNMP Collector'u kullanın." + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + '  Aktif cihaz bulunamadı.' + Style.RESET_ALL)
    print(Fore.CYAN + Style.BRIGHT + f'\nToplam aktif cihaz: {len(alive_hosts)}' + Style.RESET_ALL)
    save_session('ping_scan', {'network': str(network), 'alive_hosts': alive_hosts, 'devices': devices, 'total': len(alive_hosts)})
