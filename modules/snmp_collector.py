"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

import asyncio
import re
from colorama import Fore, Style
from pysnmp.hlapi.v3arch.asyncio import CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, get_cmd
from modules.session_store import save as save_session
from modules.vendor import snmp_vendor
IPV4_PATTERN = re.compile('^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$')
SNMP_TIMEOUT = 2
SNMP_RETRIES = 1
DEFAULT_COMMUNITY = 'public'
VERSION_MENU = {'1': 'SNMP v2c', '2': 'SNMP v3'}
SYSTEM_OIDS = {'sysName': '1.3.6.1.2.1.1.5.0', 'sysDescr': '1.3.6.1.2.1.1.1.0', 'sysObjectID': '1.3.6.1.2.1.1.2.0', 'sysUpTime': '1.3.6.1.2.1.1.3.0', 'sysContact': '1.3.6.1.2.1.1.4.0', 'sysLocation': '1.3.6.1.2.1.1.6.0'}

def _validate_ip(ip: str) -> bool:
    return bool(IPV4_PATTERN.match(ip.strip()))

def _format_uptime(ticks_value: str) -> str:
    try:
        ticks = int(str(ticks_value))
    except (TypeError, ValueError):
        return str(ticks_value)
    total_seconds = ticks // 100
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days} day{('s' if days != 1 else '')}")
    if hours:
        parts.append(f"{hours} hour{('s' if hours != 1 else '')}")
    if minutes and (not days):
        parts.append(f"{minutes} minute{('s' if minutes != 1 else '')}")
    if not parts:
        if seconds:
            parts.append(f"{seconds} second{('s' if seconds != 1 else '')}")
        else:
            parts.append('0 seconds')
    return ', '.join(parts)

async def _collect_device_info_async(host: str, community: str) -> dict[str, str]:
    snmp_engine = SnmpEngine()
    info: dict[str, str] = {}
    try:
        transport = await UdpTransportTarget.create((host, 161), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES)
        for key, oid in SYSTEM_OIDS.items():
            error_indication, error_status, _error_index, var_binds = await get_cmd(snmp_engine, CommunityData(community), transport, ContextData(), ObjectType(ObjectIdentity(oid)))
            if error_indication:
                raise ConnectionError(str(error_indication))
            if error_status:
                raise ConnectionError(error_status.prettyPrint())
            value = str(var_binds[0][1])
            if key == 'sysUpTime':
                value = _format_uptime(value)
            info[key] = value or 'Bilinmiyor'
    finally:
        snmp_engine.close_dispatcher()
    return info

def _collect_device_info(host: str, community: str) -> dict[str, str]:
    return asyncio.run(_collect_device_info_async(host, community))

def _print_results(host: str, info: dict[str, str]) -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n' + '=' * 40)
    print('SNMP DEVICE INFO SONUÇLARI')
    print('=' * 40 + Style.RESET_ALL + '\n')
    fields = [('IP', host), ('Marka', info.get('vendor', 'Bilinmiyor')), ('Device Name', info.get('sysName', 'Bilinmiyor')), ('Description', info.get('sysDescr', 'Bilinmiyor')), ('Uptime', info.get('sysUpTime', 'Bilinmiyor')), ('Contact', info.get('sysContact', 'Bilinmiyor')), ('Location', info.get('sysLocation', 'Bilinmiyor'))]
    for label, value in fields:
        print(Fore.WHITE + f'{label}: ' + Fore.GREEN + value + Style.RESET_ALL)

def _show_version_menu() -> None:
    print(Fore.WHITE + '\nSNMP version seçiniz:\n' + Style.RESET_ALL)
    for key, label in VERSION_MENU.items():
        print(Fore.GREEN + f'  {key}. ' + Fore.WHITE + label + Style.RESET_ALL)
    print()

def run() -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n=== SNMP Device Info Collector ===' + Style.RESET_ALL)
    ip_input = input(Fore.WHITE + 'SNMP ile bilgi almak istediğiniz cihaz IP adresini giriniz.\n' + 'Örnek: 192.168.1.1\n> ' + Style.RESET_ALL).strip()
    if not ip_input:
        print(Fore.RED + '[!] IP adresi boş bırakılamaz.' + Style.RESET_ALL)
        return
    if not _validate_ip(ip_input):
        print(Fore.RED + f'[!] Geçersiz IP adresi formatı: {ip_input}' + Style.RESET_ALL)
        return
    community_input = input(Fore.WHITE + 'SNMP community bilgisini giriniz.\n' + f'Varsayılan: {DEFAULT_COMMUNITY}\n> ' + Style.RESET_ALL).strip()
    community = community_input or DEFAULT_COMMUNITY
    _show_version_menu()
    version_choice = input(Fore.YELLOW + 'Seçiminiz:\n> ' + Style.RESET_ALL).strip()
    if not version_choice:
        print(Fore.RED + '[!] Seçim boş bırakılamaz.' + Style.RESET_ALL)
        return
    if version_choice not in VERSION_MENU:
        print(Fore.RED + '[!] Geçersiz seçim. Lütfen 1 veya 2 girin.' + Style.RESET_ALL)
        return
    if version_choice == '2':
        print(Fore.YELLOW + '\n  [*] SNMP v3 desteği yakında eklenecek. Şimdilik SNMP v2c kullanın.' + Style.RESET_ALL)
        return
    print(Fore.YELLOW + '\n[*] SNMP bilgileri alınıyor...' + Style.RESET_ALL)
    try:
        info = _collect_device_info(ip_input, community)
    except ConnectionError as exc:
        print(Fore.RED + f'[!] SNMP sorgusu başarısız: {exc}\n' + '    Cihazın SNMP v2c etkin olduğundan ve community bilgisinin doğru olduğundan emin olun.' + Style.RESET_ALL)
        return
    info['vendor'] = snmp_vendor(info.get('sysObjectID', ''), info.get('sysDescr', '')) or 'Bilinmiyor'
    _print_results(ip_input, info)
    save_session('snmp_info', {'host': ip_input, 'version': 'v2c', **info})
    print(Fore.GREEN + '\n[+] SNMP sorgusu tamamlandı.' + Style.RESET_ALL)
