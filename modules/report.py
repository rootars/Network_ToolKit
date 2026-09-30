"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from colorama import Fore, Style
from modules.meta import PROJECT_NAME
from modules.paths import get_project_root
from modules.session_store import get_keys
PROJECT_ROOT = get_project_root()
REPORTS_DIR = PROJECT_ROOT / 'reports'
REPORT_MENU = {'1': ('Son port tarama raporu', ['port_scan']), '2': ('Son ping tarama raporu', ['ping_scan']), '3': ('Son DNS sorgu raporu', ['dns_lookup']), '4': ('Son Whois / IP Info raporu', ['whois_lookup']), '5': ('Son log analiz raporu', ['log_analysis']), '6': ('Son SSH failed login raporu', ['ssh_failed']), '7': ('Son SNMP cihaz raporu', ['snmp_info']), '8': ('Tüm sonuçları raporla', ['port_scan', 'ping_scan', 'dns_lookup', 'whois_lookup', 'log_analysis', 'ssh_failed', 'snmp_info'])}
FORMAT_MENU = {'1': ('TXT', 'txt'), '2': ('JSON', 'json')}

def _generate_filename(extension: str) -> str:
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    return f"rootars-netaudit_report_{timestamp}.{extension}"

def _format_txt(report_data: dict[str, Any]) -> str:
    lines = [
        "=" * 50,
        f"{PROJECT_NAME} - Rapor",
        f"Oluşturulma: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 50,
        "",
    ]
    for module_key, entry in report_data.items():
        title = module_key.replace('_', ' ').upper()
        lines.append('-' * 50)
        lines.append(title)
        lines.append(f"Kayıt zamanı: {entry.get('timestamp', 'Bilinmiyor')}")
        lines.append('-' * 50)
        data = entry.get('data', {})
        lines.extend(_format_module_txt(module_key, data))
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'

def _format_module_txt(module_key: str, data: dict[str, Any]) -> list[str]:
    if module_key == 'port_scan':
        lines = [f"Hedef IP: {data.get('target', '')}"]
        if data.get('mac'):
            lines.append(f"Cihaz: {data.get('vendor') or 'Bilinmiyor'} (MAC {data['mac']})")
        lines.append('')
        for item in data.get('results', []):
            lines.append(f"[{item.get('status')}] {item.get('port')}")
        return lines
    if module_key == 'ping_scan':
        lines = [f"Network: {data.get('network', '')}", f"Toplam aktif: {data.get('total', 0)}", '']
        devices = data.get('devices')
        if devices is None:
            devices = [{'ip': host} for host in data.get('alive_hosts', [])]
        for device in devices:
            mac = device.get('mac') or '-'
            vendor = device.get('vendor') or ('Bilinmiyor' if device.get('mac') else '-')
            lines.append(f"[ALIVE] {device.get('ip', ''):<16}{mac:<18} {vendor}")
        return lines
    if module_key == 'dns_lookup':
        lines = [f"Domain: {data.get('domain', '')}", '']
        for record_type, section in data.get('results', {}).items():
            lines.append(f'[{record_type}]')
            if section.get('error'):
                lines.append(f"  Hata: {section['error']}")
            elif section.get('records'):
                lines.extend((f'  {record}' for record in section['records']))
            else:
                lines.append('  Kayıt bulunamadı.')
            lines.append('')
        return lines
    if module_key == 'log_analysis':
        lines = [f"Dosya: {data.get('file', '')}", f"Toplam satır: {data.get('total_lines', 0)}", f"Şüpheli satır: {data.get('suspicious_count', 0)}", '']
        for category, count in data.get('categories', {}).items():
            lines.append(f'[{category}] {count} adet')
        lines.append('')
        lines.append('Örnek şüpheli satırlar:')
        for idx, sample in enumerate(data.get('samples', []), start=1):
            lines.append(f"{idx}. [{sample.get('category')}] (satır {sample.get('line_no')}) {sample.get('text')}")
        return lines
    if module_key == 'whois_lookup':
        fields = [('Hedef', 'target'), ('IP', 'ip'), ('Ülke', 'country'), ('ASN', 'asn'), ('Organizasyon', 'organization'), ('Reverse DNS', 'reverse_dns')]
        return [f"{label}: {data.get(key, '')}" for label, key in fields]
    if module_key == 'ssh_failed':
        lines = [f"Dosya: {data.get('file', '')}", f"Toplam başarısız giriş: {data.get('total_attempts', 0)}", '', 'En çok deneyen IP adresleri:']
        lines.extend((f"  {idx}. {item.get('ip')} - {item.get('count')} deneme" for idx, item in enumerate(data.get('top_ips', []), start=1)))
        lines.extend(['', 'En çok denenen kullanıcı adları:'])
        lines.extend((f"  {idx}. {item.get('username')} - {item.get('count')} deneme" for idx, item in enumerate(data.get('top_users', []), start=1)))
        return lines
    if module_key == 'snmp_info':
        fields = [('IP', 'host'), ('SNMP', 'version'), ('Marka', 'vendor'), ('Device Name', 'sysName'), ('Description', 'sysDescr'), ('sysObjectID', 'sysObjectID'), ('Uptime', 'sysUpTime'), ('Contact', 'sysContact'), ('Location', 'sysLocation')]
        return [f"{label}: {data.get(key, 'Bilinmiyor')}" for label, key in fields]
    return [json.dumps(data, indent=2, ensure_ascii=False)]

def _build_report_payload(keys: list[str]) -> dict[str, Any] | None:
    payload = get_keys(keys)
    if not payload:
        return None
    return payload

def _save_report(content: str, extension: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    filepath = REPORTS_DIR / _generate_filename(extension)
    filepath.write_text(content, encoding='utf-8')
    return filepath

def _show_report_menu() -> None:
    print(Fore.WHITE + '\nHangi raporu oluşturmak istiyorsunuz?\n' + Style.RESET_ALL)
    for key, (label, _) in REPORT_MENU.items():
        print(Fore.GREEN + f'  {key}. ' + Fore.WHITE + label + Style.RESET_ALL)
    print()

def _show_format_menu() -> None:
    print(Fore.WHITE + '\nRapor formatı seçiniz:\n' + Style.RESET_ALL)
    for key, (label, _) in FORMAT_MENU.items():
        print(Fore.GREEN + f'  {key}. ' + Fore.WHITE + label + Style.RESET_ALL)
    print()

def run() -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n=== Raporlama ===' + Style.RESET_ALL)
    _show_report_menu()
    report_choice = input(Fore.YELLOW + 'Seçiminiz:\n> ' + Style.RESET_ALL).strip()
    if not report_choice:
        print(Fore.RED + '[!] Seçim boş bırakılamaz.' + Style.RESET_ALL)
        return
    if report_choice not in REPORT_MENU:
        print(Fore.RED + f'[!] Geçersiz seçim. Lütfen 1-{len(REPORT_MENU)} arası bir değer girin.' + Style.RESET_ALL)
        return
    _show_format_menu()
    format_choice = input(Fore.YELLOW + 'Seçiminiz:\n> ' + Style.RESET_ALL).strip()
    if not format_choice:
        print(Fore.RED + '[!] Seçim boş bırakılamaz.' + Style.RESET_ALL)
        return
    if format_choice not in FORMAT_MENU:
        print(Fore.RED + '[!] Geçersiz seçim. Lütfen 1 veya 2 girin.' + Style.RESET_ALL)
        return
    _, module_keys = REPORT_MENU[report_choice]
    _, extension = FORMAT_MENU[format_choice]
    report_data = _build_report_payload(module_keys)
    if not report_data:
        print(Fore.RED + '[!] Raporlanacak sonuç bulunamadı. Önce ilgili modülü çalıştırın.' + Style.RESET_ALL)
        return
    if extension == 'json':
        content = json.dumps({'generated_at': datetime.now().isoformat(timespec='seconds'), 'modules': report_data}, indent=2, ensure_ascii=False)
    else:
        content = _format_txt(report_data)
    filepath = _save_report(content, extension)
    print(Fore.CYAN + Style.BRIGHT + '\n' + '=' * 40)
    print('RAPORLAMA')
    print('=' * 40 + Style.RESET_ALL)
    print(Fore.GREEN + '\nRapor başarıyla oluşturuldu:\n' + Fore.WHITE + str(filepath.relative_to(PROJECT_ROOT)) + Style.RESET_ALL)
