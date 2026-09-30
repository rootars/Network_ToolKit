"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

import json
import re
import socket
import urllib.error
import urllib.request
from colorama import Fore, Style

from modules.meta import USER_AGENT
from modules.session_store import save as save_session

IPV4_PATTERN = re.compile('^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$')
DOMAIN_PATTERN = re.compile('^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$')
API_TIMEOUT = 5
IP_API_FIELDS = 'status,message,country,as,org,reverse,query'

def _is_ip(value: str) -> bool:
    return bool(IPV4_PATTERN.match(value))

def _is_domain(value: str) -> bool:
    return bool(DOMAIN_PATTERN.match(value.lower()))

def _resolve_domain(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as exc:
        raise ValueError(f'Domain çözümlenemedi: {domain}') from exc

def _reverse_dns(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.rstrip('.')
    except (socket.herror, socket.gaierror, OSError):
        return None

def _parse_as_field(as_field: str, org_field: str) -> tuple[str, str]:
    if not as_field:
        return ('Bilinmiyor', org_field or 'Bilinmiyor')
    parts = as_field.split(' ', 1)
    asn = parts[0]
    organization = parts[1].strip() if len(parts) > 1 else org_field or 'Bilinmiyor'
    return (asn, organization)

def _fetch_ip_info(ip: str) -> dict[str, str]:
    url = f'http://ip-api.com/json/{ip}?fields={IP_API_FIELDS}'
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=API_TIMEOUT) as response:
            data = json.loads(response.read().decode('utf-8'))
    except urllib.error.URLError as exc:
        raise ValueError(f'IP bilgisi alınamadı: {exc}') from exc
    except json.JSONDecodeError as exc:
        raise ValueError('IP bilgisi yanıtı okunamadı.') from exc
    if data.get('status') != 'success':
        message = data.get('message', 'Bilinmeyen hata')
        raise ValueError(f'Sorgu başarısız: {message}')
    asn, organization = _parse_as_field(data.get('as', ''), data.get('org', ''))
    reverse = data.get('reverse') or _reverse_dns(ip) or 'Bilinmiyor'
    return {'ip': data.get('query', ip), 'country': data.get('country', 'Bilinmiyor'), 'asn': asn, 'organization': organization, 'reverse_dns': reverse}

def _print_results(target: str, info: dict[str, str]) -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n' + '=' * 40)
    print('WHOIS / IP INFO SONUÇLARI')
    print('=' * 40 + Style.RESET_ALL + '\n')
    fields = [('Hedef', target), ('IP', info['ip']), ('Ülke', info['country']), ('ASN', info['asn']), ('Organizasyon', info['organization']), ('Reverse DNS', info['reverse_dns'])]
    for label, value in fields:
        print(Fore.WHITE + f'{label}: ' + Fore.GREEN + value + Style.RESET_ALL)

def run() -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n=== Whois / IP Info ===' + Style.RESET_ALL)
    target_input = input(Fore.WHITE + 'Sorgulamak istediğiniz IP veya domain adresini giriniz.\n' + 'Örnek: 8.8.8.8 veya google.com\n> ' + Style.RESET_ALL).strip()
    if not target_input:
        print(Fore.RED + '[!] Hedef adres boş bırakılamaz.' + Style.RESET_ALL)
        return
    target = target_input.lower()
    query_ip: str
    if _is_ip(target):
        query_ip = target
    elif _is_domain(target):
        try:
            query_ip = _resolve_domain(target)
            print(Fore.CYAN + f'\n[*] Domain çözümlendi: {target} -> {query_ip}' + Style.RESET_ALL)
        except ValueError as exc:
            print(Fore.RED + f'[!] {exc}' + Style.RESET_ALL)
            return
    else:
        print(Fore.RED + f'[!] Geçersiz IP veya domain formatı: {target_input}' + Style.RESET_ALL)
        return
    print(Fore.YELLOW + '\n[*] Bilgiler sorgulanıyor...' + Style.RESET_ALL)
    try:
        info = _fetch_ip_info(query_ip)
    except ValueError as exc:
        print(Fore.RED + f'[!] {exc}' + Style.RESET_ALL)
        return
    _print_results(target_input, info)
    save_session('whois_lookup', {'target': target_input, **info})
    print(Fore.GREEN + '\n[+] Sorgu tamamlandı.' + Style.RESET_ALL)
