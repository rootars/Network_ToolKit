"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from colorama import Fore, Style
from modules.session_store import save as save_session
TOP_RESULTS = 10
SSH_FAILURE_PATTERNS = ['failed password', 'invalid user', 'authentication failure', 'connection closed by authenticating user']
EXTRACT_PATTERNS: list[tuple[re.Pattern[str], int, int]] = [(re.compile('Failed password for invalid user (\\S+) from ([\\d.]+)', re.IGNORECASE), 1, 2), (re.compile('Failed password for (\\S+) from ([\\d.]+)', re.IGNORECASE), 1, 2), (re.compile('Invalid user (\\S+) from ([\\d.]+)', re.IGNORECASE), 1, 2), (re.compile('authentication failure.*rhost=([\\d.]+).*user=(\\S+)', re.IGNORECASE), 2, 1), (re.compile('authentication failure.*user=(\\S+).*rhost=([\\d.]+)', re.IGNORECASE), 1, 2), (re.compile('Connection closed by authenticating user (\\S+) ([\\d.]+)', re.IGNORECASE), 1, 2)]

@dataclass
class FailedAttempt:
    username: str
    ip: str
    line_no: int

def _is_ssh_failure(line: str) -> bool:
    lower = line.lower()
    return any((pattern in lower for pattern in SSH_FAILURE_PATTERNS))

def _extract_attempt(line: str, line_no: int) -> FailedAttempt | None:
    for pattern, user_group, ip_group in EXTRACT_PATTERNS:
        match = pattern.search(line)
        if match:
            username = match.group(user_group)
            ip = match.group(ip_group)
            if username and ip:
                return FailedAttempt(username=username, ip=ip, line_no=line_no)
    return None

def _read_log_file(path: Path) -> list[str]:
    with path.open('r', encoding='utf-8', errors='replace') as handle:
        return handle.readlines()

def _analyze_log(lines: list[str]) -> list[FailedAttempt]:
    attempts: list[FailedAttempt] = []
    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip('\n\r')
        if not line.strip() or not _is_ssh_failure(line):
            continue
        attempt = _extract_attempt(line, line_no)
        if attempt:
            attempts.append(attempt)
    return attempts

def _print_top_list(title: str, items: list[tuple[str, int]]) -> None:
    print(Fore.CYAN + Style.BRIGHT + f'\n{title}\n' + Style.RESET_ALL)
    if not items:
        print(Fore.YELLOW + '  Kayıt bulunamadı.' + Style.RESET_ALL)
        return
    for rank, (name, count) in enumerate(items, start=1):
        print(Fore.GREEN + f'{rank}. ' + Fore.WHITE + f'{name} - {count} deneme' + Style.RESET_ALL)

def _print_results(attempts: list[FailedAttempt]) -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n' + '=' * 40)
    print('SSH FAILED LOGIN SONUÇLARI')
    print('=' * 40 + Style.RESET_ALL + '\n')
    print(Fore.WHITE + f'Toplam başarısız giriş: {len(attempts)}' + Style.RESET_ALL)
    if not attempts:
        print(Fore.YELLOW + '\n  Başarısız SSH giriş denemesi bulunamadı.' + Style.RESET_ALL)
        return
    ip_counts = Counter((a.ip for a in attempts)).most_common(TOP_RESULTS)
    user_counts = Counter((a.username for a in attempts)).most_common(TOP_RESULTS)
    _print_top_list('En çok deneyen IP adresleri:', ip_counts)
    _print_top_list('En çok denenen kullanıcı adları:', user_counts)

def run() -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n=== SSH Failed Login Detector ===' + Style.RESET_ALL)
    path_input = input(Fore.WHITE + 'SSH auth log dosyasının yolunu giriniz.\n' + 'Örnek: /var/log/auth.log\n> ' + Style.RESET_ALL).strip()
    if not path_input:
        print(Fore.RED + '[!] Dosya yolu boş bırakılamaz.' + Style.RESET_ALL)
        return
    log_path = Path(path_input).expanduser()
    if not log_path.exists():
        print(Fore.RED + f'[!] Dosya bulunamadı: {log_path}' + Style.RESET_ALL)
        return
    if not log_path.is_file():
        print(Fore.RED + f'[!] Geçerli bir dosya değil: {log_path}' + Style.RESET_ALL)
        return
    print(Fore.YELLOW + '\n[*] SSH auth log analiz ediliyor...' + Style.RESET_ALL)
    try:
        lines = _read_log_file(log_path)
    except PermissionError:
        print(Fore.RED + f'[!] Dosyaya erişim izni yok: {log_path}' + Style.RESET_ALL)
        return
    except OSError as exc:
        print(Fore.RED + f'[!] Dosya okunamadı: {exc}' + Style.RESET_ALL)
        return
    attempts = _analyze_log(lines)
    _print_results(attempts)
    top_ips = Counter((a.ip for a in attempts)).most_common(TOP_RESULTS)
    top_users = Counter((a.username for a in attempts)).most_common(TOP_RESULTS)
    save_session('ssh_failed', {'file': str(log_path), 'total_attempts': len(attempts), 'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips], 'top_users': [{'username': user, 'count': count} for user, count in top_users]})
    print(Fore.GREEN + '\n[+] Analiz tamamlandı.' + Style.RESET_ALL)
