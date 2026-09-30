"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

import platform
import re
import subprocess
from pathlib import Path
from netaddr import EUI
from netaddr.core import AddrFormatError, NotRegisteredError
ARP_TIMEOUT = 5
PROC_ARP = Path('/proc/net/arp')
_IP_RE = re.compile('(\\d{1,3}(?:\\.\\d{1,3}){3})')
_MAC_RE = re.compile('(?<![0-9A-Fa-f])([0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})(?![0-9A-Fa-f])')
_IGNORED_MACS = {'00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'}
VENDOR_ALIASES = {'Routerboard.com': 'MikroTik'}
SNMP_ENTERPRISES = {9: 'Cisco', 11: 'HP', 161: 'Motorola / Cambium', 171: 'D-Link', 311: 'Microsoft', 890: 'ZyXEL', 2011: 'Huawei', 2636: 'Juniper', 8072: 'Net-SNMP (Linux/Unix)', 10002: 'Ubiquiti (airOS)', 11863: 'TP-Link', 12356: 'Fortinet', 14988: 'MikroTik', 17713: 'Cambium', 25461: 'Palo Alto', 30065: 'Arista', 41112: 'Ubiquiti', 43356: 'Mimosa'}
SYSDESCR_KEYWORDS: list[tuple[str, list[str]]] = [('MikroTik', ['routeros', 'mikrotik']), ('Ubiquiti', ['ubnt', 'ubiquiti', 'airos', 'edgeos', 'unifi']), ('Cambium', ['cambium', 'epmp', 'cnpilot']), ('Mimosa', ['mimosa']), ('Cisco', ['cisco']), ('Juniper', ['juniper', 'junos']), ('Huawei', ['huawei'])]
ENTERPRISE_PREFIX = '1.3.6.1.4.1.'
NET_SNMP_ENTERPRISE = 8072

def normalize_mac(mac: str) -> str:
    return ':'.join((part.zfill(2) for part in re.split('[:-]', mac.strip()))).upper()

def _read_arp_lines() -> list[str]:
    if PROC_ARP.exists():
        try:
            return PROC_ARP.read_text(encoding='utf-8', errors='replace').splitlines()[1:]
        except OSError:
            pass
    cmd = ['arp', '-a'] if platform.system() == 'Windows' else ['arp', '-an']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=ARP_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError):
        return []
    return result.stdout.splitlines()

def get_arp_table() -> dict[str, str]:
    table: dict[str, str] = {}
    for line in _read_arp_lines():
        ip_match = _IP_RE.search(line)
        mac_match = _MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue
        mac = normalize_mac(mac_match.group(1))
        if mac in _IGNORED_MACS:
            continue
        table[ip_match.group(1)] = mac
    return table

def is_locally_administered(mac: str) -> bool:
    return bool(int(normalize_mac(mac)[:2], 16) & 2)

def mac_vendor(mac: str) -> str | None:
    try:
        org = EUI(normalize_mac(mac)).oui.registration().org
    except (AddrFormatError, NotRegisteredError, IndexError, TypeError, ValueError):
        if is_locally_administered(mac):
            return 'Rastgele / yerel MAC'
        return None
    return VENDOR_ALIASES.get(org, org)

def _vendor_from_descr(sys_descr: str) -> str | None:
    lower = sys_descr.lower()
    for vendor, keywords in SYSDESCR_KEYWORDS:
        if any((keyword in lower for keyword in keywords)):
            return vendor
    return None

def snmp_vendor(sys_object_id: str, sys_descr: str='') -> str | None:
    oid = sys_object_id.strip()
    enterprise_vendor = None
    if oid.startswith(ENTERPRISE_PREFIX):
        enterprise = oid[len(ENTERPRISE_PREFIX):].split('.', 1)[0]
        if enterprise.isdigit():
            number = int(enterprise)
            enterprise_vendor = SNMP_ENTERPRISES.get(number)
            if enterprise_vendor and number != NET_SNMP_ENTERPRISE:
                return enterprise_vendor
    return _vendor_from_descr(sys_descr) or enterprise_vendor
