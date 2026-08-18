"""
backend/net_interfaces.py - Network Adapter Enumeration & Auto-Subnet Discovery

Enumerates all active network interfaces (Wi-Fi, Ethernet, VPN, WSL, VirtualBox)
and resolves local IP addresses, netmasks, CIDR subnet ranges, and default gateways.
Filters out virtual/host-only adapters when selecting the primary interface.
Supports both English and Bulgarian ipconfig /all output.
"""

import ipaddress
import logging
import re
import socket
import subprocess
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────
# Virtual adapter detection
# ────────────────────────────────────────────────────────────────

_VIRTUAL_ADAPTER_PATTERNS = [
    r"virtualbox", r"host.only", r"host-only",
    r"vmware", r"vmnet",
    r"hyper-v", r"vether", r"virtual ethernet",
    r"wsl", r"windows subsystem for linux",
    r"loopback", r"bluetooth",
    r"tap-windows", r"openvpn",
    r"vpn", r"tunnel",
    r"hamachi", r"radmin", r"zerotier",
    r"pcsb",  # VirtualBox Bridged Network Driver
]

# Known virtual/host-only subnets (CIDRs)
_VIRTUAL_CIDRS = {
    ipaddress.ip_network("192.168.56.0/24"),   # VirtualBox Host-Only default
    ipaddress.ip_network("10.0.2.0/24"),        # VirtualBox NAT default
    ipaddress.ip_network("172.16.0.0/12"),      # Docker / VPN (broad; only used as soft signal)
}


def _is_virtual_adapter(name: str) -> bool:
    """Heuristic: is this a virtual/host-only/tunnel adapter based on name?"""
    name_lower = name.lower()
    for pat in _VIRTUAL_ADAPTER_PATTERNS:
        if re.search(pat, name_lower):
            return True
    return False


def _is_virtual_subnet(ip_str: str) -> bool:
    """Check if an IP falls within a known virtual/host-only subnet."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in _VIRTUAL_CIDRS:
            if addr in net:
                return True
    except Exception:
        pass
    return False


def _adapter_sort_key(iface: Dict[str, Any]) -> int:
    """Sort key: real adapters with gateway first, then real, then virtual."""
    is_virt = iface.get("_virtual", False)
    has_gw = bool(iface.get("gateway"))
    # 0 = best (real + gateway), 1 = real no gw, 2 = virtual + gw, 3 = virtual no gw
    if not is_virt and has_gw:
        return 0
    elif not is_virt:
        return 1
    elif has_gw:
        return 2
    return 3


# ────────────────────────────────────────────────────────────────
# ipconfig pattern matching (English + Bulgarian)
# ────────────────────────────────────────────────────────────────

# Each tuple: (label, pattern, key)
# Patterns are tried in order; first match wins for that key.
_IPCONFIG_PATTERNS = [
    # IPv4 Address — English then Bulgarian
    ("IPv4 Address", re.compile(r"IPv4 Address[.\s]+:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"), "ip"),
    ("IPv4 адрес",   re.compile(r"IPv4\s+адрес[.\s]+:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"), "ip"),
    # Subnet Mask
    ("Subnet Mask",      re.compile(r"Subnet Mask[.\s]+:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"), "netmask"),
    ("Подмрежова маска", re.compile(r"Подмрежова\s+маска[.\s]+:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"), "netmask"),
    # Default Gateway
    ("Default Gateway",  re.compile(r"Default Gateway[.\s]+:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"), "gateway"),
    ("Основен шлюз",     re.compile(r"Основен\s+шлюз[.\s]+:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"), "gateway"),
    # Physical Address / MAC
    ("Physical Address",  re.compile(r"Physical Address[.\s]+:\s*([0-9A-Fa-f\-]{17})"), "mac"),
    ("Физически адрес",   re.compile(r"Физически\s+адрес[.\s]+:\s*([0-9A-Fa-f\-]{17})"), "mac"),
    # Media State — "Media disconnected" / "Състояние на носителя . . . : Носителят е прекъснат"
    ("Media State",       re.compile(r"Media State[.\s]+:.*(?:disconnected|Disconnected)"), "disconnected"),
    ("Състояние на носителя", re.compile(r"Състояние\s+на\s+носителя[.\s]+:.*(?:прекъснат|Прекъснат)"), "disconnected"),
]

# Header regex: "Ethernet adapter X:", "Wireless LAN adapter Wi-Fi:", etc.
# Also Bulgarian: "Ethernet адаптер", "Адаптер за безжична LAN мрежа"
_ADAPTER_HEADER_RE = re.compile(
    r"^(?:[A-Za-z0-9\s\-\u0400-\u04FF]+(?:adapter|адаптер|adapter))\s+(.+?):", re.IGNORECASE
)
# Wider fallback for lines that look like headers ending with ":"
_ADAPTER_HEADER_FALLBACK_RE = re.compile(
    r"^(?:Ethernet|Wireless|Wi-Fi|Ethernet|Bluetooth|VirtualBox|VMware|Hyper-V|vEthernet|WSL)[^\n]*:$", re.IGNORECASE
)


def _parse_ipconfig_line(
    line: str, current_iface: Dict[str, Any]
) -> None:
    """Try all locale patterns against an ipconfig line; update iface dict on match."""
    for _label, pattern, key in _IPCONFIG_PATTERNS:
        m = pattern.search(line)
        if m:
            if key == "ip":
                current_iface["ip"] = m.group(1).strip()
            elif key == "netmask":
                current_iface["netmask"] = m.group(1).strip()
            elif key == "gateway":
                current_iface["gateway"] = m.group(1).strip()
            elif key == "mac":
                current_iface["mac"] = m.group(1).replace("-", ":").upper()
            elif key == "disconnected":
                current_iface["status"] = "disconnected"
            return  # first match wins per line


# ────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────


def _mask_to_cidr(netmask_str: str) -> int:
    """Convert dotted netmask string (e.g. '255.255.255.0') to CIDR prefix integer (e.g. 24)."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask_str}").prefixlen
    except Exception:
        return 24


def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerate active network adapters across Windows, Linux, and macOS.
    Virtual (host-only/tunnel) adapters are tagged but still included.
    Sorted: real + gateway first, virtual last.

    :return: List of interface dictionary descriptors.
    """
    interfaces: List[Dict[str, Any]] = []

    if sys.platform == "win32":
        interfaces = _get_windows_interfaces()
    else:
        interfaces = _get_unix_interfaces()

    # Fallback to standard socket discovery if no interfaces were resolved
    if not interfaces:
        interfaces = _get_socket_fallback_interfaces()

    # Tag virtual adapters
    for iface in interfaces:
        is_virt = _is_virtual_adapter(iface.get("name", "")) or _is_virtual_subnet(
            iface.get("ip", "")
        )
        iface["_virtual"] = is_virt

    # Sort: real adapters with gateway first, virtual last
    interfaces.sort(key=_adapter_sort_key)

    return interfaces


def _get_windows_interfaces() -> List[Dict[str, Any]]:
    """Enumerate Windows network adapters by parsing ipconfig /all output."""
    interfaces: List[Dict[str, Any]] = []
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0

        proc = subprocess.run(
            ["ipconfig", "/all"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
            startupinfo=startupinfo,
            timeout=5,
        )

        current_iface: Optional[Dict[str, Any]] = None

        for line in proc.stdout.splitlines():
            # Check for interface section headers (English + Bulgarian)
            match_header = _ADAPTER_HEADER_RE.match(line)
            if not match_header:
                # Fallback: any line ending with ":" that looks like an adapter name
                match_header = _ADAPTER_HEADER_FALLBACK_RE.match(line)

            if match_header:
                if current_iface and current_iface.get("ip"):
                    interfaces.append(current_iface)
                name = match_header.group(1).strip() if match_header.lastindex else match_header.group(0).rstrip(":").strip()
                current_iface = {
                    "name": name,
                    "type": _detect_iface_type(name),
                    "ip": "",
                    "netmask": "255.255.255.0",
                    "cidr": "",
                    "gateway": "",
                    "mac": "",
                    "status": "connected",
                }
                continue

            if not current_iface:
                continue

            _parse_ipconfig_line(line, current_iface)

            # Also check for generic disconnected indicators
            if "Media State" in line and "disconnected" in line.lower():
                current_iface["status"] = "disconnected"

        if current_iface and current_iface.get("ip"):
            interfaces.append(current_iface)

    except Exception as e:
        logger.exception(f"Failed parsing Windows ipconfig: {e}")

    # Compute CIDR for all connected interfaces
    valid_interfaces = []
    for iface in interfaces:
        if (
            iface.get("ip")
            and not iface["ip"].startswith("127.")
            and iface.get("status") != "disconnected"
        ):
            try:
                mask = iface.get("netmask") or "255.255.255.0"
                network = ipaddress.IPv4Network(f"{iface['ip']}/{mask}", strict=False)
                iface["cidr"] = str(network)
                iface["prefix"] = network.prefixlen
                iface["usable_hosts"] = max(1, network.num_addresses - 2)
            except Exception:
                iface["cidr"] = f"{iface['ip']}/24"
                iface["prefix"] = 24
                iface["usable_hosts"] = 254
            valid_interfaces.append(iface)

    return valid_interfaces


def _detect_iface_type(name: str) -> str:
    """Guess adapter type from name."""
    n = name.lower()
    if any(k in n for k in ("wi-fi", "wireless", "wlan", "безжична")):
        return "wifi"
    return "ethernet"


def _get_unix_interfaces() -> List[Dict[str, Any]]:
    """Enumerate Unix interfaces using ip route or ifconfig."""
    interfaces: List[Dict[str, Any]] = []
    try:
        proc = subprocess.run(
            ["ip", "-4", "-o", "addr"], stdout=subprocess.PIPE, text=True, timeout=3
        )
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                name = parts[1]
                ip_cidr = parts[3]
                if "/" in ip_cidr:
                    ip, prefix = ip_cidr.split("/")
                    if not ip.startswith("127."):
                        network = ipaddress.IPv4Network(
                            f"{ip}/{prefix}", strict=False
                        )
                        interfaces.append(
                            {
                                "name": name,
                                "type": "wifi" if "wl" in name else "ethernet",
                                "ip": ip,
                                "cidr": str(network),
                                "prefix": int(prefix),
                                "netmask": str(network.netmask),
                                "usable_hosts": max(1, network.num_addresses - 2),
                                "gateway": "",
                                "status": "connected",
                            }
                        )
    except Exception:
        pass
    return interfaces


def _get_socket_fallback_interfaces() -> List[Dict[str, Any]]:
    """Fallback local IP discovery using socket connection (finds the route to internet)."""
    # Try multiple targets in case some are unreachable
    targets = [
        ("8.8.8.8", 80),
        ("1.1.1.1", 80),
        ("208.67.222.222", 80),  # OpenDNS
    ]
    for host, port in targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect((host, port))
            local_ip = s.getsockname()[0]
            s.close()

            if local_ip and not local_ip.startswith("127."):
                # Sanity check: if this IP is on a known virtual subnet,
                # try the next target
                if _is_virtual_subnet(local_ip):
                    continue

                network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
                return [
                    {
                        "name": "Primary Adapter (socket fallback)",
                        "type": "ethernet",
                        "ip": local_ip,
                        "cidr": str(network),
                        "prefix": 24,
                        "netmask": "255.255.255.0",
                        "usable_hosts": 254,
                        "gateway": "",
                        "status": "connected",
                    }
                ]
        except Exception:
            continue
    return []


def get_primary_interface() -> Optional[Dict[str, Any]]:
    """
    Retrieve the best active network adapter, preferring real hardware adapters
    with a default gateway over virtual/host-only/tunnel adapters.
    """
    ifaces = get_network_interfaces()
    if not ifaces:
        return None

    # Prefer non-virtual adapter with a default gateway
    for iface in ifaces:
        if iface.get("gateway") and iface.get("cidr") and not iface.get("_virtual"):
            return iface

    # Fallback: any adapter with a gateway (even virtual)
    for iface in ifaces:
        if iface.get("gateway") and iface.get("cidr"):
            return iface

    # Fallback: first non-virtual adapter
    for iface in ifaces:
        if not iface.get("_virtual") and iface.get("cidr"):
            return iface

    # Last resort: first adapter with an IP
    return ifaces[0] if ifaces else None