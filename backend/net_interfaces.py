"""
backend/net_interfaces.py - Network Adapter Enumeration & Auto-Subnet Discovery

Enumerates all active network interfaces (Wi-Fi, Ethernet, VPN, WSL, VirtualBox)
and resolves local IP addresses, netmasks, CIDR subnet ranges, and default gateways.
"""

import ipaddress
import logging
import os
import re
import socket
import subprocess
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _mask_to_cidr(netmask_str: str) -> int:
    """Convert dotted netmask string (e.g. '255.255.255.0') to CIDR prefix integer (e.g. 24)."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask_str}").prefixlen
    except Exception:
        return 24


def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerate active network adapters across Windows, Linux, and macOS.

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
            # Check for interface section headers
            # e.g. "Ethernet adapter Ethernet:" or "Wireless LAN adapter Wi-Fi:"
            match_header = re.match(r"^[A-Za-z0-9\s\-]+adapter\s+(.+?):", line)
            if match_header:
                if current_iface and current_iface.get("ip"):
                    interfaces.append(current_iface)
                name = match_header.group(1).strip()
                current_iface = {
                    "name": name,
                    "type": "wifi" if "wi-fi" in name.lower() or "wireless" in name.lower() else "ethernet",
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

            # IPv4 Address
            match_ip = re.search(r"IPv4 Address[.\s]+:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
            if match_ip:
                current_iface["ip"] = match_ip.group(1).strip()

            # Subnet Mask
            match_mask = re.search(r"Subnet Mask[.\s]+:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
            if match_mask:
                current_iface["netmask"] = match_mask.group(1).strip()

            # Default Gateway
            match_gw = re.search(r"Default Gateway[.\s]+:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
            if match_gw:
                current_iface["gateway"] = match_gw.group(1).strip()

            # Physical Address / MAC
            match_mac = re.search(r"Physical Address[.\s]+:\s*([0-9A-Fa-f\-]{17})", line)
            if match_mac:
                current_iface["mac"] = match_mac.group(1).replace("-", ":").upper()

            # Media state disconnected
            if "Media State" in line and "disconnected" in line.lower():
                current_iface["status"] = "disconnected"

        if current_iface and current_iface.get("ip"):
            interfaces.append(current_iface)

    except Exception as e:
        logger.exception(f"Failed parsing Windows ipconfig: {e}")

    # Compute CIDR for all connected interfaces
    valid_interfaces = []
    for iface in interfaces:
        if iface.get("ip") and not iface["ip"].startswith("127.") and iface.get("status") != "disconnected":
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


def _get_unix_interfaces() -> List[Dict[str, Any]]:
    """Enumerate Unix interfaces using ip route or ifconfig."""
    interfaces: List[Dict[str, Any]] = []
    try:
        proc = subprocess.run(["ip", "-4", "-o", "addr"], stdout=subprocess.PIPE, text=True, timeout=3)
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                name = parts[1]
                ip_cidr = parts[3]
                if "/" in ip_cidr:
                    ip, prefix = ip_cidr.split("/")
                    if not ip.startswith("127."):
                        network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                        interfaces.append({
                            "name": name,
                            "type": "wifi" if "wl" in name else "ethernet",
                            "ip": ip,
                            "cidr": str(network),
                            "prefix": int(prefix),
                            "netmask": str(network.netmask),
                            "usable_hosts": max(1, network.num_addresses - 2),
                            "gateway": "",
                            "status": "connected",
                        })
    except Exception:
        pass
    return interfaces


def _get_socket_fallback_interfaces() -> List[Dict[str, Any]]:
    """Fallback local IP discovery using socket connection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        if local_ip and not local_ip.startswith("127."):
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return [{
                "name": "Primary Adapter",
                "type": "ethernet",
                "ip": local_ip,
                "cidr": str(network),
                "prefix": 24,
                "netmask": "255.255.255.0",
                "usable_hosts": 254,
                "gateway": "",
                "status": "connected",
            }]
    except Exception:
        pass
    return []


def get_primary_interface() -> Optional[Dict[str, Any]]:
    """Retrieve the highest-priority active network adapter."""
    ifaces = get_network_interfaces()
    if not ifaces:
        return None

    # Prefer interface with default gateway or active Wi-Fi/Ethernet
    for iface in ifaces:
        if iface.get("gateway") and iface.get("cidr"):
            return iface

    return ifaces[0]
