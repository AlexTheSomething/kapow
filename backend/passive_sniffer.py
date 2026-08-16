"""
backend/passive_sniffer.py - Local ARP Cache Device Discovery

Discovers recently contacted LAN devices by reading the OS ARP cache
(`arp -a`) — no active TCP/SYN probes are sent. MAC vendor OUI labels
are resolved from a small built-in dictionary.

Note: This is not a packet sniffer. SSDP/mDNS listeners are not implemented yet.
"""

import logging
import re
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Common Hardware MAC Vendor OUI Dictionary
MAC_OUI_DATABASE = {
    "00:0C:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "08:00:27": "Oracle VirtualBox",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "00:1A:11": "Google, Inc.",
    "F4:F5:D8": "Google, Inc.",
    "3C:5A:B4": "Google, Inc.",
    "00:17:88": "Philips Lighting (Hue)",
    "00:1E:C2": "Apple, Inc.",
    "AC:DE:48": "Apple, Inc.",
    "F0:18:98": "Apple, Inc.",
    "3C:06:30": "Apple, Inc.",
    "40:6C:8F": "Apple, Inc.",
    "00:15:5D": "Microsoft Corporation (Hyper-V)",
    "DC:41:A9": "Microsoft Corporation",
    "00:04:4B": "NVIDIA Corporation",
    "48:B0:2D": "NVIDIA Corporation",
    "00:1A:79": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "AC:8B:A9": "TP-Link Technologies",
    "50:C7:BF": "TP-Link Technologies",
    "00:14:D1": "TP-Link Technologies",
    "24:6F:28": "Espressif Inc. (ESP32/ESP8266 IoT)",
    "30:AE:A4": "Espressif Inc. (ESP32/ESP8266 IoT)",
    "84:CC:A8": "Espressif Inc. (ESP32/ESP8266 IoT)",
    "00:1A:2B": "Cisco Systems",
    "00:26:0B": "Cisco Systems",
    "00:0E:08": "Intel Corporation",
    "00:1B:21": "Intel Corporation",
    "34:E6:D7": "Dell Inc.",
    "F8:DB:88": "Dell Inc.",
    "00:25:B3": "Hewlett Packard",
    "9C:8E:99": "Hewlett Packard",
    "00:1A:80": "Samsung Electronics",
    "50:02:91": "Sony Interactive (PlayStation)",
}


def lookup_vendor(mac: str) -> str:
    """Resolve 3-byte MAC prefix to manufacturer name."""
    clean_mac = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(clean_mac) >= 6:
        prefix = f"{clean_mac[0:2]}:{clean_mac[2:4]}:{clean_mac[4:6]}"
        return MAC_OUI_DATABASE.get(prefix, "Standard Network Interface")
    return "Unknown Vendor"


class PassiveSnifferEngine:
    """
    Manages zero-noise passive discovery of local network nodes.
    """

    def __init__(self):
        self._discovered_nodes: Dict[str, Dict[str, Any]] = {}
        self._is_listening = False
        self._listener_thread: Optional[threading.Thread] = None

    def poll_arp_cache(self) -> List[Dict[str, Any]]:
        """
        Inspect local OS ARP cache table without transmitting probe packets.
        """
        nodes = []
        try:
            startupinfo = None
            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0

            proc = subprocess.run(
                ["arp", "-a"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="ignore",
                startupinfo=startupinfo,
                timeout=3,
            )

            for line in proc.stdout.splitlines():
                # Parse lines like: "  192.168.1.1           e0-28-6d-11-22-33     dynamic"
                match = re.search(
                    r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9A-Fa-f\-]{17}|[0-9A-Fa-f:]{17})\s+([a-zA-Z]+)",
                    line,
                )
                if match:
                    ip = match.group(1).strip()
                    mac = match.group(2).replace("-", ":").upper()
                    entry_type = match.group(3).strip().lower()

                    # Filter broadcast, multicast, and loopback
                    if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255") or ip == "127.0.0.1":
                        continue
                    if mac == "FF:FF:FF:FF:FF:FF":
                        continue

                    vendor = lookup_vendor(mac)
                    node = {
                        "ip": ip,
                        "mac": mac,
                        "vendor": vendor,
                        "discovery_method": "ARP Cache (Passive)",
                        "type": entry_type,
                        "last_seen": time.time(),
                    }
                    self._discovered_nodes[ip] = node
                    nodes.append(node)

        except Exception as e:
            logger.exception(f"Failed polling ARP cache: {e}")

        return list(self._discovered_nodes.values())

    def get_discovered_nodes(self) -> List[Dict[str, Any]]:
        """Return all discovered passive network devices."""
        # Refresh with latest ARP table cache
        self.poll_arp_cache()
        return sorted(list(self._discovered_nodes.values()), key=lambda x: x.get("ip", ""))

    def clear(self):
        """Clear discovered nodes memory."""
        self._discovered_nodes.clear()
