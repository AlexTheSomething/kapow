"""
backend/passive_sniffer.py - Local Passive Device Discovery

Discovers LAN devices without sending active probes:
1. ARP cache polling (`arp -a`) — hosts recently communicated with.
2. SSDP receive-only listener — UPnP NOTIFY announcements (multicast join only).
3. mDNS receive-only listener — .local name & service announcements.

All three methods are zero-noise: the machine only listens, never transmits.
No admin/root privileges required — all operations use standard sockets.
"""

import json
import logging
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────
# MAC Vendor OUI Database
# ────────────────────────────────────────────────────────────────

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


# ────────────────────────────────────────────────────────────────
# mDNS packet parser (pure — no side effects)
# ────────────────────────────────────────────────────────────────

_DNS_COMPRESSION_MASK = 0xC0
_DNS_POINTER_MASK = 0x3FFF
_DNS_TYPE_A = 1
_DNS_TYPE_PTR = 12
_DNS_TYPE_SRV = 33
_DNS_TYPE_TXT = 16


def _parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Parse a DNS name (possibly compressed) starting at *offset*.
    Returns (dot-separated-name-string, new-offset).
    """
    labels = []
    jumped = False
    jumped_offset = offset
    max_iter = 128  # safety limit

    while max_iter > 0:
        max_iter -= 1
        if offset >= len(data):
            break

        length = data[offset]
        if length == 0:
            offset += 1
            break  # root label

        if (length & _DNS_COMPRESSION_MASK) == _DNS_COMPRESSION_MASK:
            # compression pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & _DNS_POINTER_MASK) << 8) | data[offset + 1]
            if not jumped:
                jumped_offset = offset + 2
            offset = ptr
            jumped = True
            continue

        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length

    if not jumped:
        jumped_offset = offset

    return ".".join(labels), jumped_offset


def parse_mdns_packet(data: bytes, src_addr: str) -> Optional[Dict[str, Any]]:
    """Parse a single mDNS UDP packet (receive-only). Return a node dict or None."""
    if len(data) < 12:
        return None

    try:
        # DNS header: ID(2) flags(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
        _, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return None

    is_response = bool(flags & 0x8000)  # QR bit
    offset = 12

    hostname = ""
    service = ""
    discovered_ip = ""
    txt_data: Dict[str, str] = {}
    srv_target = ""
    srv_port: Optional[int] = None

    # Skip questions
    for _ in range(qdcount):
        _, offset = _parse_dns_name(data, offset)
        offset += 4  # QTYPE(2) + QCLASS(2)

    # Parse answer + authority + additional
    total_answers = ancount + nscount + arcount
    for _ in range(total_answers):
        if offset >= len(data):
            break
        try:
            name, offset = _parse_dns_name(data, offset)
        except Exception:
            break
        if offset + 10 > len(data):
            break
        try:
            rtype, rclass_raw, _, rdlength = struct.unpack(
                "!HHIH", data[offset : offset + 10]
            )
        except struct.error:
            break
        offset += 10

        rclass = rclass_raw & 0x7FFF  # mask mDNS cache-flush / unicast-response bits

        if offset + rdlength > len(data):
            break

        rdata = data[offset : offset + rdlength]
        offset += rdlength

        if rtype == _DNS_TYPE_A and rdlength == 4:
            try:
                discovered_ip = socket.inet_ntoa(rdata)
            except Exception:
                discovered_ip = ""
            if not hostname and name:
                hostname = name.rstrip(".")

        elif rtype == _DNS_TYPE_PTR:
            try:
                target_name, _ = _parse_dns_name(data, offset - rdlength)
            except Exception:
                target_name = ""
            # target_name is the device instance; name may be service type
            service_name = target_name.rstrip(".") if target_name else ""
            if not service and service_name:
                # Derive a short service label from the domain name
                if "._tcp" in service_name:
                    service = service_name.split("._tcp")[0].split(".")[-1]
                elif "._udp" in service_name:
                    service = service_name.split("._udp")[0].split(".")[-1]
                else:
                    service = service_name

        elif rtype == _DNS_TYPE_SRV and rdlength >= 6:
            try:
                _, _, port, = struct.unpack("!HHH", rdata[:6])
                srv_port = port
                srv_target, _ = _parse_dns_name(data, offset - rdlength + 6)
            except Exception:
                pass

        elif rtype == _DNS_TYPE_TXT and rdlength > 0:
            i = 0
            while i < rdlength:
                slen = rdata[i]
                i += 1
                if i + slen > rdlength:
                    break
                chunk = rdata[i : i + slen]
                i += slen
                if b"=" in chunk:
                    k, v = chunk.split(b"=", 1)
                    txt_data[k.decode("utf-8", errors="replace")] = v.decode(
                        "utf-8", errors="replace"
                    )

    if not discovered_ip and not hostname and not service:
        return None  # no actionable data

    if not discovered_ip:
        discovered_ip = src_addr

    if not hostname and srv_target:
        hostname = srv_target.rstrip(".")

    # Build rich name from available fields
    device_name = hostname or ""
    if not device_name and txt_data.get("name"):
        device_name = txt_data["name"]

    service_label = service or ""
    if not service_label:
        # Try to derive from TXT model/type
        for key in ("md", "model", "ty", "product"):
            if txt_data.get(key):
                service_label = txt_data[key]
                break

    return {
        "ip": discovered_ip,
        "mac": "",
        "vendor": "",
        "hostname": device_name,
        "service": service_label,
        "discovery_method": "mDNS (Passive)",
        "type": "multicast",
        "last_seen": time.time(),
        "details": {
            "txt": txt_data if txt_data else None,
            "srv_port": srv_port,
        },
    }


# ────────────────────────────────────────────────────────────────
# SSDP packet parser (pure)
# ────────────────────────────────────────────────────────────────


def parse_ssdp_packet(data: bytes, src_addr: str) -> Optional[Dict[str, Any]]:
    """Parse a single SSDP NOTIFY (or response) UDP packet. Returns a node or None."""
    try:
        text = data.decode("ascii", errors="replace")
    except Exception:
        return None

    # We only process NOTIFY and M-SEARCH responses (no action on M-SEARCH requests)
    first_line = text.split("\r\n")[0] if "\r\n" in text else text.split("\n")[0]
    if not first_line.startswith("NOTIFY * HTTP/1.1") and not first_line.startswith(
        "HTTP/1.1 200 OK"
    ):
        return None

    # Parse headers case-insensitively
    headers: Dict[str, str] = {}
    for line in text.split("\r\n")[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().upper()] = value.strip()

    nt = headers.get("NT", headers.get("ST", ""))
    usn = headers.get("USN", "")
    server = headers.get("SERVER", "")
    location = headers.get("LOCATION", "")

    # Derive device name and service type
    device_name = server or ""
    # NT gives UPnP device/type description; use suffix for service label
    service_label = ""
    if nt:
        parts = nt.replace("urn:", "").replace("schemas-upnp-org:", "").split(":")
        service_label = ":".join(parts)
        # Shorten: "device" type → just the prefix
        if "device" in service_label and len(service_label) > 30:
            service_label = parts[0] if parts else nt

    # Try to get a friendlier name from USN uuid or SERVER product
    if server:
        # e.g. "Kodi/20.0 UPnP/1.0" → just "Kodi"
        product = server.split("/")[0].strip().split(" ")[0]
        if product.lower() in ("linux", "upnp", "windows", "multiscreencast"):
            product = server.split(" ")[0]
        device_name = product if product else device_name

    return {
        "ip": src_addr,
        "mac": "",
        "vendor": "",
        "hostname": device_name,
        "service": service_label,
        "discovery_method": "SSDP (Passive)",
        "type": "multicast",
        "last_seen": time.time(),
        "details": {
            "nt": nt,
            "usn": usn,
            "server": server,
            "location": location,
        },
    }


# ────────────────────────────────────────────────────────────────
# Listener base class
# ────────────────────────────────────────────────────────────────


class _MulticastListenerBase(threading.Thread):
    """Base for a receive-only UDP multicast listener daemon thread."""

    def __init__(
        self,
        name: str,
        group: str,
        port: int,
        parser_fn: Callable[[bytes, str], Optional[Dict[str, Any]]],
        on_node: Callable[[Dict[str, Any]], None],
    ):
        super().__init__(daemon=True, name=name)
        self.group = group
        self.port = port
        self._parser = parser_fn
        self._on_node = on_node
        self._running = False
        self._sock: Optional[socket.socket] = None
        self.status = "stopped"
        self.error_msg: Optional[str] = None

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def run(self):
        self._running = True
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # On Windows, bind must be explicit; on Linux SO_REUSEPORT helps
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # type: ignore[attr-defined]
            except (AttributeError, OSError):
                pass

            self._sock.bind(("0.0.0.0", self.port))

            # Join multicast group on INADDR_ANY (default interface)
            mreq = socket.inet_aton(self.group) + socket.inet_aton("0.0.0.0")
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self._sock.settimeout(1.0)
            self.status = "listening"
            self.error_msg = None
            logger.info("%s listener started on port %d", self.name, self.port)
        except OSError as e:
            self.status = "unavailable"
            self.error_msg = f"Bind failed (port {self.port} in use?): {e}"
            logger.warning("%s: %s", self.name, self.error_msg)
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
            self._sock = None
            return
        except Exception as e:
            self.status = "error"
            self.error_msg = str(e)
            logger.exception("%s setup error:", self.name)
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
            self._sock = None
            return

        buf_size = 65536
        while self._running:
            try:
                data, addr = self._sock.recvfrom(buf_size)
                src_ip = addr[0]
                try:
                    node = self._parser(data, src_ip)
                    if node:
                        self._on_node(node)
                except Exception:
                    logger.debug("%s parser error for %s", self.name, src_ip, exc_info=True)
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    self.status = "error"
                    self.error_msg = "Socket error; listener stopped."
                    logger.exception("%s socket error:", self.name)
                break

        if self._sock:
            self._sock.close()
            self._sock = None
        self.status = "stopped"


# ────────────────────────────────────────────────────────────────
# Passive Sniffer Engine
# ────────────────────────────────────────────────────────────────


class PassiveSnifferEngine:
    """
    Manages zero-noise passive discovery of local network nodes.

    Sources (all receive-only, no probes sent):
    1. ARP cache polling
    2. SSDP multicast NOTIFY listener
    3. mDNS multicast listener
    """

    def __init__(self):
        self._discovered_nodes: Dict[str, Dict[str, Any]] = {}
        self._listener_lock = threading.Lock()
        self._ssdp: Optional[_MulticastListenerBase] = None
        self._mdns: Optional[_MulticastListenerBase] = None

    def _on_node(self, node: Dict[str, Any]):
        """Merge newly discovered multicast node into the table."""
        key = node["ip"]
        with self._listener_lock:
            existing = self._discovered_nodes.get(key)
            if existing:
                # Only update fields where new data is richer
                if node.get("hostname") and not existing.get("hostname"):
                    existing["hostname"] = node["hostname"]
                if node.get("service") and not existing.get("service"):
                    existing["service"] = node["service"]
                if node.get("mac") and not existing.get("mac"):
                    existing["mac"] = node["mac"]
                if node.get("vendor") and not existing.get("vendor"):
                    existing["vendor"] = node["vendor"]
                existing["last_seen"] = max(
                    existing.get("last_seen", 0), node["last_seen"]
                )
                # Merge details
                if node.get("details"):
                    d = existing.setdefault("details", {})
                    d.update(node["details"])
                # Blend discovery methods
                existing_methods = existing.get("discovery_method", "").split(" + ")
                new_method = node.get("discovery_method", "")
                if new_method and new_method not in existing_methods:
                    existing["discovery_method"] = " + ".join(
                        existing_methods + [new_method]
                    )
            else:
                self._discovered_nodes[key] = node

    def start_listeners(self):
        """Start SSDP and mDNS receive-only listeners (non-blocking)."""
        if self._ssdp is None:
            self._ssdp = _MulticastListenerBase(
                name="SSDP-listener",
                group="239.255.255.250",
                port=1900,
                parser_fn=parse_ssdp_packet,
                on_node=self._on_node,
            )
            self._ssdp.start()

        if self._mdns is None:
            self._mdns = _MulticastListenerBase(
                name="mDNS-listener",
                group="224.0.0.251",
                port=5353,
                parser_fn=parse_mdns_packet,
                on_node=self._on_node,
            )
            self._mdns.start()

    def stop_listeners(self):
        """Stop multicast listeners."""
        for listener in (self._ssdp, self._mdns):
            if listener:
                listener.stop()
        # Let threads join briefly
        for listener in (self._ssdp, self._mdns):
            if listener and listener.is_alive():
                listener.join(timeout=2.0)

    def get_listener_status(self) -> Dict[str, Any]:
        """Return status of each listener."""
        return {
            "ssdp": {
                "status": self._ssdp.status if self._ssdp else "not_started",
                "error": self._ssdp.error_msg if self._ssdp else None,
            },
            "mdns": {
                "status": self._mdns.status if self._mdns else "not_started",
                "error": self._mdns.error_msg if self._mdns else None,
            },
        }

    def poll_arp_cache(self) -> List[Dict[str, Any]]:
        """
        Inspect local OS ARP cache table without transmitting probe packets.
        """
        nodes: List[Dict[str, Any]] = []
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
                match = re.search(
                    r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9A-Fa-f\-]{17}|[0-9A-Fa-f:]{17})\s+([a-zA-Z]+)",
                    line,
                )
                if match:
                    ip = match.group(1).strip()
                    mac = match.group(2).replace("-", ":").upper()
                    entry_type = match.group(3).strip().lower()

                    if (
                        ip.startswith("224.")
                        or ip.startswith("239.")
                        or ip.endswith(".255")
                        or ip == "127.0.0.1"
                    ):
                        continue
                    if mac == "FF:FF:FF:FF:FF:FF":
                        continue

                    vendor = lookup_vendor(mac)
                    node = {
                        "ip": ip,
                        "mac": mac,
                        "vendor": vendor,
                        "hostname": "",
                        "service": "",
                        "discovery_method": "ARP Cache (Passive)",
                        "type": entry_type,
                        "last_seen": time.time(),
                        "details": {},
                    }
                    self._discovered_nodes[ip] = node
                    nodes.append(node)

        except Exception as e:
            logger.exception(f"Failed polling ARP cache: {e}")

        return list(self._discovered_nodes.values())

    def get_discovered_nodes(self) -> List[Dict[str, Any]]:
        """Return all discovered passive network devices (ARP + multicast)."""
        # Refresh with latest ARP table cache
        self.poll_arp_cache()
        with self._listener_lock:
            return sorted(
                list(self._discovered_nodes.values()), key=lambda x: x.get("ip", "")
            )

    def clear(self):
        """Clear discovered nodes memory."""
        with self._listener_lock:
            self._discovered_nodes.clear()