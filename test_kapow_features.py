"""
test_kapow_features.py - Automated Unit Tests for Kapow Suite:
1. Network Adapter & Subnet Auto-Discovery (backend/net_interfaces.py)
2. 1-Click Protocol Launcher & Wake-on-LAN (backend/launcher.py)
3. Live ICMP Ping & Latency Jitter Telemetry (backend/telemetry.py)
4. Zero-Noise Passive Device Sniffer (backend/passive_sniffer.py)
"""

import unittest
import socket
from backend.net_interfaces import get_network_interfaces, get_primary_interface, _mask_to_cidr
from backend.launcher import launch_protocol, send_wake_on_lan
from backend.telemetry import ping_host, reset_telemetry
from backend.passive_sniffer import PassiveSnifferEngine, lookup_vendor, parse_ssdp_packet, parse_mdns_packet


class TestNetInterfaces(unittest.TestCase):
    """Test network interface enumeration and CIDR subnet calculation."""

    def test_mask_to_cidr(self):
        self.assertEqual(_mask_to_cidr("255.255.255.0"), 24)
        self.assertEqual(_mask_to_cidr("255.255.0.0"), 16)
        self.assertEqual(_mask_to_cidr("255.0.0.0"), 8)
        self.assertEqual(_mask_to_cidr("255.255.255.128"), 25)

    def test_get_network_interfaces(self):
        ifaces = get_network_interfaces()
        self.assertIsInstance(ifaces, list)
        if ifaces:
            for iface in ifaces:
                self.assertIn("name", iface)
                self.assertIn("ip", iface)
                self.assertIn("cidr", iface)
                self.assertIn("usable_hosts", iface)

    def test_get_primary_interface(self):
        primary = get_primary_interface()
        # May be None only if system has zero network connections
        if primary:
            self.assertIn("ip", primary)
            self.assertIn("cidr", primary)


class TestLauncher(unittest.TestCase):
    """Test protocol launcher parameter handling and Wake-on-LAN packet framing."""

    def test_wake_on_lan_magic_packet(self):
        # Test valid standard MAC
        res = send_wake_on_lan("00:11:22:33:44:55", broadcast_ip="127.0.0.1", port=9999)
        self.assertTrue(res["success"])
        self.assertEqual(res["mac"], "00:11:22:33:44:55")

        # Test hyphen format MAC
        res2 = send_wake_on_lan("AA-BB-CC-DD-EE-FF", broadcast_ip="127.0.0.1", port=9999)
        self.assertTrue(res2["success"])
        self.assertEqual(res2["mac"], "AA:BB:CC:DD:EE:FF")

        # Test invalid MAC length
        res_invalid = send_wake_on_lan("12:34:56")
        self.assertFalse(res_invalid["success"])

    def test_launch_protocol_validation(self):
        # Empty IP fails
        res_empty = launch_protocol("http", "")
        self.assertFalse(res_empty["success"])

        # Unsupported protocol fails
        res_unsupp = launch_protocol("nonexistent_protocol", "192.168.1.1")
        self.assertFalse(res_unsupp["success"])


class TestTelemetry(unittest.TestCase):
    """Test live ping telemetry calculations and jitter metrics."""

    def setUp(self):
        reset_telemetry()

    def test_ping_localhost_telemetry(self):
        res1 = ping_host("127.0.0.1", timeout_ms=500)
        self.assertTrue(res1["success"])
        self.assertTrue(res1["is_online"])
        self.assertIsNotNone(res1["current_latency"])
        self.assertEqual(res1["packet_loss_pct"], 0.0)

        # Run second ping to test jitter calculation
        res2 = ping_host("127.0.0.1", timeout_ms=500)
        self.assertTrue(res2["success"])
        self.assertGreaterEqual(res2["samples_count"], 2)
        self.assertIn("jitter", res2)
        self.assertIn("history", res2)

    def test_ping_unreachable_host(self):
        # RFC 5737 TEST-NET non-routable IP
        res = ping_host("192.0.2.1", timeout_ms=300)
        self.assertTrue(res["success"])
        self.assertFalse(res["is_online"])
        self.assertEqual(res["packet_loss_pct"], 100.0)


class TestPassiveSniffer(unittest.TestCase):
    """Test passive sniffer OUI vendor lookup and ARP table polling."""

    def test_vendor_lookup(self):
        self.assertIn("Apple", lookup_vendor("00:1E:C2:11:22:33"))
        self.assertIn("Raspberry Pi", lookup_vendor("B8:27:EB:AA:BB:CC"))
        self.assertIn("Espressif", lookup_vendor("24:6F:28:11:22:33"))
        self.assertIn("VMware", lookup_vendor("00:0C:29:11:22:33"))
        self.assertEqual(lookup_vendor("FF:FF:FF:FF:FF:FF"), "Standard Network Interface")

    def test_passive_sniffer_engine(self):
        engine = PassiveSnifferEngine()
        nodes = engine.poll_arp_cache()
        self.assertIsInstance(nodes, list)
        all_nodes = engine.get_discovered_nodes()
        self.assertIsInstance(all_nodes, list)

    def test_parse_ssdp_notify_packet(self):
        """Parse a real-looking SSDP NOTIFY packet."""
        packet = (
            b"NOTIFY * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b"NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
            b"USN: uuid:abcd-1234::urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
            b"SERVER: Kodi/20.0 UPnP/1.0\r\n"
            b"LOCATION: http://192.168.1.50:8080/description.xml\r\n"
            b"\r\n"
        )
        node = parse_ssdp_packet(packet, "192.168.1.50")
        self.assertIsNotNone(node)
        self.assertEqual(node["ip"], "192.168.1.50")
        self.assertIn("SSDP", node["discovery_method"])
        self.assertIn("Kodi", node["hostname"])
        self.assertIn("MediaRenderer", node["service"])

    def test_parse_ssdp_notify_empty(self):
        """Garbage data should return None."""
        self.assertIsNone(parse_ssdp_packet(b"garbage data here", "1.2.3.4"))
        self.assertIsNone(parse_ssdp_packet(b"", "1.2.3.4"))

    def test_parse_mdns_packet_a_record(self):
        """Parse an mDNS response with a single A record."""
        import struct

        # Build a minimal mDNS response: 1 A record for "tv.local" → 192.168.1.77
        # Header: ID=0, flags=0x8400 (response, authoritative), QD=0, AN=1, NS=0, AR=0
        header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        # Name: "tv.local" as labels: 2 "tv", 5 "local", 0
        name = b"\x02tv\x05local\x00"
        # Type A, class IN (with mDNS flush bit = 0x8001), TTL=120, RDLENGTH=4
        answer = name + struct.pack("!HHIH", 1, 0x8001, 120, 4) + socket.inet_aton("192.168.1.77")
        packet = header + answer

        node = parse_mdns_packet(packet, "192.168.1.77")
        self.assertIsNotNone(node)
        self.assertEqual(node["ip"], "192.168.1.77")
        self.assertIn("tv.local", node["hostname"])

    def test_parse_mdns_packet_empty(self):
        """Too-short or garbage data should return None."""
        self.assertIsNone(parse_mdns_packet(b"", "1.2.3.4"))
        self.assertIsNone(parse_mdns_packet(b"\x00" * 8, "1.2.3.4"))


if __name__ == "__main__":
    unittest.main()
