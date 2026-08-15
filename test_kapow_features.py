"""
test_kapow_features.py - Automated Unit Tests for Kapow Suite:
1. Network Adapter & Subnet Auto-Discovery (backend/net_interfaces.py)
2. 1-Click Protocol Launcher & Wake-on-LAN (backend/launcher.py)
3. Live ICMP Ping & Latency Jitter Telemetry (backend/telemetry.py)
4. Zero-Noise Passive Device Sniffer (backend/passive_sniffer.py)
"""

import unittest
from backend.net_interfaces import get_network_interfaces, get_primary_interface, _mask_to_cidr
from backend.launcher import launch_protocol, send_wake_on_lan
from backend.telemetry import ping_host, reset_telemetry
from backend.passive_sniffer import PassiveSnifferEngine, lookup_vendor


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


if __name__ == "__main__":
    unittest.main()
