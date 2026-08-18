"""
test_device_recognition.py - Unit tests for m5 device recognition upgrade.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

from backend import passive_sniffer as ps
from backend.passive_sniffer import (
    enrich_host_with_passive,
    lookup_vendor,
    MAC_OUI_DATABASE,
)


class TestOUIVendorDatabase(unittest.TestCase):
    def test_database_expanded(self):
        """m5 expands the vendor DB well beyond the original ~37 entries."""
        self.assertGreaterEqual(len(MAC_OUI_DATABASE), 150)

    def test_common_vendors_present(self):
        for prefix, vendor in {
            "B8:27:EB": "Raspberry Pi Foundation",
            "00:1A:11": "Google, Inc.",
            "00:0C:29": "VMware, Inc.",
            "00:1B:FC": "ASUS",
            "00:1A:2B": "Cisco Systems",
            "00:26:F2": "NETGEAR",
            "B8:27:EB": "Raspberry Pi Foundation",
            "00:FC:8B": "Amazon Technologies",
            "F4:F5:D8": "Google, Inc.",
            "8C:B1:9B": "Samsung Electronics",
            "00:1B:A9": "Brother Industries",
        }.items():
            self.assertEqual(lookup_vendor(prefix), vendor, f"{prefix} -> {vendor}")

    def test_lookup_unknown_returns_default(self):
        self.assertEqual(lookup_vendor("AA:BB:CC:DD:EE:FF"), "Standard Network Interface")
        self.assertEqual(lookup_vendor(""), "Unknown Vendor")

    def test_lookup_case_insensitive(self):
        self.assertEqual(lookup_vendor("00:0c:29"), "VMware, Inc.")


class TestPassiveEnrichment(unittest.TestCase):
    def _host(self, **kw):
        base = {
            "ip": "192.168.1.50",
            "mac": "B8:27:EB:11:22:33",
            "vendor": "",
            "primary_hostname": "",
            "hostname": "",
            "hostnames": [],
            "ports": [],
        }
        base.update(kw)
        return base

    def test_injects_hostname_when_missing(self):
        node = {"ip": "192.168.1.50", "hostname": "pi.local", "vendor": "", "service": "ssh"}
        h = self._host()
        enrich_host_with_passive(h, node)
        self.assertEqual(h["primary_hostname"], "pi.local")
        self.assertIn("pi.local", [hn["name"] for hn in h["hostnames"]])

    def test_does_not_overwrite_existing_hostname(self):
        node = {"ip": "192.168.1.50", "hostname": "passive.local", "vendor": ""}
        h = self._host(primary_hostname="nmap.named.host")
        enrich_host_with_passive(h, node)
        self.assertEqual(h["primary_hostname"], "nmap.named.host")

    def test_injects_vendor_from_passive(self):
        node = {"ip": "192.168.1.50", "hostname": "", "vendor": "TP-Link Technologies", "service": ""}
        h = self._host()
        enrich_host_with_passive(h, node)
        self.assertEqual(h["vendor"], "TP-Link Technologies")

    def test_injects_vendor_from_oui_when_passive_missing(self):
        node = {"ip": "192.168.1.50", "hostname": "", "vendor": "", "service": ""}
        h = self._host()
        enrich_host_with_passive(h, node)
        # B8:27:EB is Raspberry Pi
        self.assertEqual(h["vendor"], "Raspberry Pi Foundation")

    def test_injects_passive_service_label(self):
        node = {"ip": "192.168.1.50", "hostname": "", "vendor": "", "service": "googlecast"}
        h = self._host()
        enrich_host_with_passive(h, node)
        self.assertEqual(h["passive_service"], "googlecast")

    def test_merges_passive_details(self):
        node = {"ip": "192.168.1.50", "hostname": "", "vendor": "", "service": "", "details": {"model": "X1", "txt": {"ty": "Speaker"}}}
        h = self._host()
        enrich_host_with_passive(h, node)
        self.assertEqual(h["passive_details"]["model"], "X1")

    def test_none_node_is_noop(self):
        h = self._host()
        result = enrich_host_with_passive(h, None)
        self.assertIs(result, h)
        self.assertEqual(h["vendor"], "")


if __name__ == "__main__":
    unittest.main()