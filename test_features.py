"""
test_features.py - Automated Unit Tests for the 5 Power Features:
1. Automated CVE & Vulnerability Lookup (backend/cve_lookup.py)
2. Scan Diff & Network Drift Detector (backend/diff_engine.py)
3. Visual NSE Presets & Execution (backend/scanner.py)
4. Persistent SQLite Asset Inventory & Tagging (backend/asset_db.py)
"""

import os
import tempfile
import unittest
from backend.asset_db import AssetDatabase
from backend.cve_lookup import lookup_cves, enrich_scan_with_cves
from backend.diff_engine import compare_scans
from backend.scanner import ScannerEngine


class TestAssetDatabase(unittest.TestCase):
    """Test SQLite asset database CRUD and scan enrichment."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_assets.db")
        self.db = AssetDatabase(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        if os.path.exists(self.tmp_dir):
            os.rmdir(self.tmp_dir)

    def test_save_and_get_asset_by_ip(self):
        saved = self.db.save_asset(
            ip="192.168.1.50",
            alias="Backup Server",
            owner="DevOps",
            tags=["Production", "Storage"],
            notes="Synology NAS",
            risk_level="MEDIUM",
        )
        self.assertIsNotNone(saved)
        self.assertEqual(saved["alias"], "Backup Server")
        self.assertEqual(saved["owner"], "DevOps")
        self.assertIn("Production", saved["tags"])
        self.assertEqual(saved["risk_level"], "MEDIUM")

        # Retrieve by IP
        retrieved = self.db.get_asset(ip="192.168.1.50")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["alias"], "Backup Server")

    def test_save_and_get_asset_by_mac(self):
        self.db.save_asset(
            ip="192.168.1.100",
            mac="AA:BB:CC:11:22:33",
            alias="CEO Laptop",
            owner="Executive",
            tags=["VIP", "WiFi"],
            risk_level="HIGH",
        )

        retrieved = self.db.get_asset(mac="aa:bb:cc:11:22:33")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["alias"], "CEO Laptop")

    def test_enrich_host_dict(self):
        self.db.save_asset(
            ip="10.0.0.1",
            alias="Core Gateway",
            tags=["Network", "Critical"],
        )

        host_dict = {"ip": "10.0.0.1", "primary_hostname": "router.local"}
        enriched = self.db.enrich_host(host_dict)
        self.assertEqual(enriched["alias"], "Core Gateway")
        self.assertIn("Network", enriched["tags"])


class TestCveLookup(unittest.TestCase):
    """Test CVE vulnerability matcher and CVSS calculation."""

    def test_openssh_vulnerability_lookup(self):
        # OpenSSH 9.3 has known RCE CVE-2023-38408
        cves = lookup_cves(service_name="ssh", product="OpenSSH", version="9.3")
        self.assertTrue(len(cves) > 0)
        cve_ids = [c["cve_id"] for c in cves]
        self.assertIn("CVE-2023-38408", cve_ids)
        self.assertEqual(cves[0]["severity"], "CRITICAL")
        self.assertGreaterEqual(cves[0]["cvss"], 9.0)

    def test_apache_path_traversal_lookup(self):
        # Apache 2.4.49 has CVE-2021-41773
        cves = lookup_cves(service_name="http", product="Apache httpd", version="2.4.49")
        self.assertTrue(len(cves) > 0)
        cve_ids = [c["cve_id"] for c in cves]
        self.assertIn("CVE-2021-41773", cve_ids)

    def test_clean_service_lookup(self):
        # Latest OpenSSH or unknown service returns empty list
        cves = lookup_cves(service_name="ssh", product="OpenSSH", version="9.9p1")
        self.assertEqual(len(cves), 0)

    def test_enrich_scan_payload_with_cves(self):
        sample = ScannerEngine.get_sample_data()
        enriched = enrich_scan_with_cves(sample)
        hosts = enriched["data"]["hosts"]
        self.assertTrue(len(hosts) > 0)
        # Verify host risk rating is populated
        for h in hosts:
            self.assertIn("risk_level", h)
            self.assertIn("cves", h)


class TestDiffEngine(unittest.TestCase):
    """Test Scan comparison and drift detector."""

    def test_compare_scans_detects_new_and_modified_hosts(self):
        scan_a = {
            "data": {
                "hosts": [
                    {
                        "ip": "192.168.1.1",
                        "primary_hostname": "gateway",
                        "primary_os": "Linux",
                        "ports": [
                            {"portid": 80, "protocol": "tcp", "state": "open", "service": {"name": "http", "product": "nginx", "version": "1.18"}},
                            {"portid": 53, "protocol": "udp", "state": "open", "service": {"name": "domain", "product": "dnsmasq", "version": "2.80"}},
                        ]
                    },
                    {
                        "ip": "192.168.1.50",
                        "primary_hostname": "old-printer",
                        "ports": [{"portid": 631, "protocol": "tcp", "state": "open", "service": {"name": "ipp"}}]
                    }
                ]
            }
        }

        scan_b = {
            "data": {
                "hosts": [
                    # Gateway with new SSH port 22 and updated nginx version
                    {
                        "ip": "192.168.1.1",
                        "primary_hostname": "gateway",
                        "primary_os": "Linux",
                        "ports": [
                            {"portid": 80, "protocol": "tcp", "state": "open", "service": {"name": "http", "product": "nginx", "version": "1.24"}},
                            {"portid": 53, "protocol": "udp", "state": "open", "service": {"name": "domain", "product": "dnsmasq", "version": "2.80"}},
                            {"portid": 22, "protocol": "tcp", "state": "open", "service": {"name": "ssh", "product": "OpenSSH", "version": "9.2"}},
                        ]
                    },
                    # New rogue host joined
                    {
                        "ip": "192.168.1.99",
                        "primary_hostname": "rogue-device",
                        "ports": [{"portid": 4444, "protocol": "tcp", "state": "open", "service": {"name": "meterpreter"}}]
                    }
                    # 192.168.1.50 was removed / offline
                ]
            }
        }

        diff = compare_scans(scan_a, scan_b)
        self.assertTrue(diff["success"])
        self.assertTrue(diff["drift_detected"])

        # Check summary
        summary = diff["summary"]
        self.assertEqual(summary["added_hosts_count"], 1)
        self.assertEqual(summary["removed_hosts_count"], 1)
        self.assertEqual(summary["modified_hosts_count"], 1)
        self.assertEqual(summary["total_opened_ports"], 1)

        # Check added host
        self.assertEqual(diff["added_hosts"][0]["ip"], "192.168.1.99")

        # Check removed host
        self.assertEqual(diff["removed_hosts"][0]["ip"], "192.168.1.50")

        # Check modified host details
        mod = diff["modified_hosts"][0]
        self.assertEqual(mod["ip"], "192.168.1.1")
        self.assertEqual(len(mod["opened_ports"]), 1)
        self.assertEqual(mod["opened_ports"][0]["portid"], 22)
        self.assertEqual(len(mod["changed_services"]), 1)
        self.assertEqual(mod["changed_services"][0]["port"], 80)


if __name__ == "__main__":
    unittest.main()
