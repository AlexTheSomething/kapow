"""
test_host_timeline.py - Unit tests for per-host timeline reconstruction.
"""

import json
import os
import shutil
import tempfile
import time
import unittest

from backend.host_timeline import build_host_timeline
from backend.scan_store import ScanStore


def _host(ip, ports=None):
    return {
        "ip": ip,
        "status": {"state": "up"},
        "ports": ports or [],
    }


def _port(portid, state="open", service="http", product="", version=""):
    return {
        "portid": portid,
        "state": state,
        "service": {"name": service, "product": product, "version": version},
    }


class FakeScanStore:
    """In-memory ScanStore substitute for timeline tests."""

    def __init__(self, scans):
        # scans: list of (ts, payload) in chronological order
        self._scans = scans
        self._id_map = {i + 1: i for i in range(len(scans))}  # id → index

    def list_scans(self, limit=100):
        result = []
        for id_val in sorted(self._id_map.keys(), reverse=True):  # newest first
            ts, _ = self._scans[self._id_map[id_val]]
            result.append({"id": id_val, "created_at": ts})
        return result[:limit]

    def get_scan(self, scan_id):
        idx = self._id_map[int(scan_id)]
        _, payload = self._scans[idx]
        return payload


class TestHostTimeline(unittest.TestCase):
    def _make_store(self, scans):
        return FakeScanStore(scans)

    def test_first_seen_and_scan_count(self):
        now = time.time()
        store = self._make_store([
            (now, {"success": True, "data": {"hosts": [_host("10.0.0.1", ports=[_port(22, service="ssh")])]}}),
            (now + 100, {"success": True, "data": {"hosts": [_host("10.0.0.1", ports=[_port(22, service="ssh")])]}}),
        ])
        tl = build_host_timeline(store, "10.0.0.1")
        self.assertTrue(tl["success"])
        self.assertEqual(tl["scan_count"], 2)
        self.assertIsNotNone(tl["first_seen_at"])
        self.assertEqual(tl["last_seen_at"], now + 100)
        self.assertEqual(tl["events"][0]["type"], "first_seen")

    def test_ports_opened_detected(self):
        now = time.time()
        store = self._make_store([
            (now, {"success": True, "data": {"hosts": [_host("10.0.0.1", ports=[_port(22, service="ssh")])]}}),
            (now + 100, {"success": True, "data": {"hosts": [_host("10.0.0.1", ports=[_port(22, service="ssh"), _port(445, service="microsoft-ds")])]}}),
        ])
        tl = build_host_timeline(store, "10.0.0.1")
        types = [e["type"] for e in tl["events"]]
        self.assertIn("ports_opened", types)
        opened = [e for e in tl["events"] if e["type"] == "ports_opened"][0]
        self.assertIn("445", opened["detail"])

    def test_ports_closed_detected(self):
        now = time.time()
        store = self._make_store([
            (now, {"success": True, "data": {"hosts": [_host("10.0.0.1", ports=[_port(22, service="ssh"), _port(80, service="http")])]}}),
            (now + 100, {"success": True, "data": {"hosts": [_host("10.0.0.1", ports=[_port(22, service="ssh")])]}}),
        ])
        tl = build_host_timeline(store, "10.0.0.1")
        types = [e["type"] for e in tl["events"]]
        self.assertIn("ports_closed", types)

    def test_service_version_change(self):
        now = time.time()
        store = self._make_store([
            (now, {"success": True, "data": {"hosts": [_host("10.0.0.1", ports=[_port(22, service="ssh", product="OpenSSH", version="8.9")])]}}),
            (now + 100, {"success": True, "data": {"hosts": [_host("10.0.0.1", ports=[_port(22, service="ssh", product="OpenSSH", version="9.8")])]}}),
        ])
        tl = build_host_timeline(store, "10.0.0.1")
        types = [e["type"] for e in tl["events"]]
        self.assertIn("service_changed", types)

    def test_offline_gap_detected(self):
        now = time.time()
        store = self._make_store([
            (now, {"success": True, "data": {"hosts": [_host("10.0.0.1", ports=[_port(22)])]}}),
            (now + 100, {"success": True, "data": {"hosts": []}}),
            (now + 200, {"success": True, "data": {"hosts": [_host("10.0.0.1", ports=[_port(22)])]}}),
        ])
        tl = build_host_timeline(store, "10.0.0.1")
        types = [e["type"] for e in tl["events"]]
        self.assertIn("offline", types)
        # scan_count should count only scans where host was present
        self.assertEqual(tl["scan_count"], 2)

    def test_unknown_host_empty_result(self):
        now = time.time()
        store = self._make_store([
            (now, {"success": True, "data": {"hosts": [_host("10.0.0.1")]}}),
        ])
        tl = build_host_timeline(store, "192.168.99.99")
        self.assertTrue(tl["success"])
        self.assertEqual(tl["scan_count"], 0)
        self.assertIsNone(tl["first_seen_at"])


if __name__ == "__main__":
    unittest.main()