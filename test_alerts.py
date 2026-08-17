"""
test_alerts.py - Unit tests for change-detection alert engine.
"""

import os
import shutil
import tempfile
import unittest

import backend.alerts as alerts_mod
from backend.alerts import AlertStore, check_for_changes, generate_alerts


def _host(ip, ports=None, hostname="", tags=None):
    return {
        "ip": ip,
        "primary_hostname": hostname,
        "tags": tags or [],
        "ports": ports or [],
    }


def _port(portid, state="open", service="http"):
    return {"portid": portid, "state": state, "service": {"name": service}}


def _payload(hosts):
    return {"success": True, "data": {"hosts": hosts}}


class TestAlertEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_db = alerts_mod.DB_FILE
        alerts_mod.DB_FILE = os.path.join(self.tmpdir, "test_alerts.db")
        self.store = AlertStore(db_path=alerts_mod.DB_FILE)

    def tearDown(self):
        alerts_mod.DB_FILE = self._orig_db
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_first_scan_no_alerts(self):
        """First scan (no baseline) generates no alerts."""
        res = check_for_changes(
            _payload([_host("10.0.0.1", ports=[_port(22)])]),
            None,
            self.store,
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["change_count"], 0)

    def test_new_device_alert(self):
        prev = _payload([_host("10.0.0.1", ports=[_port(22)])])
        new = _payload([
            _host("10.0.0.1", ports=[_port(22)]),
            _host("10.0.0.2", ports=[_port(80)]),
        ])
        res = check_for_changes(new, prev, self.store)
        kinds = [a["kind"] for a in res["alerts"]]
        self.assertIn("new_device", kinds)

    def test_device_offline_alert(self):
        prev = _payload([
            _host("10.0.0.1", ports=[_port(22)]),
            _host("10.0.0.5", ports=[_port(80)]),
        ])
        new = _payload([_host("10.0.0.1", ports=[_port(22)])])
        res = check_for_changes(new, prev, self.store)
        kinds = [a["kind"] for a in res["alerts"]]
        self.assertIn("device_offline", kinds)

    def test_tagged_host_port_opened_critical(self):
        prev = _payload([_host("10.0.0.1", ports=[_port(22)], tags=["mine"])])
        new = _payload([_host("10.0.0.1", ports=[_port(22), _port(445)], tags=["mine"])])
        res = check_for_changes(new, prev, self.store)
        opened = [a for a in res["alerts"] if a["kind"] == "port_opened"]
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0]["severity"], "critical")

    def test_untagged_port_opened_warning(self):
        prev = _payload([_host("10.0.0.1", ports=[_port(22)])])
        new = _payload([_host("10.0.0.1", ports=[_port(22), _port(445)])])
        res = check_for_changes(new, prev, self.store)
        opened = [a for a in res["alerts"] if a["kind"] == "port_opened"]
        self.assertEqual(opened[0]["severity"], "warning")

    def test_no_changes_no_alerts(self):
        prev = _payload([_host("10.0.0.1", ports=[_port(22)], tags=["mine"])])
        new = _payload([_host("10.0.0.1", ports=[_port(22)], tags=["mine"])])
        res = check_for_changes(new, prev, self.store)
        self.assertEqual(res["change_count"], 0)

    def test_store_persistence_and_unread(self):
        sid = self.store.add_alert("new_device", "warning", "Test", host_ip="10.0.0.9")
        self.assertIsNotNone(sid)
        self.assertEqual(self.store.unread_count(), 1)
        alerts = self.store.list_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["host_ip"], "10.0.0.9")
        self.store.mark_all_read()
        self.assertEqual(self.store.unread_count(), 0)


if __name__ == "__main__":
    unittest.main()