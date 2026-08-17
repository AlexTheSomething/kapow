"""
test_scheduler.py - Unit tests for the background scan scheduler.
"""

import os
import shutil
import tempfile
import time
import unittest

import backend.scheduler as scheduler_mod
from backend.scheduler import ScanScheduler, ScheduleConfig


class TestScanScheduler(unittest.TestCase):
    def setUp(self):
        # Redirect config path to temp file to avoid touching real schedule.json
        self.tmpdir = tempfile.mkdtemp()
        self._orig_path = scheduler_mod.CONFIG_PATH
        scheduler_mod.CONFIG_PATH = os.path.join(self.tmpdir, "schedule.json")

    def tearDown(self):
        scheduler_mod.CONFIG_PATH = self._orig_path
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_scheduler(self, callback=None):
        return ScanScheduler(callback or (lambda target, profile: {"success": True, "data": {"hosts": [{"ip": "10.0.0.1"}]}}))

    def test_default_config(self):
        s = self._make_scheduler()
        cfg = s.get_config()
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["interval_minutes"], 30)

    def test_set_config_persists(self):
        s = self._make_scheduler()
        s.set_config(enabled=True, interval_minutes=5, target="10.0.0.0/24", scan_profile="quick")
        cfg = s.get_config()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["interval_minutes"], 5)
        self.assertEqual(cfg["target"], "10.0.0.0/24")

        # New instance loads persisted config from disk
        s2 = self._make_scheduler()
        cfg2 = s2.get_config()
        self.assertTrue(cfg2["enabled"])
        self.assertEqual(cfg2["interval_minutes"], 5)
        self.assertEqual(cfg2["target"], "10.0.0.0/24")

    def test_set_config_rejects_invalid_interval(self):
        s = self._make_scheduler()
        s.set_config(interval_minutes=0)
        self.assertEqual(s.get_config()["interval_minutes"], 30)  # unchanged

    def test_status_shape(self):
        s = self._make_scheduler()
        status = s.get_status()
        for key in ("enabled", "running", "interval_minutes", "target", "last_run_at", "next_run_at", "next_run_in_seconds"):
            self.assertIn(key, status)
        self.assertFalse(status["running"])

    def test_build_summary(self):
        summary = ScanScheduler._build_summary({"success": True, "data": {"hosts": [{"ip": "a"}, {"ip": "b"}, {"ip": "c"}]}})
        self.assertIn("3", summary)
        summary2 = ScanScheduler._build_summary({"success": False})
        self.assertEqual(summary2, "Scan failed")

    def test_start_and_stop(self):
        s = self._make_scheduler()
        s.start()
        self.assertTrue(s.get_status()["running"])
        s.stop()
        self.assertFalse(s.get_status()["running"])

    def test_manual_trigger_callback(self):
        calls = []
        s = self._make_scheduler(lambda target, profile: calls.append((target, profile)) or {"success": True})
        # Simulate one firing of the callback directly
        result = s._callback("192.168.1.0/24", "quick")
        self.assertTrue(result["success"])
        self.assertEqual(calls, [("192.168.1.0/24", "quick")])


if __name__ == "__main__":
    unittest.main()