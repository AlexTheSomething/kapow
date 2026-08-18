"""
test_scan_profiles.py - Unit tests for custom scan profile store.
"""

import json
import os
import shutil
import tempfile
import unittest

import backend.scan_profiles as sp_mod
from backend.scan_profiles import CustomProfileStore


class TestCustomProfileStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = CustomProfileStore(db_path=os.path.join(self.tmpdir, "profiles.db"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_validate_args_rejects_shell_chars(self):
        err = CustomProfileStore.validate_args(["-T4", "-p; rm -rf /"])
        self.assertIsNotNone(err)
        err2 = CustomProfileStore.validate_args(["-T4", "-p", "80"])
        self.assertIsNone(err2)
        err3 = CustomProfileStore.validate_args("not-a-list")
        self.assertIsNotNone(err3)
        err4 = CustomProfileStore.validate_args([123])
        self.assertIsNotNone(err4)

    def test_save_and_list_profile(self):
        res = self.store.save_profile("My Quick Scan", "quick", "Based on quick")
        self.assertTrue(res["success"])
        profiles = self.store.list_profiles()
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["name"], "My Quick Scan")
        self.assertEqual(profiles[0]["args"], ["quick"])

    def test_duplicate_name_rejected(self):
        self.store.save_profile("Dup", "quick")
        res = self.store.save_profile("Dup", "quick")
        self.assertFalse(res["success"])
        self.assertIn("already exists", res["error"])

    def test_empty_name_rejected(self):
        res = self.store.save_profile("   ", "quick")
        self.assertFalse(res["success"])

    def test_missing_based_on_rejected(self):
        res = self.store.save_profile("Valid Name", "  ")
        self.assertFalse(res["success"])
        self.assertIn("reference", res["error"])

    def test_get_and_delete(self):
        res = self.store.save_profile("To Delete", "comprehensive")
        pid = res["id"]
        got = self.store.get_profile(pid)
        self.assertEqual(got["name"], "To Delete")
        self.assertTrue(self.store.delete_profile(pid))
        self.assertIsNone(self.store.get_profile(pid))
        self.assertFalse(self.store.delete_profile(99999))

    def test_persistence_across_instances(self):
        self.store.save_profile("Persist Me", "intense")
        store2 = CustomProfileStore(db_path=self.store.db_path)
        profiles = store2.list_profiles()
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["name"], "Persist Me")


if __name__ == "__main__":
    unittest.main()