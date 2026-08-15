"""
test_backend.py - Unit and Integration Tests for Backend Engine
"""

import asyncio
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from backend.elevation import build_elevated_command, get_elevation_method, is_elevated
from backend.scanner import ScannerEngine, SAMPLE_NMAP_XML
from backend.app import BackendAPI
from parsers import NmapParser, to_ag_grid, to_cytoscape


class TestElevation(unittest.TestCase):
    """Test OS privilege elevation command builders."""

    def test_is_elevated_returns_bool(self):
        result = is_elevated()
        self.assertIsInstance(result, bool)

    def test_build_elevated_empty_command(self):
        with self.assertRaises(ValueError):
            build_elevated_command([])

    @patch('backend.elevation.is_elevated', return_value=False)
    @patch('sys.platform', 'linux')
    @patch('shutil.which', return_value='/usr/bin/pkexec')
    def test_build_elevated_linux_pkexec(self, mock_which, mock_elevated):
        cmd = ['nmap', '-sS', '192.168.1.1']
        elevated = build_elevated_command(cmd)
        self.assertEqual(elevated[0], 'pkexec')
        self.assertEqual(elevated[1:], cmd)

    @patch('backend.elevation.is_elevated', return_value=False)
    @patch('sys.platform', 'darwin')
    @patch('shutil.which', return_value='/usr/bin/osascript')
    def test_build_elevated_macos_osascript(self, mock_which, mock_elevated):
        cmd = ['nmap', '-sS', '192.168.1.1']
        elevated = build_elevated_command(cmd)
        self.assertEqual(elevated[0], 'osascript')
        self.assertEqual(elevated[1], '-e')
        self.assertIn('with administrator privileges', elevated[2])
        self.assertIn('192.168.1.1', elevated[2])

    @patch('backend.elevation.is_elevated', return_value=False)
    @patch('sys.platform', 'win32')
    def test_build_elevated_windows(self, mock_elevated):
        cmd = ['nmap.exe', '-sS', '192.168.1.1']
        elevated = build_elevated_command(cmd)
        self.assertEqual(elevated[0], 'powershell.exe')
        self.assertIn('Start-Process', " ".join(elevated))
        self.assertIn('-Verb RunAs', " ".join(elevated))


class TestScannerEngine(unittest.TestCase):
    """Test async ScannerEngine orchestration and command construction."""

    def setUp(self):
        self.engine = ScannerEngine()

    def test_check_dependencies(self):
        deps = self.engine.check_dependencies()
        self.assertIn('nmap', deps)
        self.assertIn('rustscan', deps)
        self.assertIn('installed', deps['nmap'])
        self.assertIn('installed', deps['rustscan'])
        self.assertIn('is_elevated', deps)

    def test_build_nmap_command_comprehensive(self):
        cmd = self.engine.build_nmap_command(
            target="192.168.1.0/24",
            ports="80,443",
            scan_type="comprehensive",
            requires_root=False,
        )
        self.assertIn("-sV", cmd)
        self.assertIn("-O", cmd)
        self.assertIn("--traceroute", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("80,443", cmd)
        self.assertIn("-oX", cmd)
        self.assertIn("-", cmd)
        self.assertIn("192.168.1.0/24", cmd)

    def test_build_nmap_command_profiles(self):
        # Quick
        cmd_q = self.engine.build_nmap_command(target="10.0.0.1", scan_type="quick")
        self.assertIn("-F", cmd_q)

        # Ping Sweep
        cmd_p = self.engine.build_nmap_command(target="10.0.0.0/24", scan_type="ping_sweep")
        self.assertIn("-sn", cmd_p)

        # Intense
        cmd_i = self.engine.build_nmap_command(target="10.0.0.1", scan_type="intense")
        self.assertIn("-T4", cmd_i)
        self.assertIn("-A", cmd_i)

    def test_get_sample_data(self):
        sample = ScannerEngine.get_sample_data()
        self.assertTrue(sample["success"])
        self.assertTrue(sample["is_sample"])
        self.assertGreater(len(sample["data"]["hosts"]), 0)
        self.assertGreater(len(sample["ag_grid"]), 0)
        self.assertGreater(len(sample["cytoscape"]["nodes"]), 0)
        self.assertGreater(len(sample["cytoscape"]["edges"]), 0)

        # Verify host data integrity
        host_ips = [h["ip"] for h in sample["data"]["hosts"]]
        self.assertIn("192.168.1.1", host_ips)
        self.assertIn("192.168.1.100", host_ips)
        self.assertIn("192.168.1.150", host_ips)

    def test_run_pipeline_missing_nmap_handled_gracefully(self):
        with patch.object(self.engine, 'check_dependencies', return_value={
            "nmap": {"installed": False, "path": ""},
            "rustscan": {"installed": False, "path": ""},
            "is_elevated": False,
            "platform": sys.platform
        }):
            res = asyncio.run(self.engine.run_pipeline("192.168.1.1"))
            self.assertFalse(res["success"])
            self.assertEqual(res.get("missing_dependency"), "nmap")
            self.assertIn("Nmap binary was not found", res.get("error", ""))

    def test_cancel_scan_when_idle(self):
        res = self.engine.cancel_scan()
        self.assertTrue(res["success"])
        self.assertFalse(self.engine.is_running)


class TestBackendAPI(unittest.TestCase):
    """Test BackendAPI JS bridge methods."""

    def setUp(self):
        self.api = BackendAPI()

    def test_check_dependencies_api(self):
        deps = self.api.check_dependencies()
        self.assertIn("nmap", deps)
        self.assertIn("rustscan", deps)

    def test_load_sample_scan_api(self):
        res = self.api.load_sample_scan()
        self.assertTrue(res["success"])
        self.assertEqual(len(res["data"]["hosts"]), 3)

    def test_export_results_json(self):
        sample = self.api.load_sample_scan()
        exp = self.api.export_results(sample, file_format="json")
        self.assertTrue(exp["success"])
        self.assertEqual(exp["format"], "json")
        parsed = json.loads(exp["content"])
        self.assertEqual(parsed["target"], sample["target"])

    def test_export_results_xml(self):
        sample = self.api.load_sample_scan()
        exp = self.api.export_results(sample, file_format="xml")
        self.assertTrue(exp["success"])
        self.assertEqual(exp["format"], "xml")
        self.assertIn("<nmaprun", exp["content"])

    def test_export_results_csv(self):
        sample = self.api.load_sample_scan()
        exp = self.api.export_results(sample, file_format="csv")
        self.assertTrue(exp["success"])
        self.assertEqual(exp["format"], "csv")
        self.assertIn("ip", exp["content"])
        self.assertIn("192.168.1.1", exp["content"])


if __name__ == "__main__":
    unittest.main()
