"""
test_tag_rules.py - Unit tests for the auto-suggested tag engine.
"""

import unittest

from backend.tag_rules import suggest_tags_for_scan


def _host(ip, ports=None, status="up", mac="", hostname=""):
    """Helper to build a normalized host dict."""
    return {
        "ip": ip,
        "mac": mac,
        "status": status,
        "primary_hostname": hostname,
        "ports": ports or [],
    }


def _port(portid, service_name="", product="", version="", state="open", scripts=None):
    return {
        "portid": portid,
        "protocol": "tcp",
        "state": state,
        "service": {
            "name": service_name,
            "product": product,
            "version": version,
        },
        "scripts": scripts or [],
    }


class TestTagRules(unittest.TestCase):
    def _suggest(self, hosts, history=None):
        payload = {"success": True, "data": {"hosts": hosts}}
        return suggest_tags_for_scan(payload, history_hosts=history)

    def test_empty_scan(self):
        res = self._suggest([])
        self.assertTrue(res["success"])
        self.assertEqual(res["count"], 0)

    def test_telnet_legacy_protocol(self):
        hosts = [_host("10.0.0.1", ports=[_port(23, "telnet")])]
        res = self._suggest(hosts)
        tags = [s["tag"] for s in res["suggestions"]]
        self.assertIn("legacy protocol", tags)

    def test_smb_exposed_share(self):
        hosts = [_host("10.0.0.1", ports=[_port(445, "microsoft-ds", "Windows SMB")])]
        res = self._suggest(hosts)
        tags = [s["tag"] for s in res["suggestions"]]
        self.assertIn("exposed file share", tags)

    def test_old_openssh_needs_update(self):
        hosts = [_host("10.0.0.1", ports=[_port(22, "ssh", "OpenSSH", "8.9")])]
        res = self._suggest(hosts)
        tags = [s["tag"] for s in res["suggestions"]]
        self.assertIn("needs update", tags)

    def test_recent_openssh_no_flag(self):
        hosts = [_host("10.0.0.1", ports=[_port(22, "ssh", "OpenSSH", "9.9")])]
        res = self._suggest(hosts)
        tags = [s["tag"] for s in res["suggestions"]]
        self.assertNotIn("needs update", tags)

    def test_web_admin_title(self):
        hosts = [
            _host(
                "10.0.0.1",
                ports=[
                    _port(
                        80,
                        "http",
                        "uhttpd",
                        scripts=[{"id": "http-title", "output": "OpenWrt - Router Admin"}],
                    )
                ],
            )
        ]
        res = self._suggest(hosts)
        tags = [s["tag"] for s in res["suggestions"]]
        self.assertIn("web console", tags)

    def test_rdp_remote_desktop(self):
        hosts = [_host("10.0.0.1", ports=[_port(3389, "ms-wbt-server")])]
        res = self._suggest(hosts)
        tags = [s["tag"] for s in res["suggestions"]]
        self.assertIn("remote desktop", tags)

    def test_new_device_detection(self):
        history = [_host("10.0.0.1", mac="AA:BB:CC:DD:EE:FF")]
        hosts = [_host("10.0.0.2", mac="11:22:33:44:55:66")]
        res = self._suggest(hosts, history=history)
        tags = [s["tag"] for s in res["suggestions"]]
        self.assertIn("new device", tags)

    def test_known_device_not_flagged(self):
        history = [_host("10.0.0.1", mac="AA:BB:CC:DD:EE:FF")]
        hosts = [_host("10.0.0.1", mac="AA:BB:CC:DD:EE:FF")]
        res = self._suggest(hosts, history=history)
        tags = [s["tag"] for s in res["suggestions"]]
        self.assertNotIn("new device", tags)

    def test_quiet_host(self):
        hosts = [_host("10.0.0.1", status="up", ports=[])]
        res = self._suggest(hosts)
        tags = [s["tag"] for s in res["suggestions"]]
        self.assertIn("quiet host", tags)


if __name__ == "__main__":
    unittest.main()