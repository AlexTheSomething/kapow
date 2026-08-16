"""
test_parsers.py - Unit tests for Nmap XML Parser (parsers.py)
"""

import json
import unittest
from parsers import (
    NmapParser,
    parse_nmap_xml,
    to_ag_grid,
    to_cytoscape,
    safe_parse_xml,
    is_credibly_live,
    filter_proxy_arp_ghosts,
    filter_hosts_for_inventory,
)

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O --traceroute -oX - 192.168.1.0/24" start="1690000000" startstr="Mon Jul 22 00:00:00 2024" version="7.94" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1024"/>
  <verbose level="1"/>
  <debugging level="0"/>
  <host starttime="1690000000" endtime="1690000005">
    <status state="up" reason="arp-response" reason_ttl="0"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="54:E6:FC:00:11:22" addrtype="mac" vendor="TP-Link"/>
    <hostnames>
      <hostname name="router.home.arpa" type="PTR"/>
    </hostnames>
    <ports>
      <extraports state="closed" count="998">
        <extrareasons reason="reset" count="998"/>
      </extraports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="uhttpd" version="2021-03-22" extrainfo="OpenWrt" devicetype="router" method="probed" conf="10">
          <cpe>cpe:/o:openwrt:openwrt</cpe>
        </service>
        <script id="http-title" output="OpenWrt - LuCI">
          <elem key="title">OpenWrt - LuCI</elem>
        </script>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="https" product="uhttpd" version="2021-03-22" extrainfo="OpenWrt" method="probed" conf="10"/>
      </port>
    </ports>
    <os>
      <portused state="open" proto="tcp" portid="80"/>
      <osmatch name="OpenWrt 21.02 (Linux 5.4)" accuracy="96" line="12345">
        <osclass type="router" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="96"/>
      </osmatch>
    </os>
    <distance value="1"/>
    <uptime seconds="864000" lastboot="Thu Jun 01 10:00:00 2024"/>
    <trace proto="tcp" port="80">
      <hop ttl="1" ipaddr="192.168.1.1" rtt="0.45" host="router.home.arpa"/>
    </trace>
  </host>
  <host starttime="1690000001" endtime="1690000008">
    <status state="up" reason="echo-reply" reason_ttl="128"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Intel Corporate"/>
    <hostnames>
      <hostname name="desktop-workstation" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.1" extrainfo="Ubuntu Linux" method="probed" conf="10"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.15" accuracy="98" line="54321">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="98"/>
      </osmatch>
    </os>
    <distance value="2"/>
    <trace proto="tcp" port="22">
      <hop ttl="1" ipaddr="192.168.1.1" rtt="0.40" host="router.home.arpa"/>
      <hop ttl="2" ipaddr="192.168.1.50" rtt="1.20" host="desktop-workstation"/>
    </trace>
  </host>
  <host starttime="1690000002" endtime="1690000003">
    <status state="down" reason="no-response" reason_ttl="0"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished time="1690000010" timestr="Mon Jul 22 00:00:10 2024" elapsed="10.00" summary="Nmap done; 3 IP addresses scanned" exit="success"/>
    <hosts up="2" down="1" total="3"/>
  </runstats>
</nmaprun>"""


class TestNmapParser(unittest.TestCase):

    def test_parse_nmap_xml_metadata_and_summary(self):
        data = parse_nmap_xml(SAMPLE_NMAP_XML)

        self.assertEqual(data["metadata"]["scanner"], "nmap")
        self.assertEqual(data["metadata"]["version"], "7.94")
        self.assertEqual(data["summary"]["hosts_up"], 2)
        self.assertEqual(data["summary"]["hosts_down"], 1)
        self.assertEqual(data["summary"]["hosts_total"], 3)
        self.assertEqual(data["summary"]["elapsed"], 10.0)

    def test_parse_hosts(self):
        data = parse_nmap_xml(SAMPLE_NMAP_XML)
        hosts = data["hosts"]
        self.assertEqual(len(hosts), 3)

        # Host 1
        h1 = hosts[0]
        self.assertEqual(h1["ip"], "192.168.1.1")
        self.assertEqual(h1["mac"], "54:E6:FC:00:11:22")
        self.assertEqual(h1["vendor"], "TP-Link")
        self.assertEqual(h1["primary_hostname"], "router.home.arpa")
        self.assertEqual(h1["status"]["state"], "up")
        self.assertEqual(h1["primary_os"], "OpenWrt 21.02 (Linux 5.4)")
        self.assertEqual(len(h1["ports"]), 2)

        p80 = h1["ports"][0]
        self.assertEqual(p80["portid"], 80)
        self.assertEqual(p80["protocol"], "tcp")
        self.assertEqual(p80["state"], "open")
        self.assertEqual(p80["service"]["name"], "http")
        self.assertEqual(p80["service"]["product"], "uhttpd")
        self.assertEqual(p80["service"]["banner"], "uhttpd 2021-03-22 (OpenWrt)")
        self.assertEqual(len(p80["scripts"]), 1)
        self.assertEqual(p80["scripts"][0]["id"], "http-title")

        # Host 3 (Down)
        h3 = hosts[2]
        self.assertEqual(h3["ip"], "192.168.1.99")
        self.assertEqual(h3["status"]["state"], "down")
        self.assertEqual(len(h3["ports"]), 0)

    def test_to_ag_grid(self):
        data = parse_nmap_xml(SAMPLE_NMAP_XML)
        rows = to_ag_grid(data)

        # 2 ports on host 1 + 1 port on host 2; down hosts are excluded from grid
        self.assertEqual(len(rows), 3)
        self.assertFalse(any(r["ip"] == "192.168.1.99" for r in rows))

        row0 = rows[0]
        self.assertEqual(row0["ip"], "192.168.1.1")
        self.assertEqual(row0["port"], 80)
        self.assertEqual(row0["service"], "http")
        self.assertIn("OpenWrt - LuCI", row0["scripts_summary"])

    def test_to_cytoscape(self):
        data = parse_nmap_xml(SAMPLE_NMAP_XML)
        cy = to_cytoscape(data, include_services=True, group_by_subnet=True)

        self.assertIn("nodes", cy)
        self.assertIn("edges", cy)

        nodes = cy["nodes"]
        edges = cy["edges"]

        node_ids = {n["data"]["id"] for n in nodes}
        self.assertIn("subnet-192.168.1.0_24", node_ids)
        self.assertIn("host-192.168.1.1", node_ids)
        self.assertIn("host-192.168.1.50", node_ids)
        self.assertIn("service-192.168.1.1-80-tcp", node_ids)

        # Check edge connecting host to service
        edge_sources = {e["data"]["source"] for e in edges}
        self.assertIn("host-192.168.1.1", edge_sources)

    def test_invalid_xml_handling(self):
        with self.assertRaises(ValueError):
            safe_parse_xml("")

        with self.assertRaises(ValueError):
            safe_parse_xml("<invalid></invalid>")

        with self.assertRaises(ValueError):
            safe_parse_xml("<?xml version='1.0'?><notnmap></notnmap>")

    def test_ports_only_requires_open_ports(self):
        """-Pn marks everything up; inventory must only keep hosts with open ports."""
        ghost = {
            "ip": "192.168.1.200",
            "mac": "AA:BB:CC:DD:EE:FF",
            "status": {"state": "up", "reason": "user-set"},
            "ports": [
                {"portid": 80, "protocol": "tcp", "state": "filtered", "service": {}},
            ],
        }
        live = {
            "ip": "192.168.1.10",
            "mac": "11:22:33:44:55:66",
            "status": {"state": "up", "reason": "user-set"},
            "ports": [
                {"portid": 22, "protocol": "tcp", "state": "open", "service": {"name": "ssh"}},
            ],
        }
        self.assertFalse(is_credibly_live(ghost, mode="ports_only"))
        self.assertTrue(is_credibly_live(live, mode="ports_only"))

        filtered = filter_hosts_for_inventory(
            {"hosts": [ghost, live], "summary": {}},
            scan_type="ports_only",
        )
        self.assertEqual([h["ip"] for h in filtered["hosts"]], ["192.168.1.10"])

    def test_proxy_arp_ghosts_dropped(self):
        """Many IPs sharing one MAC with no open ports are proxy-ARP ghosts."""
        gateway_mac = "54:E6:FC:00:11:22"
        ghosts = [
            {
                "ip": f"192.168.1.{i}",
                "mac": gateway_mac,
                "status": {"state": "up", "reason": "arp-response"},
                "ports": [],
            }
            for i in range(1, 12)
        ]
        # One real host with unique MAC + open port sharing nothing
        real = {
            "ip": "192.168.1.50",
            "mac": "AC:DE:48:00:22:33",
            "status": {"state": "up", "reason": "arp-response"},
            "ports": [{"portid": 22, "state": "open", "protocol": "tcp", "service": {}}],
        }
        kept = filter_proxy_arp_ghosts(ghosts + [real], mac_dup_threshold=5)
        ips = {h["ip"] for h in kept}
        self.assertEqual(ips, {"192.168.1.50"})
        self.assertEqual(len([h for h in kept if h.get("mac") == gateway_mac]), 0)

    def test_down_hosts_filtered_from_inventory(self):
        data = {
            "hosts": [
                {
                    "ip": "192.168.1.1",
                    "status": {"state": "up", "reason": "arp-response"},
                    "ports": [{"portid": 80, "state": "open", "protocol": "tcp", "service": {}}],
                },
                {
                    "ip": "192.168.1.2",
                    "status": {"state": "down", "reason": "no-response"},
                    "ports": [],
                },
                {
                    "ip": "192.168.1.3",
                    "status": {"state": "up", "reason": "user-set"},
                    "ports": [],
                },
            ],
            "summary": {"hosts_up": 3},
        }
        filtered = filter_hosts_for_inventory(data, scan_type="intense")
        ips = [h["ip"] for h in filtered["hosts"]]
        self.assertEqual(ips, ["192.168.1.1"])
        self.assertEqual(filtered["summary"]["hosts_up"], 1)


if __name__ == "__main__":
    unittest.main()
