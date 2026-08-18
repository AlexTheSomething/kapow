"""
backend/scanner.py - Asynchronous Multi-Stage Network Scanner Engine

Orchestrates 2-stage scanning pipeline:
1. Fast port sweep using `rustscan` (when available)
2. Targeted service, OS, and traceroute discovery using `nmap` (-T4 -sV -O --traceroute -oX -)
3. Real-time stdout terminal logging and resilient XML serialization into AG Grid and Cytoscape.js data models.
"""

import asyncio
import logging
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Union

# Import parsers and elevation helper
from parsers import (
    NmapParser,
    filter_hosts_for_inventory,
    filter_proxy_arp_ghosts,
    is_credibly_live,
    to_ag_grid,
    to_cytoscape,
)
from backend.elevation import build_elevated_command, is_elevated
from backend.asset_db import AssetDatabase
from backend.cve_lookup import enrich_scan_with_cves
from backend.engines import (
    find_cli_binary,
    get_available_engines,
    resolve_fast_sweep_engine,
)
from backend.scan_profiles import CustomProfileStore

logger = logging.getLogger(__name__)
asset_db = AssetDatabase()


# Sample Nmap XML for offline testing and initial UI preview
SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O --traceroute -oX - 192.168.1.0/24" start="1700000000" startstr="Wed Nov 15 10:00:00 2024" version="7.94" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1024"/>
  <verbose level="1"/>
  <debugging level="0"/>
  <host starttime="1700000000" endtime="1700000005">
    <status state="up" reason="arp-response" reason_ttl="0"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="54:E6:FC:00:11:22" addrtype="mac" vendor="TP-Link"/>
    <hostnames>
      <hostname name="gateway.home.arpa" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="53">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="domain" product="dnsmasq" version="2.86" extrainfo="OpenWrt" devicetype="router" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="uhttpd" version="2021-03-22" extrainfo="OpenWrt LuCI" devicetype="router" method="probed" conf="10">
          <cpe>cpe:/o:openwrt:openwrt</cpe>
        </service>
        <script id="http-title" output="OpenWrt - Router Admin">
          <elem key="title">OpenWrt - Router Admin</elem>
        </script>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="https" product="uhttpd" version="2021-03-22" extrainfo="SSL" method="probed" conf="10"/>
      </port>
    </ports>
    <os>
      <portused state="open" proto="tcp" portid="80"/>
      <osmatch name="OpenWrt 21.02 (Linux 5.4)" accuracy="98" line="1001">
        <osclass type="router" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="98"/>
      </osmatch>
    </os>
    <uptime seconds="864000" lastboot="Wed Nov 05 10:00:00 2024"/>
    <distance value="1"/>
    <trace port="80" proto="tcp">
      <hop ttl="1" ipaddr="192.168.1.1" rtt="0.45" host="gateway.home.arpa"/>
    </trace>
  </host>
  <host starttime="1700000002" endtime="1700000008">
    <status state="up" reason="arp-response" reason_ttl="0"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <address addr="AC:DE:48:00:22:33" addrtype="mac" vendor="Apple"/>
    <hostnames>
      <hostname name="alex-macbook.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="9.6" extrainfo="protocol 2.0" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="5000">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="Node.js Express framework" method="probed" conf="10"/>
      </port>
    </ports>
    <os>
      <portused state="open" proto="tcp" portid="22"/>
      <osmatch name="Apple macOS 14 (Sonoma)" accuracy="95" line="1002">
        <osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="14.X" accuracy="95"/>
      </osmatch>
    </os>
    <distance value="1"/>
    <trace port="22" proto="tcp">
      <hop ttl="1" ipaddr="192.168.1.1" rtt="0.52" host="gateway.home.arpa"/>
      <hop ttl="2" ipaddr="192.168.1.100" rtt="1.20" host="alex-macbook.local"/>
    </trace>
  </host>
  <host starttime="1700000003" endtime="1700000009">
    <status state="up" reason="arp-response" reason_ttl="0"/>
    <address addr="192.168.1.150" addrtype="ipv4"/>
    <address addr="00:15:5D:AA:BB:CC" addrtype="mac" vendor="Microsoft"/>
    <hostnames>
      <hostname name="win-dev-station.lan" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="135">
        <state state="open" reason="syn-ack" reason_ttl="128"/>
        <service name="msrpc" product="Microsoft Windows RPC" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack" reason_ttl="128"/>
        <service name="microsoft-ds" product="Windows 11 SMB" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open" reason="syn-ack" reason_ttl="128"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services" extrainfo="RDP" method="probed" conf="10"/>
      </port>
    </ports>
    <os>
      <portused state="open" proto="tcp" portid="445"/>
      <osmatch name="Microsoft Windows 11 22H2" accuracy="96" line="1003">
        <osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="11" accuracy="96"/>
      </osmatch>
    </os>
    <distance value="1"/>
    <trace port="445" proto="tcp">
      <hop ttl="1" ipaddr="192.168.1.1" rtt="0.61" host="gateway.home.arpa"/>
      <hop ttl="2" ipaddr="192.168.1.150" rtt="1.85" host="win-dev-station.lan"/>
    </trace>
  </host>
  <runstats>
    <finished time="1700000010" timestr="Wed Nov 15 10:00:10 2024" elapsed="10.0" summary="Nmap done at Wed Nov 15 10:00:10 2024; 3 IP addresses (3 hosts up) scanned in 10.00 seconds" exit="success"/>
    <hosts up="3" down="0" total="3"/>
  </runstats>
</nmaprun>
"""


class ScannerEngine:
    """
    Non-blocking async network scanner executing RustScan/Nmap and generating structured JSON payloads.
    """

    def __init__(self):
        self._current_process: Optional[asyncio.subprocess.Process] = None
        self._is_running: bool = False
        self._live_logs: List[str] = []
        self._status_text: str = "Ready"
        self._start_time: float = 0.0

    @property
    def is_running(self) -> bool:
        """Return whether a scan is actively running."""
        return self._is_running

    def get_live_state(self) -> Dict[str, Any]:
        """Return current real-time scanner state and accumulated terminal output."""
        elapsed = time.time() - self._start_time if self._is_running and self._start_time > 0 else 0.0
        return {
            "is_scanning": self._is_running,
            "status": self._status_text,
            "elapsed": round(elapsed, 1),
            "logs": list(self._live_logs[-200:]),  # return latest 200 log lines
        }

    def check_dependencies(self) -> Dict[str, Any]:
        """
        Check availability of CLI dependencies (nmap, rustscan, masscan, naabu)
        on system PATH, Windows Registry, or standard installation directories.

        :return: Dict containing availability status and binary paths.
        """
        engines = get_available_engines()

        return {
            "nmap": {
                "installed": engines["nmap"]["installed"],
                "path": engines["nmap"]["path"],
                "required": True,
            },
            "rustscan": {
                "installed": engines["rustscan"]["installed"],
                "path": engines["rustscan"]["path"],
            },
            "masscan": {
                "installed": engines["masscan"]["installed"],
                "path": engines["masscan"]["path"],
            },
            "naabu": {
                "installed": engines["naabu"]["installed"],
                "path": engines["naabu"]["path"],
            },
            "fast_sweep_engines": engines["fast_sweep_available"],
            "is_elevated": is_elevated(),
            "platform": sys.platform,
        }

    async def _run_fast_sweep(
        self,
        target: str,
        ports: Optional[str] = None,
        engine_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Stage 1: Execute fast port sweep using the best available engine
        (RustScan → Masscan → Naabu, or the explicitly requested engine).

        :param target: Host IP, hostname, or CIDR range.
        :param ports: Optional port range (e.g. '1-1000').
        :param engine_key: Optional engine key override ('rustscan', 'masscan', 'naabu').
        :return: Dict with {'engine': key, 'ports': [...]} or None if unavailable/failed.
        """
        adapter = resolve_fast_sweep_engine(preferred=engine_key)
        if adapter is None:
            return None

        cmd = adapter.build_cmd(target, ports)
        engine_label = adapter.label

        try:
            log_line = (
                f"[*] Stage 1/2: Running fast port sweep with {engine_label} "
                f"({' '.join(cmd)})"
            )
            logger.info(log_line)
            self._live_logs.append(log_line)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._current_process = proc
            stdout_bytes, stderr_bytes = await proc.communicate()

            if proc.returncode != 0:
                err_txt = stderr_bytes.decode("utf-8", errors="ignore")
                self._live_logs.append(
                    f"[!] {engine_label} non-zero exit ({proc.returncode}): {err_txt}"
                )
                return None

            output = stdout_bytes.decode("utf-8", errors="ignore")
            self._live_logs.append(f"[+] {engine_label} raw output: {output.strip()}")

            found_ports = adapter.parse_stdout(output)
            if found_ports:
                return {"engine": adapter.key, "ports": found_ports}

        except Exception as e:
            logger.warning(f"{engine_label} sweep encountered error: {e}")
            self._live_logs.append(f"[!] {engine_label} warning: {e}")
        finally:
            self._current_process = None

        return None

    def build_nmap_command(
        self,
        target: str,
        ports: Optional[Union[str, List[int]]] = None,
        scan_type: str = "quick",
        requires_root: bool = False,
        scripts: Optional[str] = None,
        output_xml_path: Optional[str] = None,
    ) -> List[str]:
        """
        Construct optimized argument list for Nmap with fast timing, sane timeouts, and real-time stats.

        :param target: IP, CIDR, or hostname.
        :param ports: Port string or list of port integers.
        :param scan_type: Scan profile ('quick', 'quick_plus', 'comprehensive', 'intense', 'ping_sweep', 'ports_only').
        :param requires_root: Whether to wrap with root elevation.
        :param scripts: Optional NSE scripts.
        :param output_xml_path: Temporary XML file path for structured output.
        :return: Command list ready for execution.
        """
        nmap_bin = find_cli_binary("nmap") or "nmap"
        cmd = [nmap_bin]

        # Custom user profiles: resolve alias → built-in profile args
        profile_store = CustomProfileStore()
        if scan_type.startswith("custom_"):
            try:
                pid = int(scan_type.split("_", 1)[1])
                profile = profile_store.get_profile(pid)
                if profile and profile.get("args"):
                    alias = profile["args"][0]  # e.g. "quick" or "comprehensive"
                    if alias.startswith("custom_"):
                        # chained alias — one level of indirection max
                        inner = profile_store.get_profile(int(alias.split("_", 1)[1]))
                        alias = (inner.get("args") or ["quick"])[0] if inner else "quick"
                    # Rebuild command using the aliased built-in profile
                    base_cmd = self.build_nmap_command(
                        target="",
                        ports=None,
                        scan_type=alias if alias in ("ping_sweep", "quick", "quick_plus", "comprehensive", "intense", "ports_only") else "quick",
                        requires_root=False,
                        scripts=None,
                        output_xml_path=output_xml_path,
                    )
                    # base_cmd = [nmap, ...args..., -oX path]; rebuild with target/ports
                    cmd = base_cmd
                    # Insert ports if provided (skip the -p already present, add ours)
                    if ports:
                        ports_arg = ",".join(str(p) for p in ports) if isinstance(ports, list) else str(ports).strip()
                        if ports_arg and "-p" not in cmd:
                            # insert before -oX
                            ox_idx = cmd.index("-oX") if "-oX" in cmd else len(cmd)
                            cmd = cmd[:ox_idx] + ["-p", ports_arg] + cmd[ox_idx:]
                    # Append targets (base_cmd has no target since target="")
                    for t in target.split():
                        cmd.append(t.strip())
                    if requires_root:
                        return build_elevated_command(cmd)
                    return cmd
            except (ValueError, IndexError):
                pass  # fall through to built-in profiles

        # Shared timing guardrails — prevent hung hosts from stalling the whole job
        timing_guards = [
            "--max-retries", "1",
            "--host-timeout", "45s",
            "--max-rtt-timeout", "800ms",
            "--initial-rtt-timeout", "300ms",
        ]

        # Scan profiles with optimized timing (-T4) and sane timeouts
        # Never use -Pn on raw CIDRs here; pipeline applies -Pn only to pre-discovered hosts.
        if scan_type == "ping_sweep":
            cmd.extend(["-sn", "-T4", "--max-retries", "1", "--host-timeout", "15s"])
        elif scan_type == "quick":
            cmd.extend(["-T4", "-F", *timing_guards])
        elif scan_type == "quick_plus":
            cmd.extend([
                "-sV", "--version-light", "-T4", "-F",
                "--osscan-limit", "--max-os-tries", "1",
                *timing_guards,
            ])
        elif scan_type == "intense":
            # Service + default scripts; keep host discovery unless caller already scoped targets
            cmd.extend([
                "-T4", "-sV", "--version-light", "-F", "-sC",
                "--script-timeout", "20s",
                *timing_guards,
            ])
        elif scan_type == "ports_only":
            # Skip ping only for already-scoped targets (single host or post-discovery list)
            cmd.extend(["-Pn", "-T4", "-F", *timing_guards])
        else:  # comprehensive
            cmd.extend([
                "-sV", "-T4", "--version-light", "-F",
                "--osscan-limit", "--max-os-tries", "1",
                "--max-retries", "2",
                "--host-timeout", "60s",
                "--max-rtt-timeout", "800ms",
                "--initial-rtt-timeout", "300ms",
            ])

        # Specify ports if provided
        if ports:
            if isinstance(ports, list):
                ports_arg = ",".join(str(p) for p in ports)
            else:
                ports_arg = str(ports).strip()
            if ports_arg:
                cmd.extend(["-p", ports_arg])

        # NSE Scripts if specified (avoid duplicating -sC script set when intense already set it)
        if scripts and scripts.strip():
            cmd.extend(["--script", scripts.strip()])

        # Verbosity and real-time stats interval for live feedback
        cmd.extend(["-v", "--stats-every", "1s"])

        # Output format: XML to file or stdout
        if output_xml_path:
            cmd.extend(["-oX", output_xml_path])
        else:
            cmd.extend(["-oX", "-"])

        # Target specification (supports space-separated multiple targets from ping sweep)
        for t in target.split():
            cmd.append(t.strip())

        if requires_root:
            return build_elevated_command(cmd)

        return cmd

    async def run_pipeline(
        self,
        target: str,
        ports: Optional[str] = None,
        requires_root: bool = False,
        scan_type: str = "quick",
        scripts: Optional[str] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """
        Execute full asynchronous scanning pipeline with real-time log streaming.

        :param target: Target IP, hostname, or CIDR.
        :param ports: Optional port string.
        :param requires_root: Whether root/admin privileges are requested.
        :param scan_type: Scan profile.
        :param scripts: Optional NSE scripts.
        :param progress_callback: Optional callback for status updates.
        :return: Normalized dictionary containing parsed results, AG Grid rows, and Cytoscape elements.
        """
        if self._is_running:
            return {"success": False, "error": "A scan is already in progress."}

        target = target.strip()
        if not target:
            return {"success": False, "error": "Target specification cannot be empty."}

        deps = self.check_dependencies()
        if not deps["nmap"]["installed"]:
            return {
                "success": False,
                "error": "Nmap binary was not found. Please install Nmap (https://nmap.org) or verify your installation directory.",
                "missing_dependency": "nmap",
                "dependencies": deps,
            }

        self._is_running = True
        self._start_time = time.time()
        self._live_logs = []
        self._status_text = f"Initializing {scan_type} scan on {target}..."

        stage_info: Dict[str, Any] = {
            "rustscan_used": False,  # legacy key, kept for compatibility
            "engine_used": None,
            "discovered_ports": [],
            "nmap_args": [],
        }

        # Create temporary XML file for clean structured output
        import tempfile
        xml_tmp_fd, xml_tmp_path = tempfile.mkstemp(prefix="kapow_scan_", suffix=".xml")
        os.close(xml_tmp_fd)

        try:
            # Stage 0: For subnet/range targets, first do a ping sweep to find live hosts.
            # This prevents -Pn / proxy-ARP from treating an entire /24 as alive.
            is_subnet = ("/" in target) or ("-" in target and not target.startswith("-"))
            effective_target = target
            discovery_hosts: List[Dict[str, Any]] = []

            needs_discovery = is_subnet and scan_type != "ping_sweep"
            # ports_only on a CIDR must still discover first; -Pn is applied only to survivors
            if needs_discovery:
                self._status_text = f"Stage 1: Ping sweep to discover live hosts on {target}..."
                self._live_logs.append(f"[*] Running ping sweep on {target} to find live hosts...")
                if progress_callback:
                    progress_callback(self._status_text)

                nmap_bin = find_cli_binary("nmap") or "nmap"
                sweep_cmd = [
                    nmap_bin, "-sn", "-T4",
                    "--max-retries", "1",
                    "--host-timeout", "15s",
                    "-oX", "-",
                    target,
                ]
                self._live_logs.append(f"[*] Sweep command: {' '.join(sweep_cmd)}")

                try:
                    sweep_proc = await asyncio.create_subprocess_exec(
                        *sweep_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    self._current_process = sweep_proc
                    sweep_stdout, sweep_stderr = await sweep_proc.communicate()
                    self._current_process = None
                    sweep_xml = sweep_stdout.decode("utf-8", errors="ignore") if sweep_stdout else ""

                    if sweep_xml.strip():
                        sweep_parser = NmapParser(sweep_xml)
                        sweep_data = sweep_parser.parse()
                        discovery_hosts = [
                            h for h in sweep_data.get("hosts", [])
                            if is_credibly_live(h, mode="ping_sweep") and h.get("ip")
                        ]
                        discovery_hosts = filter_proxy_arp_ghosts(
                            discovery_hosts,
                            keep_gateway_candidate=True,
                        )
                        live_hosts = [h["ip"] for h in discovery_hosts]

                        if live_hosts:
                            effective_target = " ".join(live_hosts)
                            self._live_logs.append(
                                f"[+] Ping sweep found {len(live_hosts)} credible live host(s): "
                                f"{', '.join(live_hosts)}"
                            )
                        else:
                            # Do NOT fall back to scanning the full CIDR — that recreates mass false positives
                            self._live_logs.append(
                                f"[!] Ping sweep found 0 credible live hosts on {target}. Stopping."
                            )
                            self._status_text = "No live hosts discovered."
                            empty = {
                                "metadata": sweep_data.get("metadata", {}),
                                "summary": {"hosts_up": 0, "hosts_down": 0, "hosts_total": 0},
                                "hosts": [],
                            }
                            return {
                                "success": True,
                                "target": target,
                                "scan_profile": scan_type,
                                "raw_xml": sweep_xml,
                                "data": empty,
                                "ag_grid": [],
                                "cytoscape": {"nodes": [], "edges": []},
                                "stage_info": stage_info,
                                "logs": self._live_logs,
                                "message": "No live hosts discovered during ping sweep.",
                            }
                    else:
                        err_txt = (sweep_stderr or b"").decode("utf-8", errors="ignore")
                        self._live_logs.append(
                            f"[!] Ping sweep returned no XML ({err_txt.strip() or 'empty'}). Stopping."
                        )
                        return {
                            "success": False,
                            "error": "Host discovery (ping sweep) returned no results.",
                            "stage_info": stage_info,
                            "logs": self._live_logs,
                        }
                except Exception as sweep_err:
                    self._current_process = None
                    self._live_logs.append(f"[!] Ping sweep failed ({sweep_err}). Aborting subnet scan.")
                    return {
                        "success": False,
                        "error": f"Host discovery failed: {sweep_err}",
                        "stage_info": stage_info,
                        "logs": self._live_logs,
                    }

            # Stage 1: Optional fast port sweep via best available engine
            fast_engines = deps.get("fast_sweep_engines") or []
            if fast_engines and scan_type in ("comprehensive", "quick", "quick_plus") and not ports:
                self._status_text = "Fast port discovery (best available engine)..."
                if progress_callback:
                    progress_callback(self._status_text)

                sweep_result = await self._run_fast_sweep(effective_target, ports)
                if sweep_result:
                    engine_key = sweep_result["engine"]
                    found_ports = sweep_result["ports"]
                    stage_info["engine_used"] = engine_key
                    if engine_key == "rustscan":
                        stage_info["rustscan_used"] = True
                    stage_info["discovered_ports"] = found_ports
                    ports = ",".join(str(p) for p in found_ports)
                    self._live_logs.append(
                        f"[+] Discovered {len(found_ports)} open ports via "
                        f"{engine_key}: {ports}"
                    )

            # Stage 2: Targeted Nmap scan against live hosts only
            self._status_text = f"Executing {scan_type} scan..."
            if progress_callback:
                progress_callback(self._status_text)

            nmap_cmd = self.build_nmap_command(
                target=effective_target,
                ports=ports,
                scan_type=scan_type,
                requires_root=requires_root,
                scripts=scripts,
                output_xml_path=xml_tmp_path,
            )
            stage_info["nmap_args"] = nmap_cmd

            cmd_str = " ".join(nmap_cmd)
            self._live_logs.append(f"[*] Executing Nmap process: {cmd_str}")
            logger.info(f"Executing Nmap process: {cmd_str}")

            proc = await asyncio.create_subprocess_exec(
                *nmap_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._current_process = proc

            # Real-time stdout reader loop
            async def _stream_reader(stream, is_stderr=False):
                while True:
                    line_bytes = await stream.readline()
                    if not line_bytes:
                        break
                    line = line_bytes.decode('utf-8', errors='ignore').strip()
                    if not line:
                        continue

                    prefix = "[stderr] " if is_stderr else ""
                    self._live_logs.append(f"{prefix}{line}")

                    # Detect progress and open ports in real-time
                    if "Discovered open port" in line:
                        self._status_text = line
                        if progress_callback:
                            progress_callback(line)
                    elif "About " in line and "% done" in line:
                        self._status_text = line
                        if progress_callback:
                            progress_callback(line)
                    elif "Initiating " in line or "Completed " in line:
                        self._status_text = line

            await asyncio.gather(
                _stream_reader(proc.stdout, is_stderr=False),
                _stream_reader(proc.stderr, is_stderr=True),
            )
            await proc.wait()

            # Read generated XML file
            raw_stdout = ""
            if os.path.exists(xml_tmp_path):
                try:
                    with open(xml_tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                        raw_stdout = f.read()
                except Exception as e:
                    logger.exception(f"Error reading temp XML output: {e}")

            if not raw_stdout.strip() and proc.returncode != 0:
                err_msg = f"Nmap exited with code {proc.returncode}"
                self._live_logs.append(f"[!] Scan failed: {err_msg}")
                return {
                    "success": False,
                    "error": f"Nmap execution failed: {err_msg}",
                    "stage_info": stage_info,
                    "logs": self._live_logs,
                }

            self._live_logs.append(f"[+] Scan completed ({len(raw_stdout)} bytes XML). Parsing results...")

            # Parse XML output with auto-healing parser
            parser = NmapParser(raw_stdout)
            parsed_data = parser.parse()

            # Drop down / -Pn ghosts / proxy-ARP false positives before UI models
            parsed_data = filter_hosts_for_inventory(parsed_data, scan_type=scan_type)

            # Enrich hosts with SQLite asset metadata (aliases, tags, notes)
            for h in parsed_data.get("hosts", []):
                asset_db.enrich_host(h)

            ag_grid_rows = to_ag_grid(parsed_data)
            cytoscape_elements = to_cytoscape(parsed_data)

            hosts_count = len(parsed_data.get("hosts", []))
            self._status_text = f"Scan complete: {hosts_count} host(s) discovered."
            self._live_logs.append(f"[+] Processed: {hosts_count} credible hosts, {len(ag_grid_rows)} service rows.")

            scan_payload = {
                "success": True,
                "target": target,
                "scan_profile": scan_type,
                "raw_xml": raw_stdout,
                "data": parsed_data,
                "ag_grid": ag_grid_rows,
                "cytoscape": cytoscape_elements,
                "stage_info": stage_info,
                "logs": self._live_logs,
            }

            # Enrich with CVE & Vulnerability intelligence
            enrich_scan_with_cves(scan_payload)

            if progress_callback:
                progress_callback(self._status_text)

            return scan_payload

        except asyncio.CancelledError:
            self._live_logs.append("[!] Scan was cancelled by user.")
            return {"success": False, "error": "Scan was cancelled by the user.", "logs": self._live_logs}
        except Exception as ex:
            logger.exception("Scan pipeline execution error:")
            self._live_logs.append(f"[!] Critical error: {str(ex)}")
            return {"success": False, "error": f"Scan failed: {str(ex)}", "logs": self._live_logs}
        finally:
            self._is_running = False
            self._current_process = None
            if os.path.exists(xml_tmp_path):
                try:
                    os.remove(xml_tmp_path)
                except Exception:
                    pass

    def cancel_scan(self) -> Dict[str, Any]:
        """
        Abort and terminate the currently running scan subprocess.

        :return: Status response dictionary.
        """
        self._live_logs.append("[*] Cancelling active scan subprocess...")
        if self._current_process and self._current_process.returncode is None:
            try:
                self._current_process.terminate()
                return {"success": True, "message": "Scan process cancellation signal sent."}
            except Exception as e:
                try:
                    self._current_process.kill()
                    return {"success": True, "message": "Scan process forcibly killed."}
                except Exception as kill_err:
                    return {"success": False, "error": f"Failed to kill process: {kill_err}"}
        self._is_running = False
        return {"success": True, "message": "No active scan was running."}

    @staticmethod
    def get_sample_data() -> Dict[str, Any]:
        """
        Return parsed data models from built-in sample XML for offline/demo operation.

        :return: Normalized scan dataset including AG Grid rows and Cytoscape elements.
        """
        parser = NmapParser(SAMPLE_NMAP_XML)
        parsed_data = filter_hosts_for_inventory(parser.parse(), scan_type="comprehensive")

        for h in parsed_data.get("hosts", []):
            asset_db.enrich_host(h)

        ag_grid_rows = to_ag_grid(parsed_data)
        cytoscape_elements = to_cytoscape(parsed_data)

        payload = {
            "success": True,
            "target": "192.168.1.0/24 (Sample Network)",
            "is_sample": True,
            "raw_xml": SAMPLE_NMAP_XML,
            "data": parsed_data,
            "ag_grid": ag_grid_rows,
            "cytoscape": cytoscape_elements,
            "stage_info": {
                "rustscan_used": True,
                "engine_used": "rustscan",
                "discovered_ports": [22, 53, 80, 135, 443, 445, 3389, 5000],
                "nmap_args": ["nmap", "-sV", "-O", "--traceroute", "-T4", "-oX", "-", "192.168.1.0/24"],
            },
            "logs": [
                "[*] Loaded sample network diagnostic dataset",
                "[+] Target: 192.168.1.0/24 (Subnet)",
                "[+] Discovered 3 active hosts and 8 open services with OS fingerprints.",
            ]
        }

        enrich_scan_with_cves(payload)
        return payload

