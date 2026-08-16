"""
backend/app.py - PyWebView JS API Bridge & Window Configuration

Provides:
- BackendAPI: Bridge class exposed to JavaScript via `window.pywebview.api`
- create_window(): Configures desktop window for dev or production
"""

import asyncio
import csv
import io
import json
import logging
import os
import sys
import webbrowser
from typing import Any, Dict, Optional

import webview
from backend.scanner import ScannerEngine
from backend.asset_db import AssetDatabase
from backend.diff_engine import compare_scans
from backend.cve_lookup import lookup_cves
from backend.net_interfaces import get_network_interfaces, get_primary_interface
from backend.launcher import launch_protocol, send_wake_on_lan
from backend.telemetry import ping_host, reset_telemetry
from backend.passive_sniffer import PassiveSnifferEngine
from backend.scan_store import ScanStore

logger = logging.getLogger(__name__)


class BackendAPI:
    """
    Python API methods callable from frontend JavaScript (window.pywebview.api).
    """

    def __init__(self):
        self.scanner = ScannerEngine()
        self.asset_db = AssetDatabase()
        self.scan_store = ScanStore()
        self.sniffer = PassiveSnifferEngine()
        self.sniffer.start_listeners()
        self._active_task: Optional[asyncio.Task] = None

    def check_dependencies(self) -> Dict[str, Any]:
        """
        Check availability of Nmap and RustScan CLI tools on system PATH.

        :return: JSON-serializable status dictionary.
        """
        try:
            return self.scanner.check_dependencies()
        except Exception as e:
            logger.exception("Failed checking dependencies:")
            return {
                "nmap": {"installed": False, "path": ""},
                "rustscan": {"installed": False, "path": ""},
                "is_elevated": False,
                "platform": sys.platform,
                "error": str(e),
            }

    def start_scan(
        self,
        target: str,
        ports: str = "",
        requires_root: bool = False,
        scan_type: str = "quick",
        scripts: str = "",
    ) -> Dict[str, Any]:
        """
        Start network diagnostic scan with optional NSE scripts.
        """
        logger.info(f"Scan request: target='{target}', ports='{ports}', root={requires_root}, type='{scan_type}', scripts='{scripts}'")

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(
                    self.scanner.run_pipeline(
                        target=target,
                        ports=ports,
                        requires_root=requires_root,
                        scan_type=scan_type,
                        scripts=scripts,
                    )
                )
                if result.get("success") and not result.get("is_sample"):
                    saved = self.scan_store.save_scan(result)
                    if saved.get("success"):
                        result["history_id"] = saved.get("id")
                return result
            finally:
                loop.close()
        except Exception as e:
            logger.exception("start_scan exception:")
            return {"success": False, "error": f"Internal scan engine error: {str(e)}"}

    def get_live_state(self) -> Dict[str, Any]:
        """
        Poll real-time scanner status and terminal logs while scanning.

        :return: JSON dictionary with is_scanning, status text, elapsed time, and log lines.
        """
        try:
            return self.scanner.get_live_state()
        except Exception as e:
            return {"is_scanning": False, "status": "Error", "elapsed": 0.0, "logs": [str(e)]}

    def cancel_scan(self) -> Dict[str, Any]:
        """
        Cancel active scan subprocess.

        :return: Status response dictionary.
        """
        try:
            return self.scanner.cancel_scan()
        except Exception as e:
            logger.exception("cancel_scan exception:")
            return {"success": False, "error": str(e)}

    def load_sample_scan(self) -> Dict[str, Any]:
        """
        Load sample multi-host network scan dataset for UI demonstration.

        :return: Normalized scan dataset.
        """
        try:
            return self.scanner.get_sample_data()
        except Exception as e:
            logger.exception("load_sample_scan exception:")
            return {"success": False, "error": str(e)}

    def export_results(self, payload: Dict[str, Any], file_format: str = "json") -> Dict[str, Any]:
        """
        Export scan results into JSON, CSV, or XML format.

        :param payload: Scan result object.
        :param file_format: 'json', 'csv', or 'xml'.
        :return: Dict containing exported string content or status.
        """
        try:
            fmt = file_format.lower()
            if fmt == "json":
                return {
                    "success": True,
                    "format": "json",
                    "content": json.dumps(payload, indent=2),
                    "filename": "scan_results.json",
                }
            elif fmt == "xml":
                raw_xml = payload.get("raw_xml", "")
                return {
                    "success": True,
                    "format": "xml",
                    "content": raw_xml,
                    "filename": "scan_results.xml",
                }
            elif fmt == "csv":
                rows = payload.get("ag_grid", [])
                if not rows:
                    return {"success": False, "error": "No tabular data found to export to CSV."}

                output = io.StringIO()
                fieldnames = list(rows[0].keys())
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
                return {
                    "success": True,
                    "format": "csv",
                    "content": output.getvalue(),
                    "filename": "scan_results.csv",
                }
            else:
                return {"success": False, "error": f"Unsupported export format: {file_format}"}
        except Exception as e:
            logger.exception("export_results exception:")
            return {"success": False, "error": str(e)}

    def get_all_assets(self) -> Dict[str, Any]:
        """Retrieve all tagged assets from SQLite database."""
        try:
            assets = self.asset_db.get_all_assets()
            return {"success": True, "assets": assets}
        except Exception as e:
            return {"success": False, "error": str(e), "assets": []}

    def save_asset_metadata(self, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save or update custom alias, owner, tags, notes, and risk level for a device."""
        try:
            ip = asset_data.get("ip", "")
            mac = asset_data.get("mac", "")
            alias = asset_data.get("alias", "")
            owner = asset_data.get("owner", "")
            tags = asset_data.get("tags", [])
            notes = asset_data.get("notes", "")
            risk_level = asset_data.get("risk_level", "LOW")

            saved = self.asset_db.save_asset(
                ip=ip,
                mac=mac,
                alias=alias,
                owner=owner,
                tags=tags,
                notes=notes,
                risk_level=risk_level,
            )
            return {"success": True, "asset": saved}
        except Exception as e:
            logger.exception("save_asset_metadata exception:")
            return {"success": False, "error": str(e)}

    def delete_asset_metadata(self, key: str) -> Dict[str, Any]:
        """Delete asset metadata by MAC/IP key."""
        try:
            ok = self.asset_db.delete_asset(key)
            return {"success": ok}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def compare_scan_snapshots(self, scan_a: Dict[str, Any], scan_b: Dict[str, Any]) -> Dict[str, Any]:
        """Compare two scans and return drift analysis."""
        try:
            return compare_scans(scan_a, scan_b)
        except Exception as e:
            logger.exception("compare_scan_snapshots exception:")
            return {"success": False, "error": str(e)}

    def list_scan_history(self, limit: int = 50) -> Dict[str, Any]:
        """List persisted scan snapshots (newest first)."""
        try:
            scans = self.scan_store.list_scans(limit=limit)
            return {"success": True, "scans": scans}
        except Exception as e:
            return {"success": False, "error": str(e), "scans": []}

    def get_scan_history_item(self, scan_id: int) -> Dict[str, Any]:
        """Load a full persisted scan payload by id."""
        try:
            payload = self.scan_store.get_scan(int(scan_id))
            if not payload:
                return {"success": False, "error": "Scan not found."}
            return {"success": True, "scan": payload}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def delete_scan_history_item(self, scan_id: int) -> Dict[str, Any]:
        """Delete one persisted scan snapshot."""
        try:
            ok = self.scan_store.delete_scan(int(scan_id))
            return {"success": ok}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def lookup_cves_api(
        self,
        service: str = "",
        product: str = "",
        version: str = "",
        port: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Lookup CVEs for specific service parameters."""
        try:
            cves = lookup_cves(service_name=service, product=product, version=version, port=port)
            return {"success": True, "cves": cves}
        except Exception as e:
            return {"success": False, "error": str(e), "cves": []}

    def get_network_interfaces(self) -> Dict[str, Any]:
        """Enumerate active network adapters and local subnets."""
        try:
            ifaces = get_network_interfaces()
            primary = get_primary_interface()
            return {"success": True, "interfaces": ifaces, "primary": primary}
        except Exception as e:
            logger.exception("get_network_interfaces error:")
            return {"success": False, "error": str(e), "interfaces": [], "primary": None}

    def launch_remote_tool(
        self,
        protocol: str,
        ip: str,
        port: Optional[int] = None,
        username: str = "",
    ) -> Dict[str, Any]:
        """Launch desktop protocol tools (HTTP, RDP, SSH, SMB, Ping)."""
        return launch_protocol(protocol=protocol, ip=ip, port=port, username=username)

    def send_wake_on_lan_packet(
        self,
        mac: str,
        broadcast_ip: str = "255.255.255.255",
        port: int = 9,
    ) -> Dict[str, Any]:
        """Send Wake-on-LAN magic packet to power on remote machine."""
        return send_wake_on_lan(mac_address=mac, broadcast_ip=broadcast_ip, port=port)

    def ping_host_telemetry(self, ip: str, timeout_ms: int = 1000) -> Dict[str, Any]:
        """Run single ping probe and retrieve rolling telemetry stats & jitter."""
        try:
            return ping_host(target_ip=ip, timeout_ms=timeout_ms)
        except Exception as e:
            return {"success": False, "error": str(e), "is_online": False}

    def reset_host_telemetry(self, ip: str = "") -> Dict[str, Any]:
        """Reset historical ping telemetry cache."""
        reset_telemetry(ip if ip else None)
        return {"success": True}

    def get_passive_discovered_devices(self) -> Dict[str, Any]:
        """Retrieve passively discovered network devices (zero-noise mode)."""
        try:
            devices = self.sniffer.get_discovered_nodes()
            return {"success": True, "devices": devices}
        except Exception as e:
            logger.exception("get_passive_discovered_devices error:")
            return {"success": False, "error": str(e), "devices": []}

    def get_passive_listener_status(self) -> Dict[str, Any]:
        """Return status of each passive listener (ARP, SSDP, mDNS)."""
        try:
            return {"success": True, "listeners": self.sniffer.get_listener_status()}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def open_external_url(self, url: str) -> Dict[str, Any]:
        """
        Open external URL in system default browser.

        :param url: Web URL.
        :return: Status response dictionary.
        """
        try:
            webbrowser.open(url)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}


def create_app_window(dev: bool = True, port: int = 5173) -> webview.Window:
    """
    Create and configure the PyWebView desktop application window.

    :param dev: If True, connects to Vite dev server on localhost:port; otherwise loads static build.
    :param port: Vite dev server port.
    :return: Configured webview.Window instance.
    """
    api = BackendAPI()

    if dev:
        url = f"http://localhost:{port}"
    else:
        base_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        dist_path = os.path.join(base_dir, "frontend", "dist", "index.html")
        if not os.path.exists(dist_path):
            logger.warning(f"Production build not found at {dist_path}. Falling back to dev URL.")
            url = f"http://localhost:{port}"
        else:
            url = dist_path

    window = webview.create_window(
        title="Kapow - Network Security Auditor & Topology Engine",
        url=url,
        js_api=api,
        width=1380,
        height=890,
        min_size=(960, 640),
        background_color="#0b0f19",
        easy_drag=True,
    )

    return window
