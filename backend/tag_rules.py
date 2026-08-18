"""
backend/tag_rules.py - Auto-Suggested Tag Engine

Analyzes a completed scan payload and suggests tags for hosts based on
rule patterns (old/vulnerable service versions, exposed shares, legacy
protocols, new devices, web admin panels, etc.).

Suggestions are quiet: the UI surfaces a small "N suggestions" badge only
when matches exist. Users accept (persist to asset DB) or dismiss.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Severity-ordered suggestion definitions.
# Each rule: (tag, color, reason_template, matcher_fn(host) -> Optional[str] or bool)
# matcher returns a human-readable reason (or True for default reason).

_OLD_SERVICE_HINTS = {
    "openssh": ("9.6", "CVE-2024-6387 (regreSSH) fixed in 9.8"),
    "apache": ("2.4.57", "multiple CVEs fixed in 2.4.58+"),
    "nginx": ("1.24.0", "older builds have known CVEs"),
    "proftpd": ("1.3.8", "known vulnerabilities"),
    "vsftpd": ("3.0.5", "older versions vulnerable"),
    "samba": ("4.18.0", "older versions have known CVEs"),
    "php": ("8.2.0", "older versions unsupported"),
    "mysql": ("8.0.34", "older versions have known CVEs"),
}

_WEB_ADMIN_TITLES = [
    "openwrt", "router", "routeros", "dd-wrt", "tomato", "luci",
    "pfsense", "opnsense", "unifi", "login", "admin", "dashboard",
    "control panel", "management", "console", "nas", "synology",
    "qnap", "printer", "camera",
]


def _service_product(host: Dict[str, Any], port: Dict[str, Any]) -> str:
    svc = port.get("service") or {}
    return f"{svc.get('name', '')} {svc.get('product', '')} {svc.get('version', '')}".strip().lower()


def _port_open(host: Dict[str, Any], portid: int) -> bool:
    for p in host.get("ports", []) or []:
        try:
            if int(p.get("portid", 0)) == portid:
                return p.get("state") in ("open", "Open")
        except (TypeError, ValueError):
            continue
    return False


def _find_port(host: Dict[str, Any], portid: int) -> Optional[Dict[str, Any]]:
    for p in host.get("ports", []) or []:
        try:
            if int(p.get("portid", 0)) == portid:
                return p
        except (TypeError, ValueError):
            continue
    return None


def _rule_legacy_protocol(host: Dict[str, Any]) -> Optional[str]:
    """Telnet(23) or FTP(21) open → plaintext credential exposure."""
    if _port_open(host, 23):
        return "Telnet (23) is open — credentials and traffic in plaintext"
    if _port_open(host, 21):
        return "FTP (21) is open — unencrypted file transfer"
    return None


def _rule_exposed_smb(host: Dict[str, Any]) -> Optional[str]:
    """SMB open → potential internal file share exposure."""
    if _port_open(host, 445):
        port = _find_port(host, 445)
        svc = (port or {}).get("service") or {}
        product = svc.get("product", "")
        return f"SMB (445) open{f' — {product}' if product else ''} — check share permissions"
    return None


def _rule_old_service(host: Dict[str, Any]) -> Optional[str]:
    """Known-vulnerable service versions → needs update."""
    for p in host.get("ports", []) or []:
        if p.get("state") not in ("open", "Open"):
            continue
        svc = p.get("service") or {}
        name = (svc.get("name") or "").lower()
        product = (svc.get("product") or "").lower()
        version = svc.get("version") or ""
        # Nmap service names differ from product names (ssh vs OpenSSH) — check both
        hint_key = None
        for candidate in (name, product, f"{name} {product}".strip()):
            for key in _OLD_SERVICE_HINTS:
                if key in candidate:
                    hint_key = key
                    break
            if hint_key:
                break
        if hint_key:
            base_ver, cve_note = _OLD_SERVICE_HINTS[hint_key]
            try:
                ver_num = tuple(int(x) for x in re.findall(r"\d+", version)[:3])
                base_num = tuple(int(x) for x in re.findall(r"\d+", base_ver)[:3])
                if version and ver_num < base_num:
                    return f"{product or name} {version} is old — {cve_note}"
                if not version:
                    return f"{product or name} version unknown on port {p.get('portid')} — fingerprint it"
            except Exception:
                pass
    return None


def _rule_web_admin(host: Dict[str, Any]) -> Optional[str]:
    """HTTP service with default admin-ish title → web console surface."""
    for p in host.get("ports", []) or []:
        if p.get("state") not in ("open", "Open"):
            continue
        svc = p.get("service") or {}
        if svc.get("name") not in ("http", "https", "http-proxy"):
            continue
        scripts = p.get("scripts") or []
        for script in scripts:
            title = (script.get("output") or "").lower()
            for kw in _WEB_ADMIN_TITLES:
                if kw in title:
                    return f"Web admin panel detected on port {p.get('portid')} (\"{script.get('output', '')[:40]}\")"
        product = _service_product(host, p)
        for kw in _WEB_ADMIN_TITLES:
            if kw in product:
                return f"Web service on port {p.get('portid')} looks like a management console ({product[:50]})"
    return None


def _rule_rdp_open(host: Dict[str, Any]) -> Optional[str]:
    """RDP exposed internally → remote desktop surface."""
    if _port_open(host, 3389):
        return "RDP (3389) open — remote desktop access surface"
    return None


def _rule_no_ports_but_live(host: Dict[str, Any]) -> Optional[str]:
    """Live host with zero open ports → quiet device worth a look."""
    if not host.get("ports") and host.get("status") == "up":
        return "Host is live but no open TCP ports found — could be firewall-heavy or IoT"
    return None


_RULES = [
    ("exposed file share", "rose", _rule_exposed_smb),
    ("legacy protocol", "amber", _rule_legacy_protocol),
    ("needs update", "amber", _rule_old_service),
    ("web console", "cyan", _rule_web_admin),
    ("remote desktop", "indigo", _rule_rdp_open),
    ("quiet host", "slate", _rule_no_ports_but_live),
]


def _new_device_check(host: Dict[str, Any], known_macs: set, known_ips: set) -> Optional[str]:
    """New MAC or IP never seen before → new device."""
    mac = host.get("mac")
    ip = host.get("ip") or host.get("ipv4")
    if mac and known_macs and mac.upper() not in known_macs:
        return f"MAC {mac} never seen in scan history"
    if ip and known_ips and ip not in known_ips:
        return f"IP {ip} is new — no previous record"
    return None


def suggest_tags_for_scan(
    scan_payload: Dict[str, Any],
    history_hosts: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Generate quiet tag suggestions for a completed scan.

    :param scan_payload: Normalized scan result from ScannerEngine.
    :param history_hosts: Optional list of hosts from previous scans (for "new device").
    :return: {"success": True, "suggestions": [{"ip", "hostname", "tag", "color", "reason"}], "count": N}
    """
    hosts = (scan_payload.get("data") or {}).get("hosts") or []
    if not hosts:
        return {"success": True, "suggestions": [], "count": 0}

    known_macs: set = set()
    known_ips: set = set()
    for h in history_hosts or []:
        if h.get("mac"):
            known_macs.add(h["mac"].upper())
        if h.get("ip") or h.get("ipv4"):
            known_ips.add(h["ip"] or h["ipv4"])

    suggestions: List[Dict[str, Any]] = []
    seen: set = set()  # (ip, tag) dedupe

    for host in hosts:
        ip = host.get("ip") or host.get("ipv4") or "unknown"
        hostname = host.get("primary_hostname") or host.get("hostname") or ""

        for tag, color, matcher in _RULES:
            try:
                reason = matcher(host)
            except Exception:
                logger.debug("tag rule %s crashed on %s", tag, ip, exc_info=True)
                reason = None
            if reason and (ip, tag) not in seen:
                seen.add((ip, tag))
                suggestions.append(
                    {
                        "ip": ip,
                        "hostname": hostname,
                        "tag": tag,
                        "color": color,
                        "reason": reason,
                    }
                )

        if history_hosts is not None:
            new_reason = _new_device_check(host, known_macs, known_ips)
            if new_reason and (ip, "new device") not in seen:
                seen.add((ip, "new device"))
                suggestions.append(
                    {
                        "ip": ip,
                        "hostname": hostname,
                        "tag": "new device",
                        "color": "emerald",
                        "reason": new_reason,
                    }
                )

    # Order: higher-severity tags first
    severity_order = {"rose": 0, "amber": 1, "cyan": 2, "indigo": 3, "emerald": 4, "slate": 5}
    suggestions.sort(key=lambda s: (severity_order.get(s["color"], 9), s["ip"]))

    return {"success": True, "suggestions": suggestions, "count": len(suggestions)}