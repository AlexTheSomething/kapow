"""
backend/cve_lookup.py - Automated CVE & Vulnerability Cross-Referencing Engine

Matches discovered services, CPEs, and software versions with known CVE vulnerability records.
Provides CVSS severity scores, descriptions, and patch remediation advice.
"""

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Curated high-impact vulnerability database keyed by software pattern
CVE_KNOWLEDGE_BASE = [
    # OpenSSH
    {
        "pattern": r"openssh\s*(?:[^\d]*)\s*(\d+\.\d+)",
        "product_match": ["openssh", "ssh"],
        "rules": [
            {
                "version_max": "9.7",
                "version_min": "9.2",
                "cve_id": "CVE-2024-6387",
                "cvss": 8.1,
                "severity": "HIGH",
                "title": "regreSSHion: Remote Unauthenticated Code Execution",
                "summary": "Signal handler race condition in OpenSSH's server (sshd) allows unauthenticated remote code execution with root privileges on glibc-based Linux systems.",
                "remediation": "Upgrade OpenSSH to version >= 9.8p1.",
            },
            {
                "version_max": "9.3",
                "version_min": "5.5",
                "cve_id": "CVE-2023-38408",
                "cvss": 9.8,
                "severity": "CRITICAL",
                "title": "OpenSSH PKCS#11 Provider Remote Code Execution",
                "summary": "Condition in ssh-agent PKCS#11 provider support allows remote code execution when agent forwarding is enabled.",
                "remediation": "Upgrade OpenSSH to version >= 9.3p2.",
            },
            {
                "version_max": "7.4",
                "version_min": "5.0",
                "cve_id": "CVE-2016-0777",
                "cvss": 7.5,
                "severity": "HIGH",
                "title": "OpenSSH Client Information Disclosure (Roaming)",
                "summary": "Resend code in roaming feature leaks client memory to malicious servers.",
                "remediation": "Disable UseRoaming in ssh_config or upgrade to OpenSSH >= 7.2.",
            }
        ]
    },
    # Apache HTTPD
    {
        "pattern": r"apache(?:_http_server)?\s*[/:]?\s*(\d+\.\d+\.\d+)",
        "product_match": ["apache", "httpd"],
        "rules": [
            {
                "version_max": "2.4.49",
                "version_min": "2.4.49",
                "cve_id": "CVE-2021-41773",
                "cvss": 7.5,
                "severity": "HIGH",
                "title": "Apache Path Traversal & Remote Code Execution",
                "summary": "Path traversal flaw in Apache HTTP Server 2.4.49 allows mapping URLs to files outside the document root.",
                "remediation": "Upgrade Apache HTTP Server to version >= 2.4.51.",
            },
            {
                "version_max": "2.4.50",
                "version_min": "2.4.50",
                "cve_id": "CVE-2021-42013",
                "cvss": 9.8,
                "severity": "CRITICAL",
                "title": "Apache Incomplete Fix Path Traversal & RCE",
                "summary": "Incomplete fix for CVE-2021-41773 allows remote code execution if mod_cgi is enabled.",
                "remediation": "Upgrade Apache HTTP Server to version >= 2.4.51.",
            }
        ]
    },
    # Microsoft SMB & RPC
    {
        "pattern": r"microsoft|windows|smb",
        "product_match": ["microsoft-ds", "smb", "windows 10", "windows 11", "windows server"],
        "rules": [
            {
                "version_max": "10.0.19041",
                "version_min": "10.0.0",
                "cve_id": "CVE-2020-0796",
                "cvss": 10.0,
                "severity": "CRITICAL",
                "title": "SMBGhost: Windows SMBv3 Remote Code Execution",
                "summary": "Vulnerability in Windows SMBv3 compression handling allows remote unauthenticated code execution via specially crafted packets.",
                "remediation": "Apply Microsoft Security Bulletin MS20-0796 or disable SMBv3 compression.",
            },
            {
                "version_max": "999.0",
                "version_min": "0.0",
                "port_match": [445, 139],
                "cve_id": "CVE-2017-0144",
                "cvss": 9.8,
                "severity": "CRITICAL",
                "title": "EternalBlue: SMBv1 Remote Code Execution",
                "summary": "Flaw in Microsoft SMBv1 protocol handling allows remote execution of arbitrary code (WannaCry / NotPetya vector).",
                "remediation": "Disable SMBv1 and apply Microsoft patch MS17-010.",
            }
        ]
    },
    # ProFTPD
    {
        "pattern": r"proftpd\s*(\d+\.\d+\.\d+)",
        "product_match": ["proftpd", "ftp"],
        "rules": [
            {
                "version_max": "1.3.5",
                "version_min": "1.3.0",
                "cve_id": "CVE-2015-3306",
                "cvss": 9.8,
                "severity": "CRITICAL",
                "title": "ProFTPD mod_copy Arbitrary File Copy & Execution",
                "summary": "mod_copy in ProFTPD allows unauthenticated remote attackers to read and write arbitrary files via SITE CPFR/CPTO commands.",
                "remediation": "Upgrade ProFTPD to >= 1.3.5a or disable mod_copy module.",
            }
        ]
    },
    # Dnsmasq
    {
        "pattern": r"dnsmasq\s*(\d+\.\d+)",
        "product_match": ["dnsmasq", "domain"],
        "rules": [
            {
                "version_max": "2.82",
                "version_min": "2.0",
                "cve_id": "CVE-2020-25681",
                "cvss": 8.1,
                "severity": "HIGH",
                "title": "DNSpooq: Dnsmasq DNS Cache Poisoning",
                "summary": "Weakness in DNS query ID and source port randomization allows remote DNS cache poisoning.",
                "remediation": "Upgrade dnsmasq to version >= 2.83.",
            }
        ]
    },
    # uhttpd / OpenWrt
    {
        "pattern": r"uhttpd|openwrt",
        "product_match": ["uhttpd", "openwrt"],
        "rules": [
            {
                "version_max": "2020",
                "version_min": "2010",
                "cve_id": "CVE-2020-8597",
                "cvss": 9.8,
                "severity": "CRITICAL",
                "title": "pppd EAP Buffer Overflow in Embedded Linux / OpenWrt",
                "summary": "Buffer overflow vulnerability in Point-to-Point Protocol Daemon allows unauthenticated remote code execution.",
                "remediation": "Upgrade OpenWrt firmware to latest stable release.",
            }
        ]
    }
]


def _parse_version_tuple(v_str: str) -> tuple:
    """Convert version string like '9.6p1' or '2.4.49' into integer tuple for comparison."""
    digits = re.findall(r'\d+', str(v_str))
    return tuple(int(d) for d in digits) if digits else (0,)


def lookup_cves(
    service_name: str = "",
    product: str = "",
    version: str = "",
    port: Optional[int] = None,
    cpe_list: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Search CVE knowledge base for vulnerabilities matching service, product, version, and CPE tags.

    :return: List of CVE vulnerability dictionaries sorted by CVSS score descending.
    """
    found_cves: List[Dict[str, Any]] = []
    seen_ids = set()

    search_blob = f"{service_name} {product} {version} {' '.join(cpe_list or [])}".lower()
    target_v_tuple = _parse_version_tuple(version) if version else None

    for entry in CVE_KNOWLEDGE_BASE:
        product_matched = any(p in search_blob for p in entry["product_match"])
        if not product_matched:
            continue

        for rule in entry["rules"]:
            cve_id = rule["cve_id"]
            if cve_id in seen_ids:
                continue

            # Check port restriction if specified in rule
            if "port_match" in rule and port is not None:
                if port not in rule["port_match"]:
                    continue

            # Check version range
            if target_v_tuple:
                min_tup = _parse_version_tuple(rule.get("version_min", "0"))
                max_tup = _parse_version_tuple(rule.get("version_max", "9999"))
                if min_tup <= target_v_tuple <= max_tup:
                    seen_ids.add(cve_id)
                    found_cves.append(rule)
            else:
                # If no version specified, include if product strongly matched
                if rule.get("severity") in ("CRITICAL", "HIGH") and ("port_match" in rule or len(product) > 4):
                    seen_ids.add(cve_id)
                    found_cves.append(rule)

    # Sort descending by CVSS score
    return sorted(found_cves, key=lambda x: x.get("cvss", 0.0), reverse=True)


def enrich_scan_with_cves(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich entire parsed scan payload with CVE vulnerability records and calculate host risk ratings.
    """
    hosts = scan_data.get("data", {}).get("hosts", [])
    ag_grid_rows = scan_data.get("ag_grid", [])

    # Map grid rows by id
    grid_map = {row.get("id"): row for row in ag_grid_rows}

    for host in hosts:
        host_cves = []
        host_highest_cvss = 0.0

        for p in host.get("ports", []):
            svc = p.get("service", {})
            portid = p.get("portid")
            cpes = svc.get("cpe", []) if isinstance(svc.get("cpe"), list) else [svc.get("cpe")] if svc.get("cpe") else []

            cves = lookup_cves(
                service_name=svc.get("name", ""),
                product=svc.get("product", ""),
                version=svc.get("version", ""),
                port=portid,
                cpe_list=cpes,
            )

            p["cves"] = cves
            for c in cves:
                host_cves.append(c)
                if c.get("cvss", 0) > host_highest_cvss:
                    host_highest_cvss = c.get("cvss", 0)

            # Update AG Grid row record
            row_id = f"host-{host.get('ip')}-port-{portid}-{p.get('protocol', 'tcp')}"
            if row_id in grid_map:
                grid_map[row_id]["cves"] = cves
                grid_map[row_id]["cve_count"] = len(cves)
                grid_map[row_id]["max_cvss"] = cves[0].get("cvss") if cves else None
                grid_map[row_id]["severity"] = cves[0].get("severity") if cves else None

        host["cves"] = host_cves
        host["max_cvss"] = host_highest_cvss

        # Determine automated risk level if not set
        if host_highest_cvss >= 9.0:
            auto_risk = "CRITICAL"
        elif host_highest_cvss >= 7.0:
            auto_risk = "HIGH"
        elif host_highest_cvss >= 4.0:
            auto_risk = "MEDIUM"
        else:
            auto_risk = "LOW"

        host.setdefault("risk_level", auto_risk)

    return scan_data
