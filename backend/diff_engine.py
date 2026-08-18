"""
backend/diff_engine.py - Network Scan Diff & Drift Comparison Engine

Compares two scan datasets (Baseline vs Comparison) to identify:
- New rogue devices joined to the network
- Decommissioned/offline devices
- Newly opened ports & exposed services
- Closed ports & version changes
"""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def compare_scans(scan_a: Dict[str, Any], scan_b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two scan snapshots (Scan A as baseline, Scan B as comparison).

    :param scan_a: Baseline scan dictionary (older).
    :param scan_b: Comparison scan dictionary (newer).
    :return: Normalized diff report dictionary.
    """
    hosts_a = {h.get("ip") or h.get("ipv4"): h for h in scan_a.get("data", {}).get("hosts", []) if h.get("ip") or h.get("ipv4")}
    hosts_b = {h.get("ip") or h.get("ipv4"): h for h in scan_b.get("data", {}).get("hosts", []) if h.get("ip") or h.get("ipv4")}

    ips_a = set(hosts_a.keys())
    ips_b = set(hosts_b.keys())

    added_ips = ips_b - ips_a
    removed_ips = ips_a - ips_b
    common_ips = ips_a & ips_b

    added_hosts: List[Dict[str, Any]] = [hosts_b[ip] for ip in sorted(added_ips)]
    removed_hosts: List[Dict[str, Any]] = [hosts_a[ip] for ip in sorted(removed_ips)]
    modified_hosts: List[Dict[str, Any]] = []
    unchanged_hosts: List[Dict[str, Any]] = []

    total_opened_ports = 0
    total_closed_ports = 0

    for ip in sorted(common_ips):
        ha = hosts_a[ip]
        hb = hosts_b[ip]

        # Extract port maps: port_id -> port_dict
        ports_a_map = {p.get("portid"): p for p in ha.get("ports", []) if p.get("portid")}
        ports_b_map = {p.get("portid"): p for p in hb.get("ports", []) if p.get("portid")}

        set_a = set(ports_a_map.keys())
        set_b = set(ports_b_map.keys())

        opened_port_ids = set_b - set_a
        closed_port_ids = set_a - set_b
        common_port_ids = set_a & set_b

        total_opened_ports += len(opened_port_ids)
        total_closed_ports += len(closed_port_ids)

        # Detect service version changes on common ports
        changed_services = []
        for pid in common_port_ids:
            pa = ports_a_map[pid]
            pb = ports_b_map[pid]

            svca = pa.get("service", {})
            svcb = pb.get("service", {})

            prod_a = f"{svca.get('name', '')} {svca.get('product', '')} {svca.get('version', '')}".strip()
            prod_b = f"{svcb.get('name', '')} {svcb.get('product', '')} {svcb.get('version', '')}".strip()

            if prod_a != prod_b:
                changed_services.append({
                    "port": pid,
                    "protocol": pb.get("protocol", "tcp"),
                    "before": prod_a or "unknown",
                    "after": prod_b or "unknown",
                })

        os_a = ha.get("primary_os") or "Unknown"
        os_b = hb.get("primary_os") or "Unknown"
        os_changed = (os_a != os_b) and (os_a != "Unknown" and os_b != "Unknown")

        is_modified = bool(opened_port_ids or closed_port_ids or changed_services or os_changed)

        if is_modified:
            modified_hosts.append({
                "ip": ip,
                "hostname": hb.get("primary_hostname") or ha.get("primary_hostname") or "",
                "mac": hb.get("mac") or ha.get("mac") or "",
                "vendor": hb.get("vendor") or ha.get("vendor") or "",
                "opened_ports": [ports_b_map[pid] for pid in sorted(opened_port_ids)],
                "closed_ports": [ports_a_map[pid] for pid in sorted(closed_port_ids)],
                "changed_services": changed_services,
                "os_before": os_a,
                "os_after": os_b,
                "os_changed": os_changed,
            })
        else:
            unchanged_hosts.append(hb)

    drift_detected = bool(added_hosts or removed_hosts or modified_hosts)

    return {
        "success": True,
        "drift_detected": drift_detected,
        "summary": {
            "baseline_hosts_count": len(hosts_a),
            "comparison_hosts_count": len(hosts_b),
            "added_hosts_count": len(added_hosts),
            "removed_hosts_count": len(removed_hosts),
            "modified_hosts_count": len(modified_hosts),
            "unchanged_hosts_count": len(unchanged_hosts),
            "total_opened_ports": total_opened_ports,
            "total_closed_ports": total_closed_ports,
        },
        "added_hosts": added_hosts,
        "removed_hosts": removed_hosts,
        "modified_hosts": modified_hosts,
        "unchanged_hosts": unchanged_hosts,
    }
