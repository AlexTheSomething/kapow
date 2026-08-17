"""
backend/host_timeline.py - Per-host history reconstruction.

Rebuilds a host's lifecycle from persisted scan history:
- first seen / last seen timestamps
- port state at each scan (open/closed changes over time)
- service version changes
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _find_host(payload: Dict[str, Any], ip: str) -> Optional[Dict[str, Any]]:
    hosts = (payload.get("data") or {}).get("hosts") or []
    for h in hosts:
        if (h.get("ip") or h.get("ipv4")) == ip:
            return h
    return None


def build_host_timeline(
    scan_store,
    ip: str,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Reconstruct a host's history from ScanStore.

    :param scan_store: ScanStore instance (has list_scans / get_scan).
    :param ip: Target IP.
    :param limit: Max scans to walk back through.
    :return: {
        "success": True,
        "ip": ip,
        "first_seen_at": ts | None,
        "last_seen_at": ts | None,
        "scan_count": int,
        "events": [{"ts", "type", "detail"}...]  # chronological
        "port_history": [{"ts", "open_ports": [...]}...]  # chronological
    }
    """
    try:
        scans = scan_store.list_scans(limit=limit)  # newest first
        scans.reverse()  # chronological order

        first_seen: Optional[float] = None
        last_seen: Optional[float] = None
        scan_count = 0
        events: List[Dict[str, Any]] = []
        port_history: List[Dict[str, Any]] = []
        prev_open_ports: Optional[set] = None
        prev_services: Dict[str, str] = {}

        for meta in scans:
            payload = scan_store.get_scan(meta["id"])
            if not payload:
                continue
            host = _find_host(payload, ip)
            ts = meta.get("created_at") or payload.get("_created_at") or 0

            if host is None:
                # Host absent in this scan — if we'd seen it before, it went offline
                if prev_open_ports is not None:
                    events.append({
                        "ts": ts,
                        "type": "offline",
                        "detail": f"Host not present in scan {meta['id']} (offline or filtered)",
                    })
                    prev_open_ports = None
                continue

            # First time we see it
            if first_seen is None:
                first_seen = ts
                events.append({
                    "ts": ts,
                    "type": "first_seen",
                    "detail": f"First observed in scan {meta['id']}",
                })
            last_seen = ts
            scan_count += 1

            open_ports = {
                str(p.get("portid"))
                for p in (host.get("ports") or [])
                if (p.get("state") or "").lower() == "open" and p.get("portid") is not None
            }
            port_history.append({"ts": ts, "open_ports": sorted(open_ports, key=lambda x: int(x) if x.isdigit() else 0)})

            if prev_open_ports is not None:
                opened = open_ports - prev_open_ports
                closed = prev_open_ports - open_ports
                if opened:
                    events.append({
                        "ts": ts,
                        "type": "ports_opened",
                        "detail": f"Opened port(s): {', '.join(sorted(opened, key=lambda x: int(x) if x.isdigit() else 0))}",
                    })
                if closed:
                    events.append({
                        "ts": ts,
                        "type": "ports_closed",
                        "detail": f"Closed port(s): {', '.join(sorted(closed, key=lambda x: int(x) if x.isdigit() else 0))}",
                    })

            # Service version changes
            cur_services = {}
            for p in (host.get("ports") or []):
                if (p.get("state") or "").lower() != "open":
                    continue
                pid = str(p.get("portid"))
                svc = p.get("service") or {}
                ver = f"{svc.get('name', '')} {svc.get('product', '')} {svc.get('version', '')}".strip()
                cur_services[pid] = ver
            if prev_open_ports is not None:
                for pid in open_ports & set(prev_services.keys()):
                    if pid in cur_services and pid in prev_services and cur_services[pid] != prev_services[pid]:
                        events.append({
                            "ts": ts,
                            "type": "service_changed",
                            "detail": f"Port {pid} service changed: '{prev_services[pid]}' → '{cur_services[pid]}'",
                        })
            prev_services = cur_services
            prev_open_ports = open_ports

        return {
            "success": True,
            "ip": ip,
            "first_seen_at": first_seen,
            "last_seen_at": last_seen,
            "scan_count": scan_count,
            "events": events,
            "port_history": port_history,
        }
    except Exception as e:
        logger.exception("build_host_timeline failed:")
        return {"success": False, "error": str(e)}