"""
backend/alerts.py - Change detection alerts.

Compares a new scan against the most recent previous scan and generates
actionable alerts: new devices, offline devices, newly opened ports on
tagged hosts. Alerts are persisted to a small SQLite table (shares assets.db)
and surfaced in the UI as a quiet notification bell.

Alerts are the payoff for scheduled scans: run Kapow, walk away, and it
tells you when your network changed.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets.db")


class AlertStore:
    """SQLite-backed queue of change alerts."""

    def __init__(self, db_path: str = DB_FILE, max_alerts: int = 200):
        self.db_path = db_path
        self.max_alerts = max_alerts
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    kind TEXT NOT NULL,          -- 'new_device' | 'device_offline' | 'port_opened' | 'port_closed' | 'service_changed'
                    severity TEXT NOT NULL,      -- 'info' | 'warning' | 'critical'
                    host_ip TEXT,
                    hostname TEXT,
                    title TEXT NOT NULL,
                    detail TEXT,
                    read INTEGER DEFAULT 0
                )
            """)
            conn.commit()
        except Exception:
            logger.exception("Failed to init alerts table")
        finally:
            conn.close()

    def add_alert(self, kind: str, severity: str, title: str, host_ip: str = "", hostname: str = "", detail: str = "") -> Optional[int]:
        conn = self._get_connection()
        try:
            cur = conn.execute(
                """
                INSERT INTO alerts (created_at, kind, severity, host_ip, hostname, title, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (time.time(), kind, severity, host_ip, hostname, title, detail),
            )
            # Prune old alerts
            conn.execute(
                """
                DELETE FROM alerts WHERE id NOT IN (
                    SELECT id FROM alerts ORDER BY created_at DESC LIMIT ?
                )
                """,
                (self.max_alerts,),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def list_alerts(self, unread_only: bool = False, limit: int = 50) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            query = "SELECT * FROM alerts"
            if unread_only:
                query += " WHERE read = 0"
            query += " ORDER BY created_at DESC LIMIT ?"
            rows = conn.execute(query, (min(limit, self.max_alerts),)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def unread_count(self) -> int:
        conn = self._get_connection()
        try:
            row = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE read = 0").fetchone()
            return row["c"] if row else 0
        finally:
            conn.close()

    def mark_all_read(self) -> int:
        conn = self._get_connection()
        try:
            cur = conn.execute("UPDATE alerts SET read = 1 WHERE read = 0")
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()


def _host_map(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """ip → host dict."""
    hosts = (payload.get("data") or {}).get("hosts") or []
    result = {}
    for h in hosts:
        ip = h.get("ip") or h.get("ipv4")
        if ip:
            result[ip] = h
    return result


def _port_map(host: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """portid → port dict (open ports only)."""
    result = {}
    for p in host.get("ports") or []:
        pid = p.get("portid")
        state = (p.get("state") or "").lower()
        if pid is not None and state == "open":
            result[str(pid)] = p
    return result


def _tagged(host: Dict[str, Any]) -> bool:
    tags = host.get("tags") or []
    return len(tags) > 0


def generate_alerts(
    new_payload: Dict[str, Any],
    previous_payload: Optional[Dict[str, Any]],
    store: AlertStore,
) -> List[Dict[str, Any]]:
    """
    Compare a new scan against the previous scan and store alerts.
    Returns the list of generated alerts.
    """
    alerts: List[Dict[str, Any]] = []

    new_hosts = _host_map(new_payload)
    prev_hosts = _host_map(previous_payload) if previous_payload else {}

    if not previous_payload:
        # First scan ever — no diff baseline, but note scan completion is not an alert.
        return alerts

    prev_ips = set(prev_hosts.keys())
    new_ips = set(new_hosts.keys())

    # 1. New devices
    for ip in sorted(new_ips - prev_ips):
        h = new_hosts[ip]
        hostname = h.get("primary_hostname") or h.get("hostname") or ""
        title = f"New device on network: {ip}"
        detail = f"Host {ip}" + (f" ({hostname})" if hostname else "") + " was not present in the previous scan."
        store.add_alert("new_device", "warning", title, host_ip=ip, hostname=hostname, detail=detail)
        alerts.append({"kind": "new_device", "severity": "warning", "title": title, "host_ip": ip})

    # 2. Devices that went offline
    for ip in sorted(prev_ips - new_ips):
        h = prev_hosts[ip]
        hostname = h.get("primary_hostname") or h.get("hostname") or ""
        title = f"Device offline: {ip}"
        detail = f"Host {ip}" + (f" ({hostname})" if hostname else "") + " no longer responds."
        store.add_alert("device_offline", "info", title, host_ip=ip, hostname=hostname, detail=detail)
        alerts.append({"kind": "device_offline", "severity": "info", "title": title, "host_ip": ip})

    # 3. Port changes on hosts present in both scans
    for ip in sorted(new_ips & prev_ips):
        nh = new_hosts[ip]
        ph = prev_hosts[ip]
        np_map = _port_map(nh)
        pp_map = _port_map(ph)
        hostname = nh.get("primary_hostname") or nh.get("hostname") or ""

        opened = set(np_map.keys()) - set(pp_map.keys())
        closed = set(pp_map.keys()) - set(np_map.keys())

        if opened and _tagged(nh):
            ports_list = ", ".join(sorted(opened))
            title = f"New ports opened on tagged host {ip}: {ports_list}"
            detail = f"Host {ip} has newly opened port(s) {ports_list}."
            store.add_alert("port_opened", "critical", title, host_ip=ip, hostname=hostname, detail=detail)
            alerts.append({"kind": "port_opened", "severity": "critical", "title": title, "host_ip": ip})
        elif opened:
            ports_list = ", ".join(sorted(opened))
            title = f"New ports opened on {ip}: {ports_list}"
            detail = f"Host {ip} has newly opened port(s) {ports_list}."
            store.add_alert("port_opened", "warning", title, host_ip=ip, hostname=hostname, detail=detail)
            alerts.append({"kind": "port_opened", "severity": "warning", "title": title, "host_ip": ip})

        if closed and _tagged(ph):
            ports_list = ", ".join(sorted(closed))
            title = f"Ports closed on tagged host {ip}: {ports_list}"
            store.add_alert("port_closed", "info", title, host_ip=ip, hostname=hostname, detail=f"Port(s) {ports_list} closed on {ip}.")
            alerts.append({"kind": "port_closed", "severity": "info", "title": title, "host_ip": ip})

    return alerts


def check_for_changes(
    new_payload: Dict[str, Any],
    previous_payload: Optional[Dict[str, Any]],
    store: AlertStore,
) -> Dict[str, Any]:
    """
    Wrapper that generates alerts and returns a summary for the UI.
    """
    try:
        alerts = generate_alerts(new_payload, previous_payload, store)
        return {
            "success": True,
            "change_count": len(alerts),
            "alerts": alerts,
        }
    except Exception as e:
        logger.exception("check_for_changes failed:")
        return {"success": False, "error": str(e), "change_count": 0, "alerts": []}