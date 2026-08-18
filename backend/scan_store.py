"""
backend/scan_store.py - Persistent scan snapshot history (SQLite)

Stores compact scan results so Scan Diff survives app restarts.
Caps retention to avoid unbounded growth.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

from backend.asset_db import DB_FILE

logger = logging.getLogger(__name__)

DEFAULT_MAX_SCANS = 50


class ScanStore:
    """SQLite-backed scan history (shares assets.db file, separate table)."""

    def __init__(self, db_path: str = DB_FILE, max_scans: int = DEFAULT_MAX_SCANS):
        self.db_path = db_path
        self.max_scans = max(5, int(max_scans))
        self._init_db()

    def _get_connection(self):
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    target TEXT NOT NULL,
                    scan_profile TEXT,
                    hosts_count INTEGER DEFAULT 0,
                    payload_json TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_history_created ON scan_history(created_at DESC)"
            )
            conn.commit()
        except Exception as e:
            logger.exception("Failed to init scan_history table: %s", e)
        finally:
            conn.close()

    @staticmethod
    def _compact_payload(scan_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Keep fields needed for Diff/UI; drop bulky cytoscape/ag_grid/logs."""
        data = scan_payload.get("data") or {}
        return {
            "success": True,
            "target": scan_payload.get("target", ""),
            "scan_profile": scan_payload.get("scan_profile", ""),
            "data": {
                "metadata": data.get("metadata") or {},
                "summary": data.get("summary") or {},
                "hosts": data.get("hosts") or [],
            },
            # Keep XML for re-export; may be large but useful
            "raw_xml": scan_payload.get("raw_xml") or "",
            "is_sample": bool(scan_payload.get("is_sample")),
        }

    def save_scan(self, scan_payload: Dict[str, Any]) -> Dict[str, Any]:
        if not scan_payload or not scan_payload.get("success"):
            return {"success": False, "error": "Refusing to persist unsuccessful scan."}

        compact = self._compact_payload(scan_payload)
        hosts_count = len((compact.get("data") or {}).get("hosts") or [])
        target = compact.get("target") or "unknown"
        profile = compact.get("scan_profile") or ""
        now = time.time()

        conn = self._get_connection()
        try:
            cur = conn.execute(
                """
                INSERT INTO scan_history (created_at, target, scan_profile, hosts_count, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (now, target, profile, hosts_count, json.dumps(compact)),
            )
            scan_id = cur.lastrowid
            # Enforce retention cap
            conn.execute(
                """
                DELETE FROM scan_history
                WHERE id NOT IN (
                    SELECT id FROM scan_history ORDER BY created_at DESC LIMIT ?
                )
                """,
                (self.max_scans,),
            )
            conn.commit()
            return {
                "success": True,
                "id": scan_id,
                "created_at": now,
                "target": target,
                "scan_profile": profile,
                "hosts_count": hosts_count,
            }
        except Exception as e:
            logger.exception("save_scan failed:")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), self.max_scans))
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """
                SELECT id, created_at, target, scan_profile, hosts_count
                FROM scan_history
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT id, created_at, target, scan_profile, hosts_count, payload_json FROM scan_history WHERE id = ?",
                (int(scan_id),),
            ).fetchone()
            if not row:
                return None
            payload = json.loads(row["payload_json"])
            payload["_history_id"] = row["id"]
            payload["_created_at"] = row["created_at"]
            return payload
        except Exception as e:
            logger.exception("get_scan failed:")
            return None
        finally:
            conn.close()

    def delete_scan(self, scan_id: int) -> bool:
        conn = self._get_connection()
        try:
            cur = conn.execute("DELETE FROM scan_history WHERE id = ?", (int(scan_id),))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def clear(self) -> int:
        conn = self._get_connection()
        try:
            cur = conn.execute("DELETE FROM scan_history")
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()
