"""
backend/asset_db.py - Persistent SQLite Asset Inventory & Tagging Store

Stores custom user metadata (alias, owner, tags, notes, risk level) keyed by MAC address or IP.
Automatically enriches scan results across sessions.
"""

import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DB_FILE = os.path.join(os.path.abspath(os.path.dirname(os.path.dirname(__file__))), "assets.db")


class AssetDatabase:
    """
    Local SQLite database for managing persistent network asset metadata.
    """

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create assets table if it does not exist."""
        conn = self._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    key TEXT PRIMARY KEY,
                    mac TEXT,
                    ip TEXT,
                    alias TEXT,
                    owner TEXT,
                    tags TEXT,
                    notes TEXT,
                    risk_level TEXT DEFAULT 'LOW',
                    updated_at REAL
                )
            """)
            conn.commit()
        except Exception as e:
            logger.exception(f"Failed to initialize SQLite asset database at {self.db_path}: {e}")
        finally:
            conn.close()

    def save_asset(
        self,
        ip: str,
        mac: Optional[str] = None,
        alias: str = "",
        owner: str = "",
        tags: Optional[List[str]] = None,
        notes: str = "",
        risk_level: str = "LOW",
    ) -> Dict[str, Any]:
        """
        Save or update asset metadata. Uses MAC as primary key if available, otherwise IP.
        """
        key = (mac.strip().upper() if mac and mac.strip() else ip.strip()).lower()
        if not key:
            raise ValueError("Either MAC address or IP is required to identify an asset.")

        tags_json = json.dumps(tags if isinstance(tags, list) else [t.strip() for t in str(tags).split(",") if t.strip()])
        now = time.time()

        conn = self._get_connection()
        try:
            conn.execute("""
                INSERT INTO assets (key, mac, ip, alias, owner, tags, notes, risk_level, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    mac=excluded.mac,
                    ip=excluded.ip,
                    alias=excluded.alias,
                    owner=excluded.owner,
                    tags=excluded.tags,
                    notes=excluded.notes,
                    risk_level=excluded.risk_level,
                    updated_at=excluded.updated_at
            """, (key, mac or "", ip or "", alias or "", owner or "", tags_json, notes or "", risk_level.upper() or "LOW", now))
            conn.commit()
        finally:
            conn.close()

        return self.get_asset(ip=ip, mac=mac) or {}

    def get_asset(self, ip: Optional[str] = None, mac: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieve asset metadata by MAC address (first) or IP address.
        """
        key = None
        if mac and mac.strip():
            key = mac.strip().lower()
        elif ip and ip.strip():
            key = ip.strip().lower()

        if not key:
            return None

        conn = self._get_connection()
        try:
            cursor = conn.execute("SELECT * FROM assets WHERE key = ?", (key,))
            row = cursor.fetchone()

            if not row and ip:
                cursor = conn.execute("SELECT * FROM assets WHERE ip = ?", (ip.strip(),))
                row = cursor.fetchone()

            if row:
                return self._row_to_dict(row)
        finally:
            conn.close()
        return None

    def get_all_assets(self) -> List[Dict[str, Any]]:
        """Return all saved assets."""
        conn = self._get_connection()
        try:
            cursor = conn.execute("SELECT * FROM assets ORDER BY updated_at DESC")
            return [self._row_to_dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()

    def delete_asset(self, key: str) -> bool:
        """Delete an asset by key."""
        conn = self._get_connection()
        try:
            cursor = conn.execute("DELETE FROM assets WHERE key = ? OR ip = ? OR mac = ?", (key.lower(), key, key))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def enrich_host(self, host_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inject saved alias, owner, tags, notes, and risk level into a parsed host dict.
        """
        ip = host_dict.get("ip") or host_dict.get("ipv4")
        mac = host_dict.get("mac")
        asset = self.get_asset(ip=ip, mac=mac)

        if asset:
            host_dict["alias"] = asset.get("alias", "")
            host_dict["owner"] = asset.get("owner", "")
            host_dict["tags"] = asset.get("tags", [])
            host_dict["notes"] = asset.get("notes", "")
            host_dict["risk_level"] = asset.get("risk_level", "LOW")
        else:
            host_dict.setdefault("alias", "")
            host_dict.setdefault("owner", "")
            host_dict.setdefault("tags", [])
            host_dict.setdefault("notes", "")
            host_dict.setdefault("risk_level", "LOW")

        return host_dict

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        try:
            d["tags"] = json.loads(d.get("tags") or "[]")
        except Exception:
            d["tags"] = []
        return d
