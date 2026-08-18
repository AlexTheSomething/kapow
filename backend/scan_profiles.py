"""
backend/scan_profiles.py - User-defined custom scan profiles.

Stores custom nmap argument presets in the shared SQLite database.
Arguments are stored as JSON arrays (always a list, never a raw shell string).
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

# Shell metacharacters that must never appear in profile args
_FORBIDDEN_CHARS = {";", "|", "&", ">", "<", "$", "`", "(", ")", "\n", "\r"}


class CustomProfileStore:
    """SQLite-backed store for user-defined scan profiles."""

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS custom_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    args_json TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    created_at REAL NOT NULL
                )
            """)
            conn.commit()
        except Exception:
            logger.exception("Failed to init custom_profiles table")
        finally:
            conn.close()

    @staticmethod
    def validate_args(args: List[str]) -> Optional[str]:
        """Return an error message if args contain forbidden shell chars, else None."""
        if not isinstance(args, list):
            return "args must be a list of strings"
        for i, arg in enumerate(args):
            if not isinstance(arg, str):
                return f"arg[{i}] is not a string"
            for ch in arg:
                if ch in _FORBIDDEN_CHARS:
                    return f"arg[{i}] contains forbidden character: {repr(ch)}"
        return None

    def save_profile(self, name: str, based_on_profile_id: str, description: str = "") -> Dict[str, Any]:
        """Save a custom profile that aliases a built-in or existing profile."""
        name = name.strip()
        if not name:
            return {"success": False, "error": "Profile name cannot be empty."}
        if not based_on_profile_id or not based_on_profile_id.strip():
            return {"success": False, "error": "Must reference a profile."}
        # resolve the actual args (\"" will be resolved at scan time)
        conn = self._get_connection()
        try:
            cur = conn.execute(
                "INSERT INTO custom_profiles (name, args_json, description, created_at) VALUES (?, ?, ?, ?)",
                (name, json.dumps([based_on_profile_id.strip()]), description, time.time()),
            )
            conn.commit()
            return {"success": True, "id": cur.lastrowid, "name": name}
        except sqlite3.IntegrityError:
            return {"success": False, "error": f"A profile named '{name}' already exists."}
        finally:
            conn.close()

    def list_profiles(self) -> List[Dict[str, Any]]:
        """List all custom profiles."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT id, name, args_json, description, created_at FROM custom_profiles ORDER BY name"
            ).fetchall()
            result = []
            for r in rows:
                try:
                    args = json.loads(r["args_json"])
                except Exception:
                    args = []
                result.append(
                    {
                        "id": r["id"],
                        "name": r["name"],
                        "args": args,
                        "description": r["description"] or "",
                        "created_at": r["created_at"],
                    }
                )
            return result
        finally:
            conn.close()

    def get_profile(self, profile_id: int) -> Optional[Dict[str, Any]]:
        """Get a single profile by id."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT id, name, args_json, description FROM custom_profiles WHERE id = ?", (int(profile_id),)
            ).fetchone()
            if not row:
                return None
            try:
                args = json.loads(row["args_json"])
            except Exception:
                args = []
            return {
                "id": row["id"],
                "name": row["name"],
                "args": args,
                "description": row["description"] or "",
            }
        finally:
            conn.close()

    def delete_profile(self, profile_id: int) -> bool:
        """Delete a custom profile by id. Returns True if deleted."""
        conn = self._get_connection()
        try:
            cur = conn.execute("DELETE FROM custom_profiles WHERE id = ?", (int(profile_id),))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()