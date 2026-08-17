"""
backend/scheduler.py - Background scan scheduler.

Supports periodic LAN scanning on a configurable interval. Stores config
as a simple JSON file. When a scheduled scan fires, it runs through the
normal scanner pipeline and persists the result via ScanStore.

Exposes simple start/stop/status control for the Settings UI.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "schedule.json")


@dataclass
class ScheduleConfig:
    enabled: bool = False
    interval_minutes: int = 30
    target: str = "192.168.1.0/24"
    scan_profile: str = "quick"
    last_run_at: float = 0.0
    last_run_success: bool = False
    last_result_summary: str = ""


class ScanScheduler:
    """
    Background scheduler that polls every 60s and fires a scan when
    the configured interval has elapsed since the last run.
    """

    def __init__(self, scan_callback: Callable[[str, str], Dict[str, Any]]):
        """
        :param scan_callback: async-style callback that returns scan result dict.
                              Called as scan_callback(target, scan_profile).
        """
        self._callback = scan_callback
        self._config = ScheduleConfig()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._load_config()

    # ── config persistence ──

    def _load_config(self):
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._config = ScheduleConfig(**{k: v for k, v in data.items() if k in ScheduleConfig.__dataclass_fields__})
        except Exception:
            logger.debug("No saved schedule config, using defaults.")

    def _save_config(self):
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(asdict(self._config), f, indent=2)
        except Exception:
            logger.exception("Failed to save schedule config.")

    # ── public API ──

    def get_config(self) -> Dict[str, Any]:
        with self._lock:
            return asdict(self._config)

    def set_config(self, enabled: Optional[bool] = None, interval_minutes: Optional[int] = None, target: Optional[str] = None, scan_profile: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if enabled is not None:
                self._config.enabled = enabled
            if interval_minutes is not None and interval_minutes >= 1:
                self._config.interval_minutes = int(interval_minutes)
            if target is not None:
                self._config.target = target.strip() or self._config.target
            if scan_profile is not None:
                self._config.scan_profile = scan_profile
            self._save_config()

        # If just enabled, restart the timer thread
        if self._config.enabled and not self._running:
            self.start()
        elif not self._config.enabled and self._running:
            self.stop()

        return asdict(self._config)

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="kapow-scheduler")
        self._thread.start()
        logger.info("Scan scheduler started (interval: %dm, target: %s)", self._config.interval_minutes, self._config.target)

    def stop(self):
        with self._lock:
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("Scan scheduler stopped.")

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            c = self._config
            next_run = (c.last_run_at + c.interval_minutes * 60) if c.last_run_at > 0 else time.time()
            return {
                "enabled": c.enabled,
                "running": self._running,
                "interval_minutes": c.interval_minutes,
                "target": c.target,
                "scan_profile": c.scan_profile,
                "last_run_at": c.last_run_at,
                "last_run_success": c.last_run_success,
                "last_result_summary": c.last_result_summary,
                "next_run_at": next_run,
                "next_run_in_seconds": max(0, next_run - time.time()),
            }

    # ── internal loop ──

    def _loop(self):
        logger.info("Scheduler loop started.")
        while True:
            with self._lock:
                if not self._running:
                    break
                config = self._config
                # copy needed fields while holding the lock
                enabled = config.enabled
                interval = config.interval_minutes
                last_run = config.last_run_at
                target = config.target
                profile = config.scan_profile

            if not enabled:
                time.sleep(10)
                continue

            now = time.time()
            if last_run == 0 or (now - last_run) >= interval * 60:
                logger.info("Scheduled scan firing: target=%s profile=%s", target, profile)
                try:
                    result = self._callback(target, profile)
                    summary = self._build_summary(result)
                    with self._lock:
                        self._config.last_run_at = now
                        self._config.last_run_success = bool(result.get("success"))
                        self._config.last_result_summary = summary
                    self._save_config()
                    logger.info("Scheduled scan complete: %s", summary)
                except Exception:
                    logger.exception("Scheduled scan failed:")
                    with self._lock:
                        self._config.last_run_at = now
                        self._config.last_run_success = False
                        self._config.last_result_summary = "Scan execution error"
                    self._save_config()

            time.sleep(30)  # check every 30s

    @staticmethod
    def _build_summary(result: Dict[str, Any]) -> str:
        try:
            if not result.get("success"):
                return "Scan failed"
            hosts = (result.get("data") or {}).get("hosts") or []
            return f"{len(hosts)} host(s) discovered"
        except Exception:
            return "Summary unavailable"