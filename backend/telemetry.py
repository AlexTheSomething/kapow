"""
backend/telemetry.py - Real-Time ICMP Ping & Latency Jitter Telemetry Engine

Executes lightweight non-blocking ICMP ping sweeps and tracks:
- Real-time RTT latency (ms)
- Min / Avg / Max latency
- Network Jitter (deviation between consecutive samples)
- Packet Loss percentage
- Online / Offline telemetry status
"""

import collections
import logging
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# In-memory circular buffer storing up to 30 ping history samples per IP
_TELEMETRY_CACHE: Dict[str, collections.deque] = {}
_TELEMETRY_LOSS: Dict[str, Dict[str, int]] = {}


def ping_host(target_ip: str, timeout_ms: int = 1000) -> Dict[str, Any]:
    """
    Execute single-shot ping against target host and update rolling telemetry statistics.

    :param target_ip: IP address or hostname.
    :param timeout_ms: Maximum ping timeout in milliseconds.
    :return: Telemetry statistics dictionary.
    """
    ip = target_ip.strip()
    if not ip:
        return {"success": False, "error": "Target IP cannot be empty."}

    if ip not in _TELEMETRY_CACHE:
        _TELEMETRY_CACHE[ip] = collections.deque(maxlen=30)
        _TELEMETRY_LOSS[ip] = {"sent": 0, "received": 0}

    _TELEMETRY_LOSS[ip]["sent"] += 1

    latency_ms: Optional[float] = None
    is_online = False

    try:
        startupinfo = None
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            timeout_sec = max(1, timeout_ms // 1000)
            cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
            startupinfo=startupinfo,
            timeout=max(2.0, (timeout_ms / 1000.0) + 0.5),
        )

        out = proc.stdout.lower()

        # Parse Windows / Unix ping latency
        # e.g. "time=14ms" or "time<1ms" or "time=0.456 ms"
        match = re.search(r"time[<=](\d+(?:\.\d+)?)\s*ms", out)
        if match:
            latency_ms = float(match.group(1))
            is_online = True
        elif "time<1ms" in out or "time < 1ms" in out:
            latency_ms = 0.5
            is_online = True
        elif proc.returncode == 0 and "ttl=" in out:
            latency_ms = 1.0
            is_online = True

    except Exception as e:
        logger.debug(f"Ping exception for {ip}: {e}")

    if is_online and latency_ms is not None:
        _TELEMETRY_LOSS[ip]["received"] += 1
        _TELEMETRY_CACHE[ip].append(latency_ms)
    else:
        # Append 0 for timeout visualization
        _TELEMETRY_CACHE[ip].append(None)

    # Compute Statistics
    history = list(_TELEMETRY_CACHE[ip])
    valid_samples = [s for s in history if s is not None]

    min_lat = min(valid_samples) if valid_samples else 0.0
    max_lat = max(valid_samples) if valid_samples else 0.0
    avg_lat = sum(valid_samples) / len(valid_samples) if valid_samples else 0.0

    # Calculate Jitter: mean difference between consecutive packets
    jitter = 0.0
    if len(valid_samples) >= 2:
        diffs = [abs(valid_samples[i] - valid_samples[i - 1]) for i in range(1, len(valid_samples))]
        jitter = sum(diffs) / len(diffs)

    # Packet Loss
    sent = _TELEMETRY_LOSS[ip]["sent"]
    recv = _TELEMETRY_LOSS[ip]["received"]
    loss_pct = round(((sent - recv) / sent) * 100, 1) if sent > 0 else 0.0

    return {
        "success": True,
        "ip": ip,
        "is_online": is_online,
        "current_latency": latency_ms,
        "min_latency": round(min_lat, 2),
        "avg_latency": round(avg_lat, 2),
        "max_latency": round(max_lat, 2),
        "jitter": round(jitter, 2),
        "packet_loss_pct": loss_pct,
        "samples_count": len(valid_samples),
        "history": [round(s, 1) if s is not None else 0.0 for s in history],
        "timestamp": time.time(),
    }


def reset_telemetry(target_ip: Optional[str] = None):
    """Clear telemetry statistics for target IP or all hosts."""
    if target_ip:
        _TELEMETRY_CACHE.pop(target_ip, None)
        _TELEMETRY_LOSS.pop(target_ip, None)
    else:
        _TELEMETRY_CACHE.clear()
        _TELEMETRY_LOSS.clear()
