"""
backend/engines.py - Scan Engine Registry & Adapters

Defines an abstraction layer for CLI scan engines (Nmap required; RustScan,
Masscan, Naabu optional) so the scanner pipeline can discover, select, and
orchestrate the fastest available port-discovery engine at runtime.

All engines use argument lists (never shell=True).  Root elevation is delegated
to backend/elevation.py.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# CLI binary lookup (shared with scanner)
# ─────────────────────────────────────────────────────────────

def find_cli_binary(name: str) -> Optional[str]:
    """
    Locate CLI binary across PATH, Windows Registry PATH, and common directories.

    :param name: Executable name (e.g. 'nmap', 'masscan').
    :return: Absolute path or None.
    """
    found = shutil.which(name)
    if found:
        return found

    if sys.platform == "win32":
        import winreg

        candidate_paths: List[str] = []

        for root_key, sub_key in [
            (winreg.HKEY_CURRENT_USER, "Environment"),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            ),
        ]:
            try:
                with winreg.OpenKey(root_key, sub_key) as key:
                    val, _ = winreg.QueryValueEx(key, "Path")
                    for p in val.split(";"):
                        expanded = os.path.expandvars(p.strip())
                        if expanded and os.path.isdir(expanded):
                            candidate_paths.append(expanded)
            except Exception:
                pass

        candidate_paths.extend(
            [
                r"E:\Programs\Nmap",
                r"C:\Program Files (x86)\Nmap",
                r"C:\Program Files\Nmap",
                r"C:\ProgramData\chocolatey\bin",
                os.path.expandvars(r"%USERPROFILE%\scoop\shims"),
                os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap"),
                os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Packages"),
            ]
        )

        exts = [".exe", ".bat", ".cmd", ""]
        for folder in candidate_paths:
            for ext in exts:
                candidate = os.path.join(folder, f"{name}{ext}")
                if os.path.isfile(candidate):
                    current_path = os.environ.get("PATH", "")
                    if folder not in current_path:
                        os.environ["PATH"] = f"{folder}{os.pathsep}{current_path}"
                    return candidate

    return None


# ─────────────────────────────────────────────────────────────
# Engine spec & adapter
# ─────────────────────────────────────────────────────────────


@dataclass
class EngineSpec:
    key: str
    label: str
    binary: str
    category: str  # "core" | "fast_sweep"
    required: bool = False
    installed: bool = False
    path: str = ""
    description: str = ""

    def detect(self) -> None:
        p = find_cli_binary(self.binary)
        self.installed = p is not None
        self.path = p or ""


class FastSweepAdapter:
    """
    Abstract interface for a fast port-discovery engine.
    Subclasses implement build_cmd and parse_stdout.
    """

    key: str = ""
    label: str = ""
    binary: str = ""

    def __init__(self):
        self._path: Optional[str] = None

    def is_available(self) -> bool:
        if self._path is None:
            self._path = find_cli_binary(self.binary)
        return self._path is not None

    def build_cmd(self, target: str, ports: Optional[str] = None) -> List[str]:
        raise NotImplementedError

    def parse_stdout(self, stdout: str) -> List[int]:
        raise NotImplementedError


class RustscanAdapter(FastSweepAdapter):
    key = "rustscan"
    label = "RustScan"
    binary = "rustscan"

    def build_cmd(self, target: str, ports: Optional[str] = None) -> List[str]:
        path = self._path or "rustscan"
        cmd = [path, "-a", target, "-g", "-u", "5000", "--batch-size", "4500"]
        if ports:
            cmd.extend(["-r", ports])
        return cmd

    def parse_stdout(self, stdout: str) -> List[int]:
        # RustScan 2.x: "Open 192.168.1.1:22,80,443"  or  "[22,80,443]"
        ports_set: set[int] = set()
        # Bracket style
        bracket_match = re.search(r"\[([\d,\s]+)\]", stdout)
        if bracket_match:
            for tok in bracket_match.group(1).split(","):
                tok = tok.strip()
                if tok.isdigit():
                    ports_set.add(int(tok))
        # Colon list per-line
        for line in stdout.splitlines():
            m = re.search(r"Open\s+[\d.]+\s*:\s*([\d,]+)", line)
            if m:
                for tok in m.group(1).split(","):
                    tok = tok.strip()
                    if tok.isdigit():
                        ports_set.add(int(tok))
        return sorted(ports_set) if ports_set else []


class MasscanAdapter(FastSweepAdapter):
    key = "masscan"
    label = "Masscan"
    binary = "masscan"

    def build_cmd(self, target: str, ports: Optional[str] = None) -> List[str]:
        path = self._path or "masscan"
        cmd = [path, target, "--rate", "1000", "-oJ", "-"]
        if ports:
            cmd.extend(["-p", ports])
        else:
            cmd.extend(["-p", "1-65535"])
        return cmd

    def parse_stdout(self, stdout: str) -> List[int]:
        ports_set: set[int] = set()
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            # Masscan may output config first, then results array
            # Try finding the last valid JSON block
            for line in reversed(stdout.strip().splitlines()):
                try:
                    data = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
            else:
                return []

        # Normal form: list of host dicts
        if isinstance(data, list):
            for entry in data:
                for p in entry.get("ports", []):
                    if p.get("status") == "open" and p.get("port"):
                        ports_set.add(int(p["port"]))
        elif isinstance(data, dict):
            # Single host or summary
            for p in data.get("ports", []):
                if p.get("status") == "open" and p.get("port"):
                    ports_set.add(int(p["port"]))
        return sorted(ports_set)


class NaabuAdapter(FastSweepAdapter):
    key = "naabu"
    label = "Naabu"
    binary = "naabu"

    def build_cmd(self, target: str, ports: Optional[str] = None) -> List[str]:
        path = self._path or "naabu"
        cmd = [path, "-host", target, "-json"]
        if ports:
            cmd.extend(["-p", ports])
        return cmd

    def parse_stdout(self, stdout: str) -> List[int]:
        ports_set: set[int] = set()
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if "port" in rec:
                    ports_set.add(int(rec["port"]))
            except (json.JSONDecodeError, ValueError, TypeError):
                continue
        return sorted(ports_set)


# ─────────────────────────────────────────────────────────────
# Registry / catalogue
# ─────────────────────────────────────────────────────────────

_ENGINE_SPECS: Dict[str, EngineSpec] = {
    "nmap": EngineSpec(
        key="nmap",
        label="Nmap",
        binary="nmap",
        category="core",
        required=True,
        description="Service/OS detection, scripting, and topology tracing",
    ),
    "rustscan": EngineSpec(
        key="rustscan",
        label="RustScan",
        binary="rustscan",
        category="fast_sweep",
        description="Ultra-fast Rust port scanner",
    ),
    "masscan": EngineSpec(
        key="masscan",
        label="Masscan",
        binary="masscan",
        category="fast_sweep",
        description="Internet-scale mass port scanner (rate-limited)",
    ),
    "naabu": EngineSpec(
        key="naabu",
        label="Naabu",
        binary="naabu",
        category="fast_sweep",
        description="Project Discovery's fast port scanner (Go)",
    ),
}

_ADAPTER_CLASSES: Dict[str, type] = {
    "rustscan": RustscanAdapter,
    "masscan": MasscanAdapter,
    "naabu": NaabuAdapter,
}

# Priority order for fast-sweep engine selection (best UX first)
_FAST_SWEEP_PRIORITY = ["rustscan", "masscan", "naabu"]


def get_engine_specs() -> List[EngineSpec]:
    """Return all engine specs with detection pre-filled."""
    specs = []
    for spec in _ENGINE_SPECS.values():
        spec.detect()
        specs.append(spec)
    return specs


def get_available_engines() -> Dict[str, Any]:
    """Return engine availability summary for check_dependencies / UI."""
    specs = get_engine_specs()
    result: Dict[str, Any] = {
        "nmap": {},
        "rustscan": {},
        "masscan": {},
        "naabu": {},
        "fast_sweep_available": [],
    }
    for s in specs:
        result[s.key] = {
            "installed": s.installed,
            "path": s.path,
            "label": s.label,
            "required": s.required,
            "category": s.category,
        }
        if s.installed and s.category == "fast_sweep":
            result["fast_sweep_available"].append(s.key)
    return result


def resolve_fast_sweep_engine(
    preferred: Optional[str] = None,
) -> Optional[FastSweepAdapter]:
    """
    Return the best available fast-sweep engine, respecting user preference.
    Priority (when preferred is None): rustscan → masscan → naabu.
    """
    if preferred and preferred in _ADAPTER_CLASSES:
        adapter = _ADAPTER_CLASSES[preferred]()
        if adapter.is_available():
            return adapter

    for key in _FAST_SWEEP_PRIORITY:
        adapter = _ADAPTER_CLASSES[key]()
        if adapter.is_available():
            return adapter

    return None


def get_fast_sweep_catalogue() -> List[Dict[str, Any]]:
    """Return a catalogue of fast-sweep engines for the UI."""
    catalogue = []
    for key in _FAST_SWEEP_PRIORITY:
        adapter = _ADAPTER_CLASSES[key]()
        spec = _ENGINE_SPECS.get(key)
        catalogue.append(
            {
                "key": key,
                "label": adapter.label,
                "binary": adapter.binary,
                "installed": adapter.is_available(),
                "description": spec.description if spec else "",
            }
        )
    return catalogue