"""
backend/elevation.py - Cross-Platform Privilege Elevation Engine

Provides secure command elevation across Linux, macOS, and Windows:
- Linux: `pkexec` (Polkit) / `sudo`
- macOS: `osascript` with administrator privileges
- Windows: PowerShell `Start-Process -Verb RunAs` / UAC
"""

import ctypes
import os
import platform
import shutil
import sys
from typing import List, Optional


def is_elevated() -> bool:
    """
    Check if the current process is already running with administrative/root privileges.

    :return: True if running with admin/root privileges, False otherwise.
    """
    try:
        if sys.platform == 'win32':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_elevation_method() -> Optional[str]:
    """
    Determine the primary elevation mechanism available on the current OS.

    :return: Identifier string ('pkexec', 'sudo', 'osascript', 'runas', or None)
    """
    current_os = sys.platform
    if current_os.startswith('linux'):
        if shutil.which('pkexec'):
            return 'pkexec'
        if shutil.which('sudo'):
            return 'sudo'
        return None
    elif current_os == 'darwin':
        if shutil.which('osascript'):
            return 'osascript'
        if shutil.which('sudo'):
            return 'sudo'
        return None
    elif current_os == 'win32':
        return 'runas'
    return None


def build_elevated_command(cmd_list: List[str]) -> List[str]:
    """
    Wrap an executable command list with the appropriate OS-specific elevation binary.

    :param cmd_list: List of command arguments, e.g. ['nmap', '-sS', '192.168.1.1']
    :return: Elevated command list ready for subprocess execution.
    :raises ValueError: If cmd_list is empty or OS elevation method is unsupported.
    """
    if not cmd_list:
        raise ValueError("Command list cannot be empty.")

    # If already elevated, return the command list directly
    if is_elevated():
        return list(cmd_list)

    current_os = sys.platform

    # Linux Elevation (pkexec preferred for GUI applications, sudo fallback)
    if current_os.startswith('linux'):
        if shutil.which('pkexec'):
            return ['pkexec'] + cmd_list
        elif shutil.which('sudo'):
            return ['sudo', '-n'] + cmd_list
        else:
            raise RuntimeError("No elevation tool (pkexec or sudo) found on Linux system PATH.")

    # macOS Elevation (osascript with administrator privileges)
    elif current_os == 'darwin':
        # Escape command arguments for AppleScript string
        escaped_args = []
        for arg in cmd_list:
            escaped = arg.replace('\\', '\\\\').replace('"', '\\"')
            escaped_args.append(f'"{escaped}"')
        joined_cmd = " ".join(escaped_args)
        applescript = f'do shell script "{joined_cmd}" with administrator privileges'
        return ['osascript', '-e', applescript]

    # Windows Elevation (PowerShell Start-Process with -Verb RunAs)
    elif current_os == 'win32':
        exe = cmd_list[0]
        args = cmd_list[1:]
        
        # Escape quotes in arguments for PowerShell ArgumentList
        if args:
            escaped_args = []
            for a in args:
                escaped = a.replace('"', '`"')
                escaped_args.append(f'"{escaped}"')
            args_str = ", ".join(escaped_args)
            ps_command = f"Start-Process -FilePath '{exe}' -ArgumentList @({args_str}) -Verb RunAs -Wait -NoNewWindow"
        else:
            ps_command = f"Start-Process -FilePath '{exe}' -Verb RunAs -Wait -NoNewWindow"

        return [
            'powershell.exe',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-Command',
            ps_command
        ]

    else:
        raise NotImplementedError(f"Privilege elevation is not supported on platform: {current_os}")
