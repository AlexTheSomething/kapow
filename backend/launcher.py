"""
backend/launcher.py - Quick-Action Protocol Launcher & Wake-on-LAN Engine

Enables 1-click execution of remote management protocols:
- HTTP / HTTPS (Default Web Browser)
- RDP (Windows Remote Desktop / mstsc.exe)
- SSH (Windows Terminal / PuTTY / OpenSSH)
- SMB / Shares (Windows File Explorer)
- Wake-on-LAN (Magic Packet Broadcast)
"""

import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import webbrowser
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def launch_protocol(
    protocol: str,
    ip: str,
    port: Optional[int] = None,
    username: str = "",
) -> Dict[str, Any]:
    """
    Launch native desktop application associated with protocol for target host.

    :param protocol: 'http', 'https', 'ssh', 'rdp', 'smb', 'ping_cli'.
    :param ip: Target IP address or hostname.
    :param port: Optional specific port number.
    :param username: Optional login username for SSH/RDP.
    :return: Response status dictionary.
    """
    proto = protocol.lower().strip()
    ip = ip.strip()
    if not ip:
        return {"success": False, "error": "Target IP cannot be empty."}

    try:
        if proto in ("http", "https"):
            target_port = port or (443 if proto == "https" else 80)
            url = f"{proto}://{ip}:{target_port}"
            webbrowser.open(url)
            return {"success": True, "action": "browser", "url": url}

        elif proto == "rdp":
            if sys.platform == "win32":
                rdp_target = f"{ip}:{port}" if port and port != 3389 else ip
                subprocess.Popen(["mstsc.exe", f"/v:{rdp_target}"])
                return {"success": True, "action": "mstsc", "target": rdp_target}
            else:
                # Fallback for Linux Remmina / xfreerdp
                remmina_bin = shutil.which("remmina") or shutil.which("xfreerdp")
                if remmina_bin:
                    subprocess.Popen([remmina_bin, ip])
                    return {"success": True, "action": remmina_bin, "target": ip}
                return {"success": False, "error": "No native RDP client found on this OS."}

        elif proto == "ssh":
            ssh_user = f"{username}@" if username else ""
            ssh_port_arg = f"-p {port} " if port and port != 22 else ""
            ssh_target = f"{ssh_user}{ip}"

            if sys.platform == "win32":
                # Check for Windows Terminal (wt.exe), otherwise start cmd
                if shutil.which("wt"):
                    subprocess.Popen(["wt.exe", "ssh", ssh_target] if not ssh_port_arg else ["wt.exe", "ssh", "-p", str(port), ssh_target])
                else:
                    cmd_str = f"start cmd.exe /k ssh {ssh_port_arg}{ssh_target}"
                    os.system(cmd_str)
                return {"success": True, "action": "ssh_terminal", "target": ssh_target}
            else:
                # Unix terminal launcher
                terminal_bin = shutil.which("x-terminal-emulator") or shutil.which("gnome-terminal") or shutil.which("xterm")
                if terminal_bin:
                    subprocess.Popen([terminal_bin, "-e", f"ssh {ssh_port_arg}{ssh_target}"])
                    return {"success": True, "action": "ssh_terminal", "target": ssh_target}
                return {"success": False, "error": "No terminal emulator found to launch SSH."}

        elif proto == "smb":
            if sys.platform == "win32":
                unc_path = f"\\\\{ip}"
                os.startfile(unc_path)
                return {"success": True, "action": "explorer", "target": unc_path}
            else:
                return {"success": False, "error": "SMB Explorer is only supported on Windows."}

        elif proto == "ping_cli":
            if sys.platform == "win32":
                if shutil.which("wt"):
                    subprocess.Popen(["wt.exe", "cmd.exe", "/k", f"ping -t {ip}"])
                else:
                    os.system(f"start cmd.exe /k ping -t {ip}")
                return {"success": True, "action": "ping_cli", "target": ip}
            else:
                return {"success": False, "error": "Ping CLI terminal is only supported on Windows."}

        else:
            return {"success": False, "error": f"Unsupported protocol: {protocol}"}

    except Exception as e:
        logger.exception(f"Failed launching protocol {protocol} for {ip}: {e}")
        return {"success": False, "error": str(e)}


def send_wake_on_lan(
    mac_address: str,
    broadcast_ip: str = "255.255.255.255",
    port: int = 9,
) -> Dict[str, Any]:
    """
    Construct and broadcast a Wake-on-LAN (WoL) magic packet.

    A magic packet consists of 6 repetitions of 0xFF followed by 16 repetitions of the target 6-byte MAC.

    :param mac_address: Target hardware MAC (e.g. 'AA:BB:CC:DD:EE:FF' or 'aa-bb-cc-dd-ee-ff').
    :param broadcast_ip: Target broadcast address (default: 255.255.255.255).
    :param port: UDP destination port (standard: 7 or 9).
    :return: Response status dictionary.
    """
    clean_mac = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(clean_mac) != 12:
        return {
            "success": False,
            "error": f"Invalid MAC address format '{mac_address}'. Expected 12 hexadecimal characters.",
        }

    try:
        mac_bytes = bytes.fromhex(clean_mac)
        # 6 bytes 0xFF + 16 x MAC bytes
        magic_packet = b"\xff" * 6 + mac_bytes * 16

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic_packet, (broadcast_ip, port))
        sock.close()

        formatted_mac = ":".join(clean_mac[i:i+2].upper() for i in range(0, 12, 2))
        return {
            "success": True,
            "message": f"Wake-on-LAN magic packet successfully sent to {formatted_mac} via {broadcast_ip}:{port}.",
            "mac": formatted_mac,
        }

    except Exception as e:
        logger.exception(f"Failed sending WoL packet to {mac_address}: {e}")
        return {"success": False, "error": str(e)}
