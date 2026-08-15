# 💥 Kapow — Modern Network Security Auditor & Topology Engine

> A high-performance, cross-platform desktop network administrator utility and vulnerability auditor built with Python 3, PyWebView, React, Tailwind CSS, AG Grid, and Cytoscape.js.

---

## ✨ Features at a Glance

* 🌐 **Auto-Detect My Network**: Instantly enumerates network adapters (Wi-Fi, Ethernet, VPN, WSL), local IPs, default gateways, and subnets. One-click **"Scan My LAN"** button!
* 🚀 **1-Click Remote Protocol Launcher**:
  * **HTTP / HTTPS (80/443/8080)**: Launch in default browser.
  * **RDP (3389)**: Windows Remote Desktop (`mstsc.exe`).
  * **SSH (22)**: Windows Terminal / PuTTY / OpenSSH.
  * **SMB (445)**: Windows File Explorer (`\\<ip>`).
  * **Wake-on-LAN (WoL)**: Broadcast magic packets using hardware MAC.
* 📈 **Live ICMP Ping & Jitter Telemetry**: Sub-second rolling telemetry dashboard with live animated sparkline charts, tracking RTT min/avg/max, jitter, and packet loss %.
* 🛡️ **Automated CVE & Vulnerability Engine**: Cross-references discovered software versions and CPEs against known CVE records (OpenSSH RCEs, Apache Path Traversal, EternalBlue SMB) with CVSS severity scoring.
* ⏳ **Scan Diff & Drift Detector ("Time Machine")**: Side-by-side comparison of any two network scans to spot newly joined rogue devices, decommissioned hosts, and exposed ports.
* 🪐 **Multi-Layout Interactive Topology**: Force-directed (fCoSE), Concentric Radial, Hierarchical Tree, Circular, and Grid layouts with red glowing badges for vulnerable assets.
* 📊 **AG Grid Asset Inventory**: High-performance tabular inventory with instant search, status pills, port protocols, and CVE badges.
* 🏷️ **Persistent Asset Store (SQLite)**: Tag devices with custom aliases (e.g., *"CEO Laptop"*, *"Primary DC"*), department owners, tags (`#Production`, `#DMZ`), and risk ratings that persist across scans.
* 🔕 **Zero-Noise Passive Device Sniffer**: Passively discovers active devices on the local LAN via ARP cache and broadcast packets without transmitting active probe packets.
* 💻 **Real-Time Live Console**: Hacker terminal with ANSI streaming logs, auto-scroll lock, copy logs, and `.log` download.

---

## 🛠️ Architecture & Technology Stack

```
Kapow/
├── backend/
│   ├── app.py                 # PyWebView Desktop API Bridge
│   ├── scanner.py             # Multi-stage asynchronous Nmap / RustScan engine
│   ├── net_interfaces.py      # Network adapter & subnet auto-discovery
│   ├── launcher.py            # Protocol launcher & Wake-on-LAN engine
│   ├── telemetry.py           # Real-time ICMP ping & jitter telemetry
│   ├── passive_sniffer.py     # Zero-noise passive ARP & broadcast listener
│   ├── cve_lookup.py          # CVE vulnerability database & CVSS scorer
│   ├── diff_engine.py         # Network drift & scan comparator
│   ├── asset_db.py            # SQLite persistent asset metadata store
│   └── elevation.py           # Cross-platform root/admin elevation (UAC / pkexec)
├── frontend/                  # Modern React + Tailwind CSS Desktop GUI
│   ├── src/components/
│   │   ├── Topology.jsx       # Cytoscape.js Multi-Layout Network Canvas
│   │   ├── DataGrid.jsx       # AG Grid Tabular Asset Inventory
│   │   ├── HostProfiler.jsx   # Two-Pane Host Diagnostics & Metadata Editor
│   │   ├── LatencyMonitor.jsx # Live Ping Telemetry & Sparkline Waveform
│   │   ├── PassiveSniffer.jsx # Passive Broadcast Device Sniffer
│   │   ├── QuickActions.jsx   # 1-Click Remote Protocol Launcher Bar
│   │   ├── ScanDiff.jsx       # Side-by-Side Scan Diff & Drift Comparator
│   │   ├── ScanControls.jsx   # Target Specification & NSE Preset Builder
│   │   └── LiveConsole.jsx    # Real-Time Terminal Log Streamer
│   └── dist/                  # Compiled Production Bundle
└── main.py                    # Application Entry Point
```

---

## 🚀 Quickstart Guide

### Prerequisites
1. **Python 3.10+** installed.
2. **Nmap** installed ([nmap.org](https://nmap.org)). On Windows, ensure Nmap is installed in `E:\Programs\Nmap` or `C:\Program Files (x86)\Nmap`.
3. *(Optional)* **RustScan** for ultra-fast port sweeps ([github.com/RustScan/RustScan](https://github.com/RustScan/RustScan)).

### Installation
```bash
# Clone the repository
git clone https://github.com/<username>/kapow.git
cd kapow

# Install Python dependencies
pip install pywebview

# (Optional) Run frontend build if modifying React code
cd frontend
npm install
npm run build
cd ..
```

### Running Kapow
```bash
# Launch the desktop application
python main.py

# Check CLI dependencies
python main.py --check

# Test scan against localhost
python main.py --test-scan 127.0.0.1
```

---

## 🧪 Running Automated Tests

Kapow includes an automated unit test suite covering all modules:

```bash
python -m unittest test_kapow_features.py test_features.py test_backend.py test_parsers.py
```

---

## 📄 License
MIT License. Created with ❤️ for network engineers and security auditors.
