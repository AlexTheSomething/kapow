# Kapow — Network Security Auditor & Topology Engine

Cross-platform desktop network administration utility: discover hosts, inventory services, visualize topology, and tag assets. Built with **Python 3 + PyWebView** and a **React / Vite / Tailwind** UI.

Public repo: https://github.com/AlexTheSomething/kapow

---

## Features

* **Auto-Detect My Network** — Enumerates adapters (Wi-Fi, Ethernet, VPN, WSL), local IP, gateway, and CIDR. One-click **Scan My LAN**.
* **Hybrid scans** — Optional fast port sweep (RustScan / Masscan / Naabu — best available engine auto-selected), then targeted Nmap service scans. Subnet targets run a ping sweep first; proxy-ARP "ghost" hosts are filtered.
* **Dual view** — AG Grid asset inventory + Cytoscape.js topology (fCoSE and other layouts).
* **Protocol launcher** — Open HTTP/HTTPS, RDP, SSH, SMB; send Wake-on-LAN magic packets.
* **ICMP telemetry** — Rolling RTT min/avg/max, jitter, and loss with a sparkline.
* **CVE hints** — Offline curated knowledge base (not a live NVD feed). Matches common product/version patterns with CVSS-style severity labels.
* **Scan Diff** — Compare two scan snapshots; history persists across app restarts (SQLite, capped at 50 scans).
* **SQLite asset store** — Aliases, owners, tags, notes, and risk ratings across scans (`assets.db`, gitignored).
* **Passive discovery** — ARP cache polling + receive-only SSDP (UPnP NOTIFY) and mDNS (.local) multicast listeners. Zero probes sent — no SYN, no ping, no M-SEARCH.
* **Live console** — Streaming Nmap output, cancel, export JSON/CSV/XML.

---

## Architecture

```
Kapow/
├── main.py                    # Entry (--prod, --check, --mock, --test-scan)
├── parsers.py                 # Nmap XML → AG Grid / Cytoscape + live-host filters
├── requirements.txt
├── start_kapow.bat            # One-click Windows launcher
├── backend/
│   ├── app.py                 # PyWebView JS API bridge
│   ├── scanner.py             # Async Nmap + multi-engine pipeline
│   ├── engines.py             # Engine registry (RustScan/Masscan/Naabu adapters)
│   ├── elevation.py           # On-demand UAC / pkexec / osascript
│   ├── net_interfaces.py
│   ├── launcher.py
│   ├── telemetry.py
│   ├── passive_sniffer.py     # ARP cache + SSDP + mDNS (receive-only)
│   ├── scan_store.py          # Persistent scan history (SQLite)
│   ├── cve_lookup.py          # Curated offline CVE KB
│   ├── diff_engine.py
│   └── asset_db.py
└── frontend/                  # React + Vite + Tailwind
```

---

## One-Click Launch (Windows)

Double-click **`start_kapow.bat`**. The launcher:

1. Finds your Python 3.10+ install
2. Installs Python dependencies if needed
3. Builds the React frontend if `frontend/dist` is missing (requires Node.js)
4. Launches Kapow in production mode

Prerequisites for the one-click launcher:
- **Python 3.10+** ([python.org](https://python.org/downloads/))
- **Nmap** on PATH ([nmap.org](https://nmap.org))
- **Node.js 18+** (optional — only needed on first run to build the UI)

---

## Install & run (dev)

```bash
git clone https://github.com/AlexTheSomething/kapow.git
cd kapow

pip install -r requirements.txt

# Production UI (uses frontend/dist if present)
python main.py --prod

# Dev UI (start Vite first)
cd frontend && npm install && npm run dev
# other terminal:
python main.py
```

Other commands:

```bash
python main.py --check          # diagnose CLI tools
python main.py --mock           # print sample scan data
python main.py --test-scan 127.0.0.1  # run scan from CLI
```

Rebuild the UI after frontend edits:

```bash
cd frontend && npm install && npm run build
```

---

## Tests

```bash
python -m unittest test_kapow_features.py test_features.py test_backend.py test_parsers.py
```

---

## License

MIT. Built for network engineers and defensive security auditors.