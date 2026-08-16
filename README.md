# Kapow — Network Security Auditor & Topology Engine

Cross-platform desktop network administration utility: discover hosts, inventory services, visualize topology, and tag assets. Built with **Python 3 + PyWebView** and a **React / Vite / Tailwind** UI.

Public repo: https://github.com/AlexTheSomething/kapow

---

## Features

* **Auto-Detect My Network** — Enumerates adapters (Wi-Fi, Ethernet, VPN, WSL), local IP, gateway, and CIDR. One-click **Scan My LAN**.
* **Hybrid scans** — Optional RustScan open-port discovery, then targeted Nmap service scans. Subnet targets run a ping sweep first; proxy-ARP “ghost” hosts are filtered.
* **Dual view** — AG Grid asset inventory + Cytoscape.js topology (fCoSE and other layouts).
* **Protocol launcher** — Open HTTP/HTTPS, RDP, SSH, SMB; send Wake-on-LAN magic packets.
* **ICMP telemetry** — Rolling RTT min/avg/max, jitter, and loss with a sparkline.
* **CVE hints** — Offline curated knowledge base (not a live NVD feed). Matches common product/version patterns with CVSS-style severity labels.
* **Scan Diff** — Compare two scan snapshots in the current session (history is in-memory unless persisted later).
* **SQLite asset store** — Aliases, owners, tags, notes, and risk ratings across scans (`assets.db`, gitignored).
* **ARP cache discovery** — Lists devices from the local OS ARP table (no SYN probes). Not a packet sniffer; SSDP/mDNS not implemented yet.
* **Live console** — Streaming Nmap output, cancel, export JSON/CSV/XML.

---

## Architecture

```
Kapow/
├── main.py                    # Entry (--prod, --check, --mock, --test-scan)
├── parsers.py                 # Nmap XML → AG Grid / Cytoscape + live-host filters
├── requirements.txt
├── backend/
│   ├── app.py                 # PyWebView JS API bridge
│   ├── scanner.py             # Async Nmap / RustScan pipeline
│   ├── elevation.py           # On-demand UAC / pkexec / osascript
│   ├── net_interfaces.py
│   ├── launcher.py
│   ├── telemetry.py
│   ├── passive_sniffer.py     # ARP cache reader
│   ├── cve_lookup.py          # Curated offline CVE KB
│   ├── diff_engine.py
│   └── asset_db.py
└── frontend/                  # React + Vite + Tailwind
```

---

## Prerequisites

1. **Python 3.10+**
2. **Nmap** on PATH ([nmap.org](https://nmap.org)). Windows also probes common install dirs.
3. *(Optional)* **RustScan** for faster port discovery.
4. **Node.js 18+** only if you change the React UI.

---

## Install & run

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
python main.py --check
python main.py --mock
python main.py --test-scan 127.0.0.1
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
