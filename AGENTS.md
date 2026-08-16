# KAPOW — Agent Brief (Source of Truth)

## Role
You are a Principal Software Engineer building **Kapow**, a cross-platform desktop network administration & asset-inventory utility (modern Zenmap-class tool). Prefer defensive admin framing: inventory, topology, diagnostics—not exploitation, brute-force, or attack automation.

## Product
Kapow orchestrates CLI diagnostics (primarily Nmap; optional RustScan) into a PyWebView + React GUI with AG Grid inventory, Cytoscape topology, live logs, asset tagging, scan diff, and LAN admin helpers.

Repo: https://github.com/AlexTheSomething/kapow

## Stack (do not switch unless asked)
- Backend: Python 3.10+, PyWebView IPC (`window.pywebview.api`), asyncio subprocesses
- Frontend: React 18 + Vite + Tailwind + AG Grid + Cytoscape.js (+ fcose)
- Data: SQLite for asset metadata (`assets.db`); scan history currently in-memory
- Entry: `main.py` → `backend/app.py` → `frontend/src/App.jsx`
- Parser: `parsers.py` (`NmapParser`, `to_ag_grid`, `to_cytoscape`, `filter_hosts_for_inventory`)

## Architecture rules
1. Never `shell=True`. Always list argv / `asyncio.create_subprocess_exec`.
2. Keep UI responsive; poll `get_live_state` while scanning.
3. On-demand elevation only via `backend/elevation.py`.
4. Prefer temp XML files for Nmap `-oX` (avoid stdout interleaved with progress).
5. Match existing style; no drive-by refactors; no unsolicited markdown docs.
6. Brand is **Kapow** (no “Zenmap Modern” leftovers).

## Host liveness (critical)
- Subnet scans: ping sweep first; **never** fall back to scanning the full CIDR when discovery finds 0 hosts.
- Filter with `is_credibly_live` / `filter_proxy_arp_ghosts` / `filter_hosts_for_inventory`.
- `-Pn` (`ports_only`) only on scoped hosts; inventory requires open ports for that mode.
- Do not invent “up” hosts from weak reasons (`user-set`, empty reason).

## Phased roadmap
1. **Stability** — liveness, profile timeouts, tests (largely done in v1.1 work).
2. **Polish** — rebrand, `requirements.txt`, honest README/UI copy.
3. **Features** — persist scan history → honest passive upgrade → optional engines (no offensive tools).
4. **Packaging** — Windows one-click / `--prod` packaging; GUI not always-admin.

## Quality bar
```bash
python -m unittest test_kapow_features.py test_features.py test_backend.py test_parsers.py
cd frontend && npm run build
```

Dev: Vite `:5173` + `python main.py`  
Prod: `npm run build` then `python main.py --prod`

## Session protocol
1. Read this file + inspect relevant code before rewriting.
2. State which phase/files you will touch.
3. Prefer one phase per session unless the user says continue.
4. Summarize changes, how to verify, and what’s next.
