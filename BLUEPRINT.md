# Kapow v2.0 — Product Blueprint

*A network reconnaissance cockpit for power users, homelab operators, and security pros.*

---

## 1. What Kapow is (one-liner)

**Know your network. Catch what changes. Reach any device.**

Three overlapping audiences: home labbers managing their gear, network admins keeping inventory, and white-hat pentesters doing recon. The tool is the same — the workflows differ.

---

## 2. Information Architecture

### Navigation (top-level tab bar)

| Tab | Purpose | Shows |
|---|---|---|
| **Home** | Landing + topology canvas + last scan summary | Topology canvas with adapters, live hosts, scan button, recent changes |
| **Inventory** | Sortable/filterable list of all hosts/services | AG Grid table with tags, quick actions, search |
| **Changes** | Scan diff — "what changed since last time?" | Baseline + comparison, host drift, port exposure deltas |

### Drill-down (not tabs)

| View | Trigger | Behavior |
|---|---|---|
| **Host Profiler** | Click any host anywhere | Full-screen, back button. Ports, OS, telemetry, tags, notes, CVE hints |
| **Console** | During/after a scan | Collapsible bottom drawer — live nmap output streaming |
| **Settings** | Gear icon (top-right) | Scan scheduling, preferences, about |

### What disappears from the top-level tab bar

- **Passive Sniffer** → merged into Home (discovered devices appear on the canvas with a "passive" badge)
- **Ping Telemetry** → merged into Host Profiler (live RTT shown per-host)
- **Raw XML** → removed as a view; export-only
- **Console** → bottom drawer, not a tab

---

## 3. Home Screen (first thing you see)

```
┌─────────────────────────────────────────────────────┐
│ [Kapow logo]   Target: 192.168.1.0/24   [ SCAN ▼ ]  │  ← compact scan bar
│                                       profile: quick │
├─────────────────────────────────────────────────────┤
│                                                     │
│              TOPOLOGY CANVAS (hero)                  │
│  Shows detected adapters as root nodes.              │
│  On scan: hosts light up ONE BY ONE as discovered.   │
│  Passive devices appear with subtle fade-in.         │
│  Click any node → drill into Host Profiler.          │
│                                                     │
├─────────────────────────────────────────────────────┤
│  Last scan: 5 hosts, 2 new since yesterday           │
│  ▸ 192.168.1.1  gateway   🟢  |  ▸ 192.168.1.42     │
│  ▸ 192.168.1.77 printer   🟡  |  ▸ 192.168.1.99 new │
└─────────────────────────────────────────────────────┘
```

**Key behaviors:**
- On first launch (no scan history): adapters visible, empty canvas, big inviting Scan button
- On subsequent launches: last scan summary loaded from SQLite, canvas shows last known state
- Scan button is always visible — it's the primary action
- Advanced scan options (ports, root toggle, scripts) hidden behind a disclosure arrow; all defaults are sensible

---

## 4. Tag & Note System

### Manual tags
- Free-form text tags per host (`mine`, `suspicious`, `to-investigate`, `print server`)
- Color picker per tag (or auto-assigned from a palette)
- Tags show everywhere: topology nodes (colored badge), inventory rows (chips), diff view (tagged hosts highlighted on change)

### Auto-suggested tags (quiet intelligence)
- **When:** after each scan completes. Only if matches exist.
- **Where:** subtle "**2 suggestions**" badge on the Home screen and Inventory tab. Click to open a side panel.
- **How it works:** The app checks scan results against a rule set:
  - Old/vulnerable service versions → `needs update`
  - SMB (445) open → `exposed file share`
  - Telnet/FTP → `legacy protocol`
  - New MAC vendor never seen before → `new device`
  - Web admin panel detected → `web console`
  - Device with 0 open ports but ARP-live → `quiet host`
- User accepts (✓) or dismisses (✗). Accepted tags are saved to that host permanently.
- **Never nag.** No popups, no full-screen interruptions.

### Notes (per-host)
- Markdown-capable text area per host (freeform)
- Visible in Host Profiler
- Saved to SQLite alongside tags/alias/owner/risk

---

## 5. Host Profiler (drill-down)

Full-screen view when clicking any host. Back button returns to previous view.

```
[← Back]                         Host: 192.168.1.42 (alex-macbook)
─────────────────────────────────────────────────────────
[ Tags: [mine] [needs update]  ]  [ + Add tag ]
[Alias: alex-macbook] [Owner: ] [Risk: Low ▼]

┌─ Ports & Services ──────────────────────────────────┐
│ 22/tcp   OpenSSH 9.6        🟢  [SSH]               │
│ 5000/tcp Node.js Express     🟢  [HTTP]              │
└──────────────────────────────────────────────────────┘

┌─ Telemetry ─────────────────────────────────────────┐
│ RTT: 1.2ms avg │ Jitter: 0.3ms │ Loss: 0%  [▁▃▁▅▃] │
└──────────────────────────────────────────────────────┘

┌─ CVE Hints ─────────────────────────────────────────┐
│ ⚠ OpenSSH < 9.7 — potential CVE-2024-6387 (regreSSH)│
└──────────────────────────────────────────────────────┘

┌─ Notes ─────────────────────────────────────────────┐
│ My MacBook dev machine. Has Docker running.         │
└──────────────────────────────────────────────────────┘

OS: Apple macOS 14 (Sonoma)  |  MAC: AC:DE:48:00:22:33
```

---

## 6. Scan Workflow

1. User opens Kapow → Home screen with topology canvas and last scan summary
2. Target is pre-filled with detected LAN subnet
3. User clicks **Scan** (or selects a profile from the dropdown)
4. Topology canvas pulses — hosts appear one-by-one as nmap discovers them
5. Live console drawer can be pulled up for detailed output
6. Scan completes → discovered hosts count-up animation, "2 suggestions" badge appears
7. User clicks hosts to explore, reviews suggestions, tags devices
8. Next scan: diff view shows exactly what changed

---

## 7. What Gets Simplified

| Before (v1.x) | After (v2.0) |
|---|---|
| 8 tabs always visible | 3 tabs + host drill-down + console drawer |
| 6 scan profiles as radio buttons | 1 dropdown with sensible default (Quick) |
| Ports field, root toggle, scripts always visible | Collapsed behind "Advanced" disclosure |
| 5 CLI dependency badges in header | Reduced to 2 core (Nmap + fast-sweep engine) |
| Passive sniffer as separate tab | Merged into Home canvas |
| Ping telemetry as separate tab | Merged into Host Profiler |
| Auto-loads sample data on launch | Loads last real scan from history |
| Export always in header | Available in scan results / settings |

---

## 8. Animation Roadmap

### Phase A — Foundation (during UI rebuild)
- **Topology discovery**: hosts glow into existence on the canvas one-by-one as nmap discovers them
- **Tab transitions**: smooth slide between Home / Inventory / Changes (200ms)
- **Host drill-down**: canvas node expands from its position into the full Profiler screen
- **Tag sparkle**: brief shimmer when a tag is first applied to a host
- **Passive fade-in**: ARP/SSDP/mDNS devices appear with a soft fade-in on the canvas
- **Scan pulse**: topology canvas has a subtle scanning wave during active scan

### Phase B — Premium Polish (after foundation is solid)
- Glass morphism panels (frosted glass backgrounds)
- Neon/accent glow on interactive elements
- Particle effects during scan discovery
- Smooth layout engine on canvas (force-directed with animation)
- Count-up numbers on scan complete (hosts, ports, new devices)

---

## 9. Future (Not In This Version)

These are acknowledged but deferred to avoid scope creep:

- **YAML plugin/workflow system** — user-defined scan pipelines
- **Hydra integration** — credential testing (offensive)
- **Brute-force module** — controlled password/credential attacks
- **Live NVD feed** — currently offline CVE KB is honest and sufficient
- **Masscan/Naabu as user-selectable engines** — currently auto-selected, no UI toggle needed yet
- **Export PDF/Markdown reports** — useful for client deliverable or personal inspection
- **Multi-user / cloud sync / mobile** — not worth building; local-first is the strength

---

## 10. Before / After Summary

| Axis | v1.x (now) | v2.0 (blueprint) |
|---|---|---|
| **First impression** | Empty table, auto-loaded fake data | Topology canvas with adapters, ready to scan |
| **Home** | Doesn't exist | Canvas + scan CTA + last summary — the heart |
| **Tabs** | 8 tabs, feature-list feel | 3 tabs + drill-down + drawer |
| **Tagging** | Manual aliases/tags in a form | Smart suggestions + manual tags + visual badges everywhere |
| **Animation** | None | Discovery glow, transitions, expand, sparkle |
| **Clutter** | 6 profiles, ports, root, scripts → always visible | Advanced collapsed, sensible defaults |
| **Host exploration** | Profiler tab, separate from topology | Click canvas node → expand into full profiler |
| **Purpose** | "Network scanner GUI" | "Know your network. Catch changes. Reach any device." |

---

*Last updated: 2026-08-17. This document is the source of truth for the v2.0 rebuild. Any code change should point back to a section here.*