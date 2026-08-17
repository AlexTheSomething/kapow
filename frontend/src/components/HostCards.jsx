import React, { useState } from 'react';
import { Wifi, Globe, Terminal, Shield, Server, Laptop, Router as RouterIcon, ExternalLink, Search, X, Filter, Tag, ShieldAlert, Sparkles, ChevronDown, ChevronUp, Copy, Check } from 'lucide-react';
import TagChip from './TagChip';

/**
 * Single Host Card — compact, expandable. Shows key info at a glance;
 * expands to reveal full port details with banners and scripts.
 */
function HostCard({ host, onSelectHost, onLaunchProtocol, index }) {
  const [expanded, setExpanded] = useState(false);
  const [expandedPort, setExpandedPort] = useState(null);
  const [copiedIp, setCopiedIp] = useState(false);

  if (!host) return null;
  const ip = host.ip || host.ipv4 || '';
  const hostname = host.primary_hostname || host.hostname || '';
  const os = host.primary_os || '';
  const mac = host.mac || '';
  const vendor = host.vendor || '';
  const ports = host.ports || [];
  const tags = host.tags || [];
  const cves = host.cves || [];
  const severity = host.severity || (host.max_cvss >= 9 ? 'CRITICAL' : (host.cves?.length > 0 ? 'VULN' : null));
  const maxCvss = host.max_cvss;

  // OS icon
  const osLower = os.toLowerCase();
  let OsIcon = Laptop;
  if (osLower.includes('router') || osLower.includes('openwrt') || osLower.includes('cisco')) OsIcon = RouterIcon;
  else if (osLower.includes('server') || osLower.includes('linux') || osLower.includes('bsd')) OsIcon = Server;

  // Count ports by state
  const openPorts = ports.filter((p) => (p.state || p.status || '').toLowerCase() === 'open');
  const filteredPorts = ports.filter((p) => (p.state || p.status || '').toLowerCase() === 'filtered');

  const handleCopyIp = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(ip);
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 1500);
  };

  const renderPortPill = (p) => {
    const svc = p.service || {};
    const portId = p.portid || p.port;
    const isHttp = portId === 80 || portId === 443 || portId === 8080 || portId === 8443;
    const isSsh = portId === 22;
    const isRdp = portId === 3389;
    const color = isHttp ? 'border-cyan-500/40 text-cyan-300' : isSsh ? 'border-indigo-500/40 text-indigo-300' : isRdp ? 'border-violet-500/40 text-violet-300' : 'border-slate-700 text-slate-400';
    return (
      <div key={`${portId}-${p.protocol}`} className={`flex items-center gap-1.5 px-2 py-1 rounded-lg border text-[10px] font-mono ${color} bg-dark-950/80`}>
        <span className="font-bold">{portId}/{p.protocol || 'tcp'}</span>
        <span className="text-slate-500">{svc.name || '?'}</span>
      </div>
    );
  };

  // Quick actions to surface
  const hasHttp = openPorts.some((p) => p.portid === 80 || p.portid === 443 || p.portid === 8080 || p.portid === 8443);
  const hasSsh = openPorts.some((p) => p.portid === 22);
  const hasRdp = openPorts.some((p) => p.portid === 3389);
  const hasSmb = openPorts.some((p) => p.portid === 445);

  return (
    <div
      className="bg-dark-900 border border-slate-800 rounded-2xl overflow-hidden hover:border-slate-700 transition-all duration-200 animate-slide-up"
      style={{ animationDelay: `${index * 50}ms` }}
    >
      {/* Header — always visible */}
      <div
        onClick={() => onSelectHost && onSelectHost({ host, initialPort: null })}
        className="p-4 cursor-pointer group"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            {/* IP row */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm font-bold text-cyan-300 group-hover:text-brand-neon transition-colors">{ip}</span>
              {hostname && (
                <span className="text-xs text-slate-400 font-mono truncate">({hostname})</span>
              )}
              <button onClick={handleCopyIp} className="opacity-0 group-hover:opacity-100 p-0.5 text-slate-500 hover:text-white transition-all">
                {copiedIp ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
            {/* Meta row */}
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              {os && (
                <span className="flex items-center gap-1 text-[10px] text-slate-500">
                  <OsIcon className="w-3 h-3" /> {os}
                </span>
              )}
              {vendor && <span className="text-[10px] text-slate-600">{vendor}</span>}
              {mac && <span className="text-[10px] text-slate-600 font-mono">{mac}</span>}
            </div>
            {/* Tags */}
            {tags.length > 0 && (
              <div className="flex items-center gap-1 mt-2 flex-wrap">
                {tags.map((t) => (
                  <TagChip key={t} tag={t} color={t === 'needs update' ? 'amber' : t === 'new device' ? 'emerald' : t === 'exposed file share' ? 'rose' : t === 'web console' ? 'cyan' : 'slate'} small />
                ))}
              </div>
            )}
          </div>

          {/* Right side: status + count */}
          <div className="flex flex-col items-end gap-1.5 shrink-0">
            {/* Port count badge */}
            <span className="flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              {openPorts.length} open
            </span>
            {filteredPorts.length > 0 && (
              <span className="flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                {filteredPorts.length} filtered
              </span>
            )}
            {severity && (
              <span className={`flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full ${
                severity === 'CRITICAL' ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
              }`}>
                <ShieldAlert className="w-3 h-3" />
                {severity}
                {maxCvss ? ` ${maxCvss}` : ''}
              </span>
            )}
          </div>
        </div>

        {/* Port pills — quick glance */}
        {openPorts.length > 0 && (
          <div className="flex items-center gap-1.5 mt-3 flex-wrap">
            {openPorts.slice(0, 6).map(renderPortPill)}
            {openPorts.length > 6 && (
              <span className="text-[10px] text-slate-500 px-1">+{openPorts.length - 6} more</span>
            )}
          </div>
        )}
      </div>

      {/* Action bar */}
      <div className="px-4 pb-3 flex items-center gap-2 border-t border-slate-800/50 pt-3">
        {hasHttp && (
          <button onClick={(e) => { e.stopPropagation(); onLaunchProtocol?.('http', ip, 80); }} className="flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-all">
            <Globe className="w-3 h-3" /> HTTP
          </button>
        )}
        {hasSsh && (
          <button onClick={(e) => { e.stopPropagation(); onLaunchProtocol?.('ssh', ip, 22); }} className="flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 hover:bg-indigo-500/20 transition-all">
            <Terminal className="w-3 h-3" /> SSH
          </button>
        )}
        {hasRdp && (
          <button onClick={(e) => { e.stopPropagation(); onLaunchProtocol?.('rdp', ip, 3389); }} className="flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-semibold bg-violet-500/10 text-violet-400 border border-violet-500/20 hover:bg-violet-500/20 transition-all">
            <Shield className="w-3 h-3" /> RDP
          </button>
        )}
        {hasSmb && (
          <button onClick={(e) => { e.stopPropagation(); onLaunchProtocol?.('smb', ip, 445); }} className="flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-semibold bg-slate-700/50 text-slate-300 border border-slate-600 hover:bg-slate-700 transition-all">
            <Server className="w-3 h-3" /> SMB
          </button>
        )}
        <div className="flex-1" />
        {/* Expand toggle */}
        <button
          onClick={(e) => { e.stopPropagation(); setExpanded(!expanded); }}
          className="flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-semibold text-slate-400 hover:text-white hover:bg-slate-800 transition-all"
        >
          {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          <span>{expanded ? 'Less' : `All ports (${ports.length})`}</span>
        </button>
        <button
          onClick={(e) => { e.stopPropagation(); onSelectHost && onSelectHost({ host, initialPort: null }); }}
          className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-bold bg-brand-cyan hover:bg-cyan-400 text-slate-950 transition-all"
        >
          Inspect <ExternalLink className="w-3 h-3" />
        </button>
      </div>

      {/* Expanded port detail */}
      {expanded && (
        <div className="border-t border-slate-800 p-4 space-y-2 animate-slide-up">
          {ports.length === 0 && (
            <p className="text-xs text-slate-500 italic py-2">No ports discovered.</p>
          )}
          {ports.map((p) => {
            const svc = p.service || {};
            const portId = p.portid || p.port;
            const isExpanded = expandedPort === portId;
            const scripts = p.scripts || [];
            const banner = svc.banner || p.banner || '';

            return (
              <div key={`${portId}-${p.protocol}`}>
                <div
                  onClick={() => setExpandedPort(isExpanded ? null : portId)}
                  className={`flex items-center justify-between p-2.5 rounded-xl cursor-pointer transition-all ${
                    isExpanded ? 'bg-dark-850 border border-brand-cyan/30' : 'bg-dark-950 border border-slate-800/50 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-xs font-bold text-brand-cyan">{portId}/{p.protocol || 'tcp'}</span>
                    <span className="text-xs text-slate-200 font-medium">{svc.name || 'unknown'}</span>
                    {svc.product && <span className="text-[10px] text-slate-400 truncate">{svc.product} {svc.version || ''}</span>}
                  </div>
                  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                    (p.state || '').toLowerCase() === 'open' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                    (p.state || '').toLowerCase() === 'filtered' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                    'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}>{p.state || 'unknown'}</span>
                </div>
                {isExpanded && (
                  <div className="mx-1 mb-1 p-3 rounded-b-xl bg-dark-950 border border-t-0 border-slate-800 animate-slide-up text-xs space-y-2">
                    {banner && (
                      <div><span className="text-[10px] font-bold text-slate-500 uppercase">Banner</span>
                        <p className="mt-0.5 text-slate-300 font-mono break-all">{banner}</p></div>
                    )}
                    {scripts.length > 0 && (
                      <div><span className="text-[10px] font-bold text-slate-500 uppercase">Scripts</span>
                        {scripts.map((s, si) => (
                          <div key={si} className="mt-1 p-2 rounded bg-slate-900 border border-slate-800">
                            <span className="text-[10px] font-bold text-cyan-400">{s.id || s.script_id}</span>
                            <pre className="mt-0.5 text-[10px] text-slate-300 whitespace-pre-wrap break-all font-mono max-h-20 overflow-y-auto">{s.output || s.result || ''}</pre>
                          </div>
                        ))}</div>
                    )}
                    {!banner && !scripts.length && (svc.product || svc.extrainfo) && (
                      <p className="text-slate-400 font-mono text-[10px]">{[svc.product, svc.version, svc.extrainfo].filter(Boolean).join(' ')}</p>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/**
 * HostCards — the card-based inventory view. Replaces the old AG Grid table.
 * Shows one card per host with expandable port detail, tag chips, quick actions,
 * and staggered entrance animation.
 */
export default function HostCards({ hosts, onSelectHost, onLaunchProtocol }) {
  const [search, setSearch] = useState('');
  const [activeFilter, setActiveFilter] = useState('all');

  if (!hosts || hosts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500 p-8">
        <Wifi className="w-12 h-12 mb-3 text-slate-600" />
        <p className="text-sm font-medium mb-1">No hosts discovered yet</p>
        <p className="text-xs text-slate-600 max-w-xs text-center">
          Run a scan from the Home tab to populate your inventory.
        </p>
      </div>
    );
  }

  // Filter hosts based on search + quick filter
  const filtered = hosts.filter((h) => {
    const ip = (h.ip || h.ipv4 || '').toLowerCase();
    const hn = (h.primary_hostname || h.hostname || '').toLowerCase();
    const os = (h.primary_os || '').toLowerCase();
    const mac = (h.mac || '').toLowerCase();
    const tags = (h.tags || []).map((t) => t.toLowerCase());
    const q = search.toLowerCase();

    const matchesSearch = !q || ip.includes(q) || hn.includes(q) || os.includes(q) || mac.includes(q) || tags.some((t) => t.includes(q));

    if (!matchesSearch) return false;

    switch (activeFilter) {
      case 'tagged':
        return (h.tags || []).length > 0;
      case 'cves':
        return (h.cves || []).length > 0;
      case 'critical':
        return h.severity === 'CRITICAL' || (h.max_cvss || 0) >= 9.0;
      case 'needs_update':
        return (h.tags || []).includes('needs update');
      default:
        return true;
    }
  });

  const FILTERS = [
    { id: 'all', label: 'All', icon: Filter },
    { id: 'tagged', label: 'Tagged', icon: Tag },
    { id: 'cves', label: 'CVEs', icon: ShieldAlert },
    { id: 'critical', label: 'Critical', icon: Sparkles },
  ];

  return (
    <div className="flex flex-col h-full bg-dark-900 overflow-hidden">
      {/* Filter bar */}
      <div className="p-4 border-b border-slate-800 bg-dark-950/90 flex items-center gap-3 shrink-0 flex-wrap">
        <div className="flex items-center gap-2">
          <Wifi className="w-4 h-4 text-brand-cyan" />
          <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">Inventory</span>
          <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
            {hosts.length} hosts
          </span>
          {filtered.length !== hosts.length && (
            <span className="text-[10px] text-cyan-400 font-semibold">· {filtered.length} visible</span>
          )}
        </div>

        {/* Quick filters */}
        <div className="flex items-center gap-1.5">
          {FILTERS.map((f) => (
            <button
              key={f.id}
              onClick={() => setActiveFilter(activeFilter === f.id ? 'all' : f.id)}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold transition-all ${
                activeFilter === f.id
                  ? 'bg-brand-cyan text-slate-950'
                  : 'bg-slate-800 text-slate-400 border border-slate-700 hover:text-slate-200'
              }`}
            >
              <f.icon className="w-3 h-3" />
              {f.label}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative ml-auto w-56">
          <Search className="w-3 h-3 text-slate-400 absolute left-2.5 top-2" />
          <input
            type="text"
            placeholder="Filter hosts..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-dark-900 border border-slate-700 focus:border-brand-cyan rounded-lg pl-8 pr-7 py-1.5 text-[11px] text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-brand-cyan transition-all"
          />
          {search && (
            <button onClick={() => setSearch('')} className="absolute right-2 top-2 text-slate-400 hover:text-white">
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Cards grid */}
      <div className="flex-1 overflow-y-auto p-4">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-slate-500 text-xs italic">
            <Search className="w-5 h-5 mb-1.5 text-slate-600" />
            No hosts match your filter.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {filtered.map((host, idx) => (
              <HostCard
                key={host.ip || host.ipv4 || idx}
                host={host}
                onSelectHost={onSelectHost}
                onLaunchProtocol={onLaunchProtocol}
                index={idx}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}