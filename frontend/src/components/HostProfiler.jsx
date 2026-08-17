import React, { useState, useEffect } from 'react';
import { ArrowLeft, Server, Wifi, Globe, Terminal, Shield, Activity, Clock, Save, Plus } from 'lucide-react';
import TagChip from './TagChip';

/**
 * HostProfiler — full-screen drill-down for a single host.
 * Displays: ports, OS, telemetry, tags, notes, CVE hints, quick actions.
 */
export default function HostProfiler({ host, initialPort, scanData, onBack, onSaveAsset, onLaunchProtocol, onPingTelemetry }) {
  const [telemetry, setTelemetry] = useState(null);
  const [tags, setTags] = useState([]);
  const [tagInput, setTagInput] = useState('');
  const [notes, setNotes] = useState('');
  const [alias, setAlias] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [expandedPort, setExpandedPort] = useState(initialPort || null);

  const ip = host?.ip || host?.ipv4 || host?.data?.ip || '';
  const hostname = host?.primary_hostname || host?.hostname || host?.data?.label || '';
  const os = host?.primary_os || host?.os || '';
  const mac = host?.mac || host?.data?.mac || '';
  const vendor = host?.vendor || host?.data?.vendor || '';
  const ports = host?.ports || (host?.data?.ports || []);
  const cves = host?.cves || (host?.data?.cves || []);
  const savedTags = Array.isArray(host?.tags) ? host.tags : [];

  // Populate from existing asset data
  useEffect(() => {
    setTags(savedTags || []);
    setAlias(host?.alias || '');
    setNotes(host?.notes || '');
  }, [host]);

  // Load telemetry
  useEffect(() => {
    if (!ip) return;
    let cancelled = false;
    const fetchPing = async () => {
      if (onPingTelemetry) {
        const res = await onPingTelemetry(ip);
        if (!cancelled && res?.success) setTelemetry(res);
      }
    };
    fetchPing();
    const interval = setInterval(fetchPing, 3000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [ip]);

  const addTag = () => {
    const tag = tagInput.trim();
    if (tag && !tags.includes(tag)) {
      setTags([...tags, tag]);
    }
    setTagInput('');
  };

  const removeTag = (t) => setTags(tags.filter((x) => x !== t));

  const handleSave = async () => {
    setSaving(true);
    if (onSaveAsset) {
      await onSaveAsset({
        ip,
        mac,
        alias,
        tags,
        notes,
        risk_level: 'LOW',
      });
    }
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const rtt = telemetry?.current_latency;
  const pingDot = rtt !== null ? (rtt < 2 ? '🟢' : rtt < 10 ? '🟡' : '🔴') : '⚫';
  const pingColor = rtt !== null ? (rtt < 2 ? 'text-emerald-400' : rtt < 10 ? 'text-amber-400' : 'text-rose-400') : 'text-slate-500';

  return (
    <div className="flex flex-col h-full w-full bg-dark-950 overflow-hidden select-none animate-drill-zoom">
      {/* ── Header ── */}
      <div className="p-4 bg-dark-900 border-b border-slate-800 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-base font-bold text-cyan-300">{ip}</span>
              {hostname && <span className="text-sm text-slate-400 font-mono">({hostname})</span>}
              <span className={`text-xs font-semibold ${pingColor}`}>{pingDot} {rtt !== null ? `${rtt.toFixed(1)} ms` : '—'}</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-500 mt-0.5">
              {os && <span className="flex items-center gap-1"><Server className="w-3 h-3" />{os}</span>}
              {mac && <span className="flex items-center gap-1">MAC: {mac}</span>}
              {vendor && <span className="text-slate-500">{vendor}</span>}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => onLaunchProtocol?.('http', ip)}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/25 transition-all flex items-center gap-1"
          ><Globe className="w-3.5 h-3.5" />HTTP</button>
          <button
            onClick={() => onLaunchProtocol?.('ssh', ip, 22)}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 hover:bg-indigo-500/25 transition-all flex items-center gap-1"
          ><Terminal className="w-3.5 h-3.5" />SSH</button>
          <button
            onClick={() => onLaunchProtocol?.('rdp', ip, 3389)}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-violet-500/10 text-violet-400 border border-violet-500/30 hover:bg-violet-500/25 transition-all flex items-center gap-1"
          ><Shield className="w-3.5 h-3.5" />RDP</button>
          <button
            onClick={() => onLaunchProtocol?.('smb', ip, 445)}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-700/50 text-slate-300 border border-slate-600 hover:bg-slate-700 transition-all flex items-center gap-1"
          ><Server className="w-3.5 h-3.5" />SMB</button>
        </div>
      </div>

      {/* ── Body ── */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Tags + Alias */}
        <div className="bg-dark-900 border border-slate-800 rounded-2xl p-4 animate-slide-up">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Tags & Identity</h3>
          <div className="flex items-center gap-2 flex-wrap mb-3">
            {tags.map((t) => (
              <TagChip key={t} tag={t} color="cyan" animated onRemove={removeTag} />
            ))}
            <div className="flex items-center gap-1">
              <input
                type="text"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') addTag(); }}
                placeholder="Add tag..."
                className="w-24 bg-dark-950 border border-slate-700 rounded-lg px-2 py-1 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-brand-cyan"
              />
              <button onClick={addTag} className="p-1 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-all">
                <Plus className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500">Alias:</span>
            <input
              type="text"
              value={alias}
              onChange={(e) => setAlias(e.target.value)}
              placeholder="e.g. gateway, macbook, nas"
              className="flex-1 max-w-xs bg-dark-950 border border-slate-700 rounded-lg px-2 py-1 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-brand-cyan"
            />
          </div>
        </div>

        {/* Ports */}
        {ports?.length > 0 && (
          <div className="bg-dark-900 border border-slate-800 rounded-2xl p-4 animate-slide-up" style={{ animationDelay: '40ms' }}>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Wifi className="w-3.5 h-3.5" /> Open Ports & Services ({ports.length})
            </h3>
            <div className="space-y-2">
              {ports.map((port, idx) => {
                const p = port.data || port;
                const svc = p.service || {};
                const serviceName = svc.name || 'unknown';
                const portId = p.portid || p.port;
                const isExpanded = expandedPort === portId;
                const scripts = p.scripts || [];
                const banner = svc.banner || p.banner || '';
                const isHttp = serviceName === 'http' || serviceName === 'https';
                const isSsh = portId === 22 || serviceName === 'ssh';
                const isRdp = portId === 3389 || serviceName === 'ms-wbt-server';
                const isSmb = portId === 445 || serviceName === 'microsoft-ds';

                return (
                  <div key={idx}>
                    <div
                      onClick={() => setExpandedPort(isExpanded ? null : portId)}
                      className={`flex items-center justify-between p-2.5 rounded-xl cursor-pointer transition-all ${
                        isExpanded ? 'bg-dark-850 border border-brand-cyan/30' : 'bg-dark-950 border border-slate-800/50 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <span className="font-mono text-sm font-bold text-brand-cyan shrink-0">{portId}/{p.protocol || 'tcp'}</span>
                        <div className="min-w-0">
                          <span className="text-sm text-slate-200 font-medium">{serviceName}</span>
                          {svc.product && <span className="text-xs text-slate-400 ml-1.5 truncate">{svc.product} {svc.version || ''}</span>}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {isHttp && (
                          <button onClick={(e) => { e.stopPropagation(); onLaunchProtocol?.('http', ip, portId); }} className="px-2 py-1 rounded-lg text-[10px] font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-all">Open</button>
                        )}
                        {isSsh && (
                          <button onClick={(e) => { e.stopPropagation(); onLaunchProtocol?.('ssh', ip, 22); }} className="px-2 py-1 rounded-lg text-[10px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 hover:bg-indigo-500/20 transition-all">SSH</button>
                        )}
                        {isRdp && (
                          <button onClick={(e) => { e.stopPropagation(); onLaunchProtocol?.('rdp', ip, 3389); }} className="px-2 py-1 rounded-lg text-[10px] font-semibold bg-violet-500/10 text-violet-400 border border-violet-500/20 hover:bg-violet-500/20 transition-all">RDP</button>
                        )}
                        {isSmb && (
                          <button onClick={(e) => { e.stopPropagation(); onLaunchProtocol?.('smb', ip, 445); }} className="px-2 py-1 rounded-lg text-[10px] font-semibold bg-slate-700/50 text-slate-300 border border-slate-600 hover:bg-slate-700 transition-all">SMB</button>
                        )}
                        <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">{p.state || 'open'}</span>
                      </div>
                    </div>
                    {/* Expando: banner + scripts */}
                    {isExpanded && (
                      <div className="mx-1 mb-1 p-3 rounded-b-xl bg-dark-950 border border-t-0 border-slate-800 animate-slide-up text-xs space-y-2">
                        {banner && (
                          <div>
                            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Banner</span>
                            <p className="mt-0.5 text-slate-300 font-mono break-all">{banner}</p>
                          </div>
                        )}
                        {scripts.length > 0 && (
                          <div>
                            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">NSE Scripts ({scripts.length})</span>
                            <div className="mt-1 space-y-1.5">
                              {scripts.map((s, si) => (
                                <div key={si} className="p-2 rounded bg-slate-900 border border-slate-800">
                                  <span className="text-[10px] font-bold text-cyan-400">{s.id || s.script_id || 'script'}</span>
                                  <pre className="mt-0.5 text-[10px] text-slate-300 whitespace-pre-wrap break-all font-mono leading-relaxed max-h-24 overflow-y-auto">
                                    {s.output || s.result || ''}
                                  </pre>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        {(svc.product || svc.extrainfo) && !banner && !scripts.length && (
                          <div>
                            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Service Details</span>
                            <p className="mt-0.5 text-slate-300 font-mono">
                              {[svc.product, svc.version, svc.extrainfo].filter(Boolean).join(' ')}
                            </p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Telemetry */}
        {telemetry && (
          <div className="bg-dark-900 border border-slate-800 rounded-2xl p-4 animate-slide-up" style={{ animationDelay: '80ms' }}>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Activity className="w-3.5 h-3.5" /> Ping Telemetry
            </h3>
            <div className="grid grid-cols-4 gap-3">
              <div className="p-3 rounded-xl bg-dark-950 text-center">
                <div className={`text-xl font-bold font-mono ${pingColor}`}>{rtt !== null ? rtt.toFixed(1) : '—'}</div>
                <div className="text-[10px] text-slate-500">ms RTT</div>
              </div>
              <div className="p-3 rounded-xl bg-dark-950 text-center">
                <div className="text-xl font-bold font-mono text-slate-200">{telemetry?.jitter?.toFixed(1) || '—'}</div>
                <div className="text-[10px] text-slate-500">ms jitter</div>
              </div>
              <div className="p-3 rounded-xl bg-dark-950 text-center">
                <div className="text-xl font-bold font-mono text-slate-200">{telemetry?.packet_loss_pct?.toFixed(0) || 0}%</div>
                <div className="text-[10px] text-slate-500">loss</div>
              </div>
              <div className="p-3 rounded-xl bg-dark-950 text-center">
                <div className="text-xl font-bold font-mono text-slate-200">{telemetry?.samples_count || 0}</div>
                <div className="text-[10px] text-slate-500">samples</div>
              </div>
            </div>
          </div>
        )}

        {/* CVE Hints */}
        {cves?.length > 0 && (
          <div className="bg-dark-900 border border-slate-800 rounded-2xl p-4 animate-slide-up" style={{ animationDelay: '120ms' }}>
            <h3 className="text-xs font-bold text-amber-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Shield className="w-3.5 h-3.5" /> CVE Hints ({cves.length})
            </h3>
            <div className="space-y-2">
              {cves.map((cve, idx) => (
                <div key={idx} className="p-2.5 rounded-xl bg-amber-500/5 border border-amber-500/15 text-xs">
                  <span className="font-bold text-amber-300">{cve.cve_id || cve.id}</span>
                  <span className="ml-2 text-slate-400">{cve.description || cve.details || ''}</span>
                  {cve.severity && (
                    <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                      cve.severity === 'HIGH' ? 'bg-rose-500/15 text-rose-400' :
                      cve.severity === 'MEDIUM' ? 'bg-amber-500/15 text-amber-400' :
                      'bg-slate-500/15 text-slate-400'
                    }`}>{cve.severity}</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Notes */}
        <div className="bg-dark-900 border border-slate-800 rounded-2xl p-4 animate-slide-up" style={{ animationDelay: '160ms' }}>
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Notes</h3>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Add notes about this host... (supports markdown)"
            rows={4}
            className="w-full bg-dark-950 border border-slate-700 rounded-xl px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-brand-cyan resize-y"
          />
        </div>
      </div>

      {/* ── Footer Save ── */}
      <div className="p-4 bg-dark-900 border-t border-slate-800 flex items-center justify-between shrink-0">
        <span className="text-xs text-slate-500">
          {saved ? '✓ Saved to asset database' : 'Changes are local until saved.'}
        </span>
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold bg-brand-cyan hover:bg-cyan-400 text-slate-950 shadow-glow-cyan transition-all disabled:opacity-50"
        >
          <Save className="w-3.5 h-3.5" />
          <span>{saving ? 'Saving...' : 'Save'}</span>
        </button>
      </div>
    </div>
  );
}