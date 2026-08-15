import React, { useState } from 'react';
import { Server, Laptop, Router as RouterIcon, Shield, Layers, GitCommit, Copy, Check, Clock, ExternalLink, Tag, Save, ShieldAlert, AlertTriangle, Edit3 } from 'lucide-react';
import QuickActions from './QuickActions';

export default function HostProfiler({ hosts, onSaveAsset, onSelectHostModal, onLaunchProtocol, onSendWol, onOpenTelemetry }) {
  const [selectedIp, setSelectedIp] = useState(hosts?.[0]?.ip || hosts?.[0]?.ipv4 || null);
  const [copiedIp, setCopiedIp] = useState(false);

  const activeHost = (hosts || []).find((h) => (h.ip || h.ipv4) === selectedIp) || hosts?.[0];

  // Editable Asset Metadata State
  const [alias, setAlias] = useState(activeHost?.alias || '');
  const [owner, setOwner] = useState(activeHost?.owner || '');
  const [tagsText, setTagsText] = useState((activeHost?.tags || []).join(', '));
  const [notes, setNotes] = useState(activeHost?.notes || '');
  const [riskLevel, setRiskLevel] = useState(activeHost?.risk_level || 'LOW');
  const [saveSuccess, setSaveSuccess] = useState(false);

  // Sync state when active host changes
  React.useEffect(() => {
    if (activeHost) {
      setAlias(activeHost.alias || '');
      setOwner(activeHost.owner || '');
      setTagsText((activeHost.tags || []).join(', '));
      setNotes(activeHost.notes || '');
      setRiskLevel(activeHost.risk_level || 'LOW');
      setSaveSuccess(false);
    }
  }, [activeHost?.ip, activeHost?.ipv4]);

  if (!hosts || hosts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500 italic p-8">
        <Server className="w-12 h-12 mb-3 text-slate-600 animate-pulse" />
        <p>No host profile records available. Run a network scan to populate host diagnostics.</p>
      </div>
    );
  }

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 1500);
  };

  const handleSaveMetadata = async () => {
    if (!activeHost || !onSaveAsset) return;
    const tagsArray = tagsText.split(',').map((t) => t.strip ? t.strip() : t.trim()).filter(Boolean);
    const payload = {
      ip: activeHost.ip || activeHost.ipv4,
      mac: activeHost.mac || '',
      alias,
      owner,
      tags: tagsArray,
      notes,
      risk_level: riskLevel,
    };

    const res = await onSaveAsset(payload);
    if (res && res.success) {
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2000);
    }
  };

  const ports = activeHost?.ports || [];
  const osMatches = activeHost?.os_matches || [];
  const traceroute = activeHost?.traceroute || [];
  const cves = activeHost?.cves || [];
  const uptime = activeHost?.uptime;

  return (
    <div className="flex h-full w-full bg-dark-950 overflow-hidden select-none">
      {/* Left Hosts Sidebar */}
      <div className="w-72 border-r border-slate-800 bg-dark-900 flex flex-col shrink-0">
        <div className="p-3 border-b border-slate-800 bg-dark-950 flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-brand-cyan" />
            Network Hosts ({hosts.length})
          </span>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 p-2 space-y-1">
          {hosts.map((h, idx) => {
            const ip = h.ip || h.ipv4 || `Host ${idx + 1}`;
            const isSelected = (activeHost?.ip || activeHost?.ipv4) === ip;
            const openCount = (h.ports || []).filter((p) => p.state === 'open').length;
            const isCritical = h.risk_level === 'CRITICAL' || (h.max_cvss && h.max_cvss >= 9.0);

            return (
              <button
                key={idx}
                onClick={() => setSelectedIp(ip)}
                className={`w-full text-left p-2.5 rounded-xl transition-all flex items-start gap-2.5 ${
                  isSelected 
                    ? 'bg-cyan-500/15 border border-cyan-500/40 text-white shadow-sm' 
                    : 'hover:bg-slate-800/60 text-slate-300 border border-transparent'
                }`}
              >
                <div className={`p-1.5 rounded-lg shrink-0 mt-0.5 ${isCritical ? 'bg-rose-500/20 text-rose-400' : 'bg-dark-950/80 text-cyan-400'}`}>
                  <Laptop className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-slate-100 truncate">
                      {h.alias || ip}
                    </span>
                    <span className={`w-2 h-2 rounded-full shrink-0 ${isCritical ? 'bg-rose-500 animate-pulse' : 'bg-emerald-400'}`} />
                  </div>
                  <p className="text-[11px] text-slate-400 truncate mt-0.5">
                    {h.alias ? ip : h.primary_hostname || h.vendor || 'Unknown device'}
                  </p>
                  <div className="flex items-center gap-2 mt-1.5">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-emerald-400">
                      {openCount} ports
                    </span>
                    {h.cves && h.cves.length > 0 && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 font-bold">
                        {h.cves.length} CVEs
                      </span>
                    )}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Right Host Detail Dashboard */}
      {activeHost && (
        <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-dark-950">
          
          {/* Host Header Card */}
          <div className="p-5 rounded-2xl glass-panel border border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 p-0.5 flex items-center justify-center shadow-glow-cyan">
                <div className="w-full h-full bg-dark-900 rounded-[10px] flex items-center justify-center">
                  <Server className="w-6 h-6 text-brand-neon" />
                </div>
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h2 className="text-xl font-bold font-mono text-white tracking-tight">
                    {alias || activeHost.ip || activeHost.ipv4}
                  </h2>
                  <button
                    onClick={() => handleCopy(activeHost.ip || activeHost.ipv4)}
                    className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-all"
                    title="Copy IP"
                  >
                    {copiedIp ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                    {activeHost.status?.state?.toUpperCase() || 'ONLINE'}
                  </span>
                  {riskLevel === 'CRITICAL' && (
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40">
                      CRITICAL RISK
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  IP: <span className="text-cyan-300 font-mono font-bold mr-3">{activeHost.ip || activeHost.ipv4}</span>
                  Hostname: <span className="text-slate-200 font-mono">{activeHost.primary_hostname || 'None'}</span>
                </p>
              </div>
            </div>

            <button
              onClick={() => onSelectHostModal(activeHost)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all"
            >
              <span>Full Diagnostic Modal</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Quick Protocol Launchers */}
          <QuickActions
            ip={activeHost.ip || activeHost.ipv4}
            mac={activeHost.mac}
            ports={ports}
            onLaunchProtocol={onLaunchProtocol}
            onSendWol={onSendWol}
            onOpenTelemetry={onOpenTelemetry}
          />

          {/* Feature 7: Asset Tagging & Persistent SQLite Store */}
          <div className="p-5 rounded-2xl bg-dark-900 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-2">
                <Tag className="w-4 h-4" />
                Asset Metadata & Inventory Tagging (Persistent SQLite)
              </span>
              <button
                onClick={handleSaveMetadata}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-600/30 transition-all"
              >
                {saveSuccess ? <Check className="w-3.5 h-3.5 text-white" /> : <Save className="w-3.5 h-3.5" />}
                <span>{saveSuccess ? 'Saved to DB!' : 'Save Asset Info'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Custom Alias / Name:</label>
                <input
                  type="text"
                  value={alias}
                  onChange={(e) => setAlias(e.target.value)}
                  placeholder="e.g. Primary DC, CEO Laptop, Core Router"
                  className="w-full bg-dark-950 border border-slate-700 focus:border-brand-cyan rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Owner / Department:</label>
                <input
                  type="text"
                  value={owner}
                  onChange={(e) => setOwner(e.target.value)}
                  placeholder="e.g. DevOps, Security Ops, IT Staff"
                  className="w-full bg-dark-950 border border-slate-700 focus:border-brand-cyan rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Risk Classification:</label>
                <select
                  value={riskLevel}
                  onChange={(e) => setRiskLevel(e.target.value)}
                  className="w-full bg-dark-950 border border-slate-700 focus:border-brand-cyan rounded-xl px-3 py-2 text-slate-200 focus:outline-none font-semibold"
                >
                  <option value="LOW">LOW RISK</option>
                  <option value="MEDIUM">MEDIUM RISK</option>
                  <option value="HIGH">HIGH RISK</option>
                  <option value="CRITICAL">CRITICAL RISK</option>
                </select>
              </div>

              <div className="md:col-span-2">
                <label className="block text-slate-400 mb-1 font-semibold">Tags (comma separated):</label>
                <input
                  type="text"
                  value={tagsText}
                  onChange={(e) => setTagsText(e.target.value)}
                  placeholder="e.g. Production, Linux, DMZ, Critical-Asset"
                  className="w-full bg-dark-950 border border-slate-700 focus:border-brand-cyan rounded-xl px-3 py-2 text-cyan-300 placeholder-slate-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Admin Notes:</label>
                <input
                  type="text"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Maintenance notes, contact info..."
                  className="w-full bg-dark-950 border border-slate-700 focus:border-brand-cyan rounded-xl px-3 py-2 text-slate-300 placeholder-slate-500 focus:outline-none"
                />
              </div>
            </div>
          </div>

          {/* Feature 1: CVE Vulnerability Intelligence Card */}
          {cves.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-xs font-bold text-rose-400 uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Discovered Vulnerabilities & CVE Advisories ({cves.length})
              </h3>
              <div className="space-y-2.5">
                {cves.map((cve, cIdx) => (
                  <div key={cIdx} className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/30 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-bold text-rose-300">{cve.cve_id}</span>
                        <span className="text-xs font-semibold text-white">{cve.title}</span>
                      </div>
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                        CVSS {cve.cvss} ({cve.severity})
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">{cve.summary}</p>
                    <div className="p-2.5 rounded-xl bg-dark-950/80 border border-slate-800 text-xs text-emerald-300 font-mono">
                      <strong>Remediation:</strong> {cve.remediation}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Discovered Ports & Services Table */}
          <div>
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Layers className="w-4 h-4 text-brand-emerald" />
              Open Ports & Services ({ports.length})
            </h3>
            {ports.length > 0 ? (
              <div className="border border-slate-800 rounded-2xl overflow-hidden bg-dark-900 shadow-xl">
                <table className="w-full text-left text-xs">
                  <thead className="bg-dark-950 text-slate-400 font-semibold border-b border-slate-800">
                    <tr>
                      <th className="p-3">Port</th>
                      <th className="p-3">State</th>
                      <th className="p-3">Service</th>
                      <th className="p-3">Version & Software</th>
                      <th className="p-3">Vulnerability / NSE</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {ports.map((p, pIdx) => {
                      const svc = p.service || {};
                      const pCves = p.cves || [];
                      return (
                        <tr key={pIdx} className="hover:bg-slate-800/40 transition-colors">
                          <td className="p-3 font-bold text-cyan-300">
                            {p.portid}/{p.protocol}
                          </td>
                          <td className="p-3">
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                              {p.state}
                            </span>
                          </td>
                          <td className="p-3 text-indigo-300 font-bold">{svc.name || '—'}</td>
                          <td className="p-3 text-slate-300 font-sans text-xs">
                            {svc.product ? `${svc.product} ${svc.version || ''}` : svc.banner || '—'}
                          </td>
                          <td className="p-3 font-sans text-xs">
                            {pCves.length > 0 ? (
                              <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 font-bold font-mono text-[10px]">
                                {pCves[0].cve_id} (CVSS {pCves[0].cvss})
                              </span>
                            ) : (
                              <span className="text-slate-500 text-[11px]">No known CVEs</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-dark-900/60 border border-slate-800 text-xs text-slate-400 italic">
                No open ports discovered on this host.
              </div>
            )}
          </div>

          {/* OS Fingerprints */}
          {osMatches.length > 0 && (
            <div>
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4 text-brand-cyan" />
                OS Detection Fingerprints
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {osMatches.map((os, oIdx) => (
                  <div key={oIdx} className="p-3.5 rounded-xl bg-dark-900 border border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="font-semibold text-slate-200 text-xs">{os.name}</span>
                      {os.classes?.[0] && (
                        <span className="block text-[11px] text-slate-400 mt-0.5">
                          {os.classes[0].vendor} {os.classes[0].osfamily} ({os.classes[0].type})
                        </span>
                      )}
                    </div>
                    <span className="text-xs font-mono font-bold text-emerald-400 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                      {os.accuracy}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}
