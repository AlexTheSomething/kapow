import React from 'react';
import { X, Server, Shield, Globe, Clock, GitCommit, Layers, Terminal, AlertCircle, ShieldAlert, Tag } from 'lucide-react';
import QuickActions from './QuickActions';

export default function HostDetailModal({ host, allHostsData, onClose, onLaunchProtocol, onSendWol, onOpenTelemetry }) {
  if (!host) return null;

  // Find rich host record from parsed scan data if available
  const fullHost = (allHostsData || []).find((h) => h.ip === host.ip || h.ipv4 === host.ip) || host;

  const ports = fullHost.ports || [];
  const osMatches = fullHost.os_matches || [];
  const traceroute = fullHost.traceroute || [];
  const cves = fullHost.cves || [];
  const uptime = fullHost.uptime;
  const tags = fullHost.tags || [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200 select-none">
      <div className="relative w-full max-w-3xl max-h-[88vh] bg-dark-900 border border-slate-700/80 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-dark-950/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white font-mono">
                  {fullHost.alias || fullHost.ip || fullHost.ipv4}
                </h2>
                <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                  {fullHost.status?.state || 'UP'}
                </span>
                {fullHost.risk_level === 'CRITICAL' && (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40">
                    CRITICAL
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 font-mono">
                IP: {fullHost.ip || fullHost.ipv4} | Hostname: {fullHost.primary_hostname || fullHost.hostname || 'No reverse PTR'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-white hover:bg-slate-700 transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content Scrollable Area */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm">
          
          {/* Quick Actions Protocol Toolbar */}
          <QuickActions
            ip={fullHost.ip || fullHost.ipv4}
            mac={fullHost.mac}
            ports={ports}
            onLaunchProtocol={onLaunchProtocol}
            onSendWol={onSendWol}
            onOpenTelemetry={onOpenTelemetry}
          />

          {/* Quick Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3 rounded-xl bg-dark-950/70 border border-slate-800">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">MAC Address</span>
              <span className="font-mono text-xs text-slate-200">{fullHost.mac || '—'}</span>
            </div>
            <div className="p-3 rounded-xl bg-dark-950/70 border border-slate-800">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">Hardware Vendor</span>
              <span className="text-xs text-slate-200 truncate block">{fullHost.vendor || '—'}</span>
            </div>
            <div className="p-3 rounded-xl bg-dark-950/70 border border-slate-800">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">Network Distance</span>
              <span className="text-xs text-cyan-400 font-semibold">{fullHost.distance ? `${fullHost.distance} hop(s)` : 'Direct'}</span>
            </div>
            <div className="p-3 rounded-xl bg-dark-950/70 border border-slate-800">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">Uptime</span>
              <span className="text-xs text-slate-200">
                {uptime?.seconds ? `${Math.round(uptime.seconds / 86400)} days` : '—'}
              </span>
            </div>
          </div>

          {/* Tags & Owner Bar if present */}
          {(fullHost.owner || tags.length > 0) && (
            <div className="p-3 rounded-xl bg-dark-950/80 border border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <Tag className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-slate-400">Owner:</span>
                <span className="text-white font-semibold">{fullHost.owner || 'Unassigned'}</span>
              </div>
              {tags.length > 0 && (
                <div className="flex items-center gap-1.5">
                  {tags.map((t, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-[10px]">
                      #{t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* CVE Vulnerability Advisories */}
          {cves.length > 0 && (
            <div>
              <h3 className="text-xs font-bold text-rose-400 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Discovered CVE Advisories ({cves.length})
              </h3>
              <div className="space-y-2">
                {cves.map((cve, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs space-y-1">
                    <div className="flex items-center justify-between font-mono font-bold text-rose-300">
                      <span>{cve.cve_id} — {cve.title}</span>
                      <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300">CVSS {cve.cvss} ({cve.severity})</span>
                    </div>
                    <p className="text-slate-300 text-xs">{cve.summary}</p>
                    <p className="text-emerald-300 font-mono text-[11px]"><strong>Fix:</strong> {cve.remediation}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Operating System Detection */}
          <div>
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-brand-cyan" />
              OS Detection Matches
            </h3>
            {osMatches.length > 0 ? (
              <div className="space-y-2">
                {osMatches.map((os, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-dark-950/60 border border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="font-semibold text-slate-200 text-xs">{os.name}</span>
                      {os.classes && os.classes.length > 0 && (
                        <div className="flex gap-1.5 mt-1">
                          {os.classes.map((cls, cIdx) => (
                            <span key={cIdx} className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                              {cls.vendor} {cls.osfamily} ({cls.type})
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="text-right">
                      <span className="text-xs font-mono font-bold text-emerald-400">{os.accuracy}% match</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-3 rounded-xl bg-dark-950/40 border border-slate-800 text-xs text-slate-400">
                {fullHost.primary_os || fullHost.os_name || 'No OS fingerprints captured.'}
              </div>
            )}
          </div>

          {/* Open Ports & Services */}
          <div>
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-brand-emerald" />
              Discovered Services & Ports ({ports.length})
            </h3>
            {ports.length > 0 ? (
              <div className="border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-dark-950 text-slate-400 font-semibold border-b border-slate-800">
                    <tr>
                      <th className="p-2.5">Port</th>
                      <th className="p-2.5">State</th>
                      <th className="p-2.5">Service</th>
                      <th className="p-2.5">Version & Product</th>
                      <th className="p-2.5">NSE Script Output</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {ports.map((p, idx) => {
                      const svc = p.service || {};
                      const scripts = p.scripts || [];
                      return (
                        <tr key={idx} className="hover:bg-slate-800/40">
                          <td className="p-2.5 font-bold text-cyan-300">
                            {p.portid}/{p.protocol}
                          </td>
                          <td className="p-2.5">
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/15 text-emerald-400">
                              {p.state}
                            </span>
                          </td>
                          <td className="p-2.5 text-indigo-300">{svc.name || '—'}</td>
                          <td className="p-2.5 text-slate-300 font-sans text-xs">
                            {svc.product ? `${svc.product} ${svc.version || ''}` : svc.banner || '—'}
                          </td>
                          <td className="p-2.5 font-sans text-xs text-slate-400">
                            {scripts.length > 0 ? (
                              <div className="space-y-1">
                                {scripts.map((s, sIdx) => (
                                  <div key={sIdx} className="bg-dark-950 p-1.5 rounded border border-slate-800 text-[11px] font-mono text-cyan-300">
                                    <strong className="text-slate-400">{s.id}:</strong> {s.output}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              '—'
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-3 rounded-xl bg-dark-950/40 border border-slate-800 text-xs text-slate-400">
                No open ports identified.
              </div>
            )}
          </div>

          {/* Traceroute Path */}
          {traceroute.length > 0 && (
            <div>
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                <GitCommit className="w-4 h-4 text-indigo-400" />
                Traceroute Hops ({traceroute.length})
              </h3>
              <div className="p-3 rounded-xl bg-dark-950/60 border border-slate-800 space-y-2">
                {traceroute.map((hop, hIdx) => (
                  <div key={hIdx} className="flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center gap-2">
                      <span className="w-6 h-6 rounded-full bg-slate-800 flex items-center justify-center text-slate-400 text-[10px] font-bold">
                        {hop.ttl}
                      </span>
                      <span className="text-slate-200 font-semibold">{hop.ip}</span>
                      {hop.host && <span className="text-slate-500">({hop.host})</span>}
                    </div>
                    <span className="text-cyan-400">{hop.rtt ? `${hop.rtt} ms` : '—'}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-dark-950/80 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-all"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
}
