import React, { useState, useEffect } from 'react';
import { GitCompare, PlusCircle, MinusCircle, AlertCircle, CheckCircle, Server, Layers, ArrowRight, ShieldAlert } from 'lucide-react';

export default function ScanDiff({ scanHistory, currentScan, onCompareScans }) {
  const [baselineId, setBaselineId] = useState('');
  const [comparisonId, setComparisonId] = useState('');
  const [diffResult, setDiffResult] = useState(null);

  // Available scans list including current scan and history items
  const availableScans = [
    ...(currentScan ? [{ id: 'current', label: `Current Scan: ${currentScan.target || 'Live'}`, data: currentScan }] : []),
    ...scanHistory.map((s, idx) => ({ id: `hist-${s.id || idx}`, label: `${s.target} (${s.timestamp || 'Previous'})`, data: s.data || s })),
  ];

  useEffect(() => {
    if (availableScans.length >= 2) {
      if (!baselineId) setBaselineId(availableScans[1].id);
      if (!comparisonId) setComparisonId(availableScans[0].id);
    } else if (availableScans.length === 1) {
      setComparisonId(availableScans[0].id);
    }
  }, [availableScans.length]);

  const handleRunDiff = async () => {
    const scanA = availableScans.find((s) => s.id === baselineId)?.data;
    const scanB = availableScans.find((s) => s.id === comparisonId)?.data;

    if (!scanA || !scanB) return;

    if (onCompareScans) {
      const res = await onCompareScans(scanA, scanB);
      setDiffResult(res);
    }
  };

  useEffect(() => {
    if (baselineId && comparisonId && baselineId !== comparisonId) {
      handleRunDiff();
    }
  }, [baselineId, comparisonId]);

  return (
    <div className="flex flex-col h-full w-full bg-dark-950 text-slate-200 overflow-hidden select-none">
      {/* Top Controls & Selectors Bar */}
      <div className="p-4 bg-dark-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/15 text-cyan-400">
            <GitCompare className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-xs font-bold uppercase tracking-wider text-white">
              Scan Diff & Drift Detector ("Time Machine")
            </h2>
            <p className="text-[11px] text-slate-400">Compare network snapshots to spot rogue hosts and port exposure</p>
          </div>
        </div>

        {/* Scan Selectors */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-semibold">Baseline:</span>
            <select
              value={baselineId}
              onChange={(e) => setBaselineId(e.target.value)}
              className="bg-dark-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-brand-cyan"
            >
              <option value="">Select baseline scan...</option>
              {availableScans.map((s) => (
                <option key={s.id} value={s.id}>{s.label}</option>
              ))}
            </select>
          </div>

          <ArrowRight className="w-4 h-4 text-slate-500" />

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-semibold">Comparison:</span>
            <select
              value={comparisonId}
              onChange={(e) => setComparisonId(e.target.value)}
              className="bg-dark-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-brand-cyan"
            >
              <option value="">Select comparison scan...</option>
              {availableScans.map((s) => (
                <option key={s.id} value={s.id}>{s.label}</option>
              ))}
            </select>
          </div>

          <button
            onClick={handleRunDiff}
            disabled={!baselineId || !comparisonId || baselineId === comparisonId}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-brand-cyan hover:bg-cyan-400 text-slate-950 shadow-glow-cyan transition-all disabled:opacity-40"
          >
            Compute Diff
          </button>
        </div>
      </div>

      {/* Main Diff Content */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {(!diffResult || !diffResult.summary) ? (
          <div className="flex flex-col items-center justify-center h-64 text-slate-500 italic">
            <GitCompare className="w-12 h-12 mb-3 text-slate-600 animate-pulse" />
            <p>Select two different scans above to analyze added devices, closed ports, and service changes.</p>
            {availableScans.length < 2 && (
              <p className="text-xs text-slate-600 mt-1">Run another scan to create baseline snapshots.</p>
            )}
          </div>
        ) : (
          <>
            {/* Summary Metrics Bar */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between">
                <div>
                  <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider block">New Hosts Joined</span>
                  <span className="text-2xl font-bold font-mono text-white">+{diffResult.summary.added_hosts_count}</span>
                </div>
                <PlusCircle className="w-7 h-7 text-emerald-400" />
              </div>

              <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-between">
                <div>
                  <span className="text-[11px] font-bold text-rose-400 uppercase tracking-wider block">Hosts Removed / Offline</span>
                  <span className="text-2xl font-bold font-mono text-white">-{diffResult.summary.removed_hosts_count}</span>
                </div>
                <MinusCircle className="w-7 h-7 text-rose-400" />
              </div>

              <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-between">
                <div>
                  <span className="text-[11px] font-bold text-amber-400 uppercase tracking-wider block">Newly Opened Ports</span>
                  <span className="text-2xl font-bold font-mono text-white">+{diffResult.summary.total_opened_ports}</span>
                </div>
                <AlertCircle className="w-7 h-7 text-amber-400" />
              </div>

              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block">Unchanged Hosts</span>
                  <span className="text-2xl font-bold font-mono text-slate-300">{diffResult.summary.unchanged_hosts_count}</span>
                </div>
                <CheckCircle className="w-7 h-7 text-slate-500" />
              </div>
            </div>

            {/* Added Hosts Section */}
            {diffResult.added_hosts?.length > 0 && (
              <div>
                <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <PlusCircle className="w-4 h-4" />
                  Newly Discovered Hosts (+{diffResult.added_hosts.length})
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {diffResult.added_hosts.map((h, idx) => (
                    <div key={idx} className="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/30 flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm font-bold text-emerald-300">{h.ip || h.ipv4}</span>
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 font-semibold">NEW</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">{h.primary_hostname || h.hostname || 'No hostname'}</p>
                        <p className="text-xs text-slate-500">{h.primary_os || 'Unknown OS'}</p>
                      </div>
                      <span className="text-xs font-mono px-2 py-1 rounded bg-slate-800 text-emerald-400">
                        {(h.ports || []).length} open ports
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Modified Hosts Section */}
            {diffResult.modified_hosts?.length > 0 && (
              <div>
                <h3 className="text-xs font-bold text-amber-400 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <AlertCircle className="w-4 h-4" />
                  Modified Hosts & Port Exposure Changes ({diffResult.modified_hosts.length})
                </h3>
                <div className="space-y-3">
                  {diffResult.modified_hosts.map((mh, idx) => (
                    <div key={idx} className="p-4 rounded-xl bg-dark-900 border border-slate-800 space-y-3">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                        <div className="flex items-center gap-2">
                          <Server className="w-4 h-4 text-cyan-400" />
                          <span className="font-mono font-bold text-white text-sm">{mh.ip}</span>
                          {mh.hostname && <span className="text-xs text-slate-400 font-mono">({mh.hostname})</span>}
                        </div>
                        {mh.os_changed && (
                          <span className="text-xs text-amber-400">OS Drift: {mh.os_before} ➔ {mh.os_after}</span>
                        )}
                      </div>

                      {/* Newly opened ports on this host */}
                      {mh.opened_ports?.length > 0 && (
                        <div>
                          <span className="text-[11px] font-semibold text-emerald-400 block mb-1.5">+ Newly Opened Ports:</span>
                          <div className="flex flex-wrap gap-2">
                            {mh.opened_ports.map((op, oIdx) => (
                              <span key={oIdx} className="px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 font-mono text-xs">
                                + {op.portid}/{op.protocol} ({op.service?.name || 'unknown'})
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Closed ports on this host */}
                      {mh.closed_ports?.length > 0 && (
                        <div>
                          <span className="text-[11px] font-semibold text-rose-400 block mb-1.5">- Closed Ports:</span>
                          <div className="flex flex-wrap gap-2">
                            {mh.closed_ports.map((cp, cIdx) => (
                              <span key={cIdx} className="px-2.5 py-1 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 font-mono text-xs">
                                - {cp.portid}/{cp.protocol} ({cp.service?.name || 'unknown'})
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Changed service versions */}
                      {mh.changed_services?.length > 0 && (
                        <div>
                          <span className="text-[11px] font-semibold text-cyan-400 block mb-1.5">~ Service Version Changes:</span>
                          <div className="space-y-1 text-xs font-mono">
                            {mh.changed_services.map((cs, sIdx) => (
                              <div key={sIdx} className="p-2 rounded bg-dark-950 border border-slate-800 text-slate-300 flex items-center justify-between">
                                <span>Port {cs.port}/{cs.protocol}:</span>
                                <span className="text-slate-400">{cs.before} <span className="text-cyan-400 font-bold">➔</span> <span className="text-emerald-400">{cs.after}</span></span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Removed Hosts Section */}
            {diffResult.removed_hosts?.length > 0 && (
              <div>
                <h3 className="text-xs font-bold text-rose-400 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <MinusCircle className="w-4 h-4" />
                  Offline / Decommissioned Hosts (-{diffResult.removed_hosts.length})
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {diffResult.removed_hosts.map((h, idx) => (
                    <div key={idx} className="p-4 rounded-xl bg-rose-500/5 border border-rose-500/30 flex items-start justify-between opacity-80">
                      <div>
                        <span className="font-mono text-sm font-bold text-rose-300 line-through">{h.ip || h.ipv4}</span>
                        <p className="text-xs text-slate-400 mt-1">{h.primary_hostname || h.hostname || 'No hostname'}</p>
                      </div>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-semibold">REMOVED</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
