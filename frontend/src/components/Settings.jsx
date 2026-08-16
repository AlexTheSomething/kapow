import React, { useState } from 'react';
import { X, Clock, Bell, Moon, RefreshCw, Info } from 'lucide-react';

/**
 * Settings — small modal with preferences. Scan scheduling lives here,
 * out of the way, per the blueprint.
 */
export default function Settings({ onClose, dependencies, onRefreshDeps }) {
  const [autoScanEnabled, setAutoScanEnabled] = useState(false);
  const [interval, setIntervalMins] = useState(30);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in" onClick={onClose}>
      <div
        className="w-[480px] max-h-[80vh] overflow-y-auto bg-dark-900 border border-slate-700 rounded-2xl shadow-2xl animate-slide-up"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between sticky top-0 bg-dark-900 rounded-t-2xl z-10">
          <h2 className="text-sm font-bold text-white">Settings</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-6">
          {/* Scan scheduling */}
          <section>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Clock className="w-3.5 h-3.5" /> Automatic Scans
            </h3>
            <div className="flex items-center justify-between p-3 rounded-xl bg-dark-950 border border-slate-800">
              <div>
                <div className="text-xs font-semibold text-slate-200">Periodic LAN scan</div>
                <div className="text-[10px] text-slate-500 mt-0.5">Scan your LAN on a schedule and alert on changes</div>
              </div>
              <button
                onClick={() => setAutoScanEnabled(!autoScanEnabled)}
                className={`relative w-10 h-5 rounded-full transition-colors ${autoScanEnabled ? 'bg-brand-cyan' : 'bg-slate-700'}`}
              >
                <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${autoScanEnabled ? 'left-5' : 'left-0.5'}`} />
              </button>
            </div>
            {autoScanEnabled && (
              <div className="mt-2 p-3 rounded-xl bg-dark-950 border border-slate-800 flex items-center gap-3 animate-slide-up">
                <span className="text-xs text-slate-400">Every</span>
                <input
                  type="number"
                  min="5"
                  max="1440"
                  value={interval}
                  onChange={(e) => setIntervalMins(parseInt(e.target.value) || 30)}
                  className="w-20 bg-dark-900 border border-slate-700 rounded-lg px-2 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-brand-cyan"
                />
                <span className="text-xs text-slate-400">minutes</span>
                <span className="text-[10px] text-amber-400 ml-auto">Coming soon — scheduling backend lands after the UI rebuild</span>
              </div>
            )}
          </section>

          {/* Dependencies */}
          <section>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <RefreshCw className="w-3.5 h-3.5" /> CLI Tools
            </h3>
            <div className="space-y-2">
              {[
                { key: 'nmap', label: 'Nmap', required: true },
                { key: 'rustscan', label: 'RustScan' },
                { key: 'masscan', label: 'Masscan' },
                { key: 'naabu', label: 'Naabu' },
              ].map((tool) => {
                const info = dependencies?.[tool.key];
                const installed = info?.installed;
                return (
                  <div key={tool.key} className="flex items-center justify-between p-2.5 rounded-xl bg-dark-950 border border-slate-800 text-xs">
                    <span className="text-slate-200 font-medium">
                      {tool.label} {tool.required && <span className="text-[9px] text-rose-400 font-bold ml-1">REQUIRED</span>}
                    </span>
                    <span className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${installed ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                      <span className={`text-[10px] font-semibold ${installed ? 'text-emerald-400' : 'text-rose-400'}`}>
                        {installed ? 'installed' : 'missing'}
                      </span>
                    </span>
                  </div>
                );
              })}
            </div>
            <button
              onClick={onRefreshDeps}
              className="mt-2 text-[10px] font-semibold text-cyan-400 hover:text-cyan-300"
            >
              ↻ Re-check tools
            </button>
          </section>

          {/* About */}
          <section>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Info className="w-3.5 h-3.5" /> About
            </h3>
            <div className="p-3 rounded-xl bg-dark-950 border border-slate-800 text-xs text-slate-400 space-y-1">
              <p><span className="text-slate-200 font-semibold">Kapow</span> v2.0 — Network Auditor</p>
              <p className="text-[10px]">Know your network. Catch what changes. Reach any device.</p>
              <p className="text-[10px] text-slate-600">github.com/AlexTheSomething/kapow</p>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}