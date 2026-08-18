import React, { useState, useEffect } from 'react';
import { Play, Square, Zap, Eye, EyeOff, Sparkles, Radio, Wifi, Layers, ChevronDown, Save, Plus, X } from 'lucide-react';
import Topology from './Topology';
import ErrorBoundary from './ErrorBoundary';
import TagChip from './TagChip';

const QUICK_PROFILES = [
  { id: 'quick', label: 'Quick Scan', desc: 'Top 100 ports, ~2s' },
  { id: 'quick_plus', label: 'Quick + Services', desc: 'Service versions, ~10s' },
  { id: 'comprehensive', label: 'Comprehensive', desc: 'Deep fingerprint, ~15s' },
  { id: 'intense', label: 'Intense + Scripts', desc: 'Full NSE scripts, ~15s' },
  { id: 'ping_sweep', label: 'Ping Sweep', desc: 'Host discovery only' },
];

export default function Home({
  target, setTarget,
  scanProfile, setScanProfile,
  isScanning, onStartScan, onCancelScan,
  networkInterfaces = [],
  scanData, scanHistory = [],
  passiveDevices = [],
  suggestionCount = 0,
  onOpenSuggestions,
  onSelectHost,
  onScanLan,
}) {
  const [showProfiles, setShowProfiles] = useState(false);
  const [customProfiles, setCustomProfiles] = useState([]);
  const [showSaveModal, setShowSaveModal] = useState(false);
  const [newProfileName, setNewProfileName] = useState('');
  const [newProfileDesc, setNewProfileDesc] = useState('');
  const [saveError, setSaveError] = useState('');
  const primaryIface = networkInterfaces[0];

  // Load custom profiles
  useEffect(() => {
    (async () => {
      try {
        if (window.pywebview?.api?.list_custom_profiles) {
          const res = await window.pywebview.api.list_custom_profiles();
          if (res?.success) setCustomProfiles(res.profiles || []);
        }
      } catch (_) {}
    })();
  }, []);

  const activeProfile = QUICK_PROFILES.find((p) => p.id === scanProfile) || customProfiles.find((p) => `custom_${p.id}` === scanProfile) || QUICK_PROFILES[0];
  const lastScan = scanHistory[0];
  const hostsCount = scanData?.data?.hosts?.length || 0;
  const elements = scanData?.cytoscape || { nodes: [], edges: [] };

  const handleScan = () => { if (isScanning) return; onStartScan(target); };

  const handleSaveProfile = async () => {
    const name = newProfileName.trim();
    if (!name) { setSaveError('Name required'); return; }
    try {
      if (window.pywebview?.api?.save_custom_profile) {
        const res = await window.pywebview.api.save_custom_profile(name, scanProfile, newProfileDesc || `${activeProfile?.label || scanProfile} preset`);
        if (res?.success) {
          // Reload profiles
          const list = await window.pywebview.api.list_custom_profiles();
          if (list?.success) setCustomProfiles(list.profiles || []);
          setShowSaveModal(false); setNewProfileName(''); setNewProfileDesc(''); setSaveError('');
        } else {
          setSaveError(res?.error || 'Save failed');
        }
      }
    } catch (e) { setSaveError('API error'); }
  };

  return (
    <div className="flex flex-col h-full w-full bg-dark-950 overflow-hidden select-none">
      {/* ── Compact Scan Bar ── */}
      <div className="p-3 bg-dark-900 border-b border-slate-800 flex items-center gap-3 shrink-0">
        <div className="relative flex-1 max-w-md">
          <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="192.168.1.0/24 or host IP"
            className="w-full bg-dark-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-brand-cyan transition-all"
            disabled={isScanning} onKeyDown={(e) => { if (e.key === 'Enter') handleScan(); }} />
          {primaryIface?.cidr && (
            <button onClick={() => setTarget(primaryIface.cidr)} className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] font-semibold px-2 py-0.5 rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-all" title={`Scan My LAN: ${primaryIface.cidr}`}>My LAN</button>
          )}
        </div>
        <div className="relative">
          <button onClick={() => setShowProfiles(!showProfiles)} className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-dark-950 border border-slate-700 text-slate-200 hover:border-slate-600 transition-all">
            <Zap className="w-3.5 h-3.5 text-brand-cyan" /><span>{activeProfile?.label || scanProfile}</span>
            <ChevronDown className={`w-3 h-3 text-slate-400 transition-transform ${showProfiles ? 'rotate-180' : ''}`} />
          </button>
          {showProfiles && (
            <div className="absolute top-full mt-1 left-0 w-60 bg-dark-950 border border-slate-700 rounded-xl shadow-xl py-1 z-50 animate-slide-up" onMouseLeave={() => setShowProfiles(false)}>
              <div className="px-3 py-1 text-[9px] font-bold text-slate-500 uppercase tracking-wider">Built-in</div>
              {QUICK_PROFILES.map((p) => (
                <button key={p.id} onClick={() => { setScanProfile(p.id); setShowProfiles(false); }}
                  className={`w-full text-left px-3 py-2 text-xs group hover:bg-slate-800/60 transition-colors ${p.id === scanProfile ? 'bg-cyan-500/10 border-l-2 border-brand-cyan' : ''}`}>
                  <div className="font-semibold text-slate-200 group-hover:text-white">{p.label}</div>
                  <div className="text-[10px] text-slate-500">{p.desc}</div>
                </button>
              ))}
              {customProfiles.length > 0 && (
                <>
                  <div className="px-3 py-1 mt-1 text-[9px] font-bold text-slate-500 uppercase tracking-wider border-t border-slate-800">Custom</div>
                  {customProfiles.map((cp) => (
                    <button key={`custom_${cp.id}`} onClick={() => { setScanProfile(`custom_${cp.id}`); setShowProfiles(false); }}
                      className={`w-full text-left px-3 py-2 text-xs group hover:bg-slate-800/60 transition-colors ${`custom_${cp.id}` === scanProfile ? 'bg-cyan-500/10 border-l-2 border-brand-cyan' : ''}`}>
                      <div className="font-semibold text-slate-200 group-hover:text-white">{cp.name}</div>
                      <div className="text-[10px] text-slate-500">{cp.description || `${(cp.args || []).length} args`}</div>
                    </button>
                  ))}
                </>
              )}
              <div className="border-t border-slate-800 pt-1 mt-1">
                <button onClick={() => { setShowProfiles(false); setShowSaveModal(true); }}
                  className="w-full text-left px-3 py-2 text-[10px] font-semibold text-cyan-400 hover:bg-slate-800/60 transition-colors flex items-center gap-1.5">
                  <Plus className="w-3 h-3" /> Save current as profile
                </button>
              </div>
            </div>
          )}
        </div>
        {isScanning ? (
          <button onClick={onCancelScan} className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30 hover:bg-rose-500/25 transition-all animate-pulse">
            <Square className="w-3.5 h-3.5" /><span>Cancel</span>
          </button>
        ) : (
          <button onClick={handleScan} disabled={!target.trim()} className="flex items-center gap-1.5 px-5 py-2 rounded-lg text-xs font-bold bg-brand-cyan hover:bg-cyan-400 text-slate-950 shadow-glow-cyan transition-all disabled:opacity-30 disabled:cursor-not-allowed">
            <Play className="w-3.5 h-3.5" /><span>Scan</span>
          </button>
        )}
        {suggestionCount > 0 && (
          <button onClick={onOpenSuggestions} className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[10px] font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/20 hover:bg-amber-500/20 transition-all animate-fade-in">
            <Sparkles className="w-3 h-3" /><span>{suggestionCount} suggestion{suggestionCount > 1 ? 's' : ''}</span>
          </button>
        )}
      </div>
      {/* Canvas */}
      <div className="flex-1 relative min-h-0">
        {hostsCount > 0 || elements.nodes?.length > 0 ? (
          <ErrorBoundary>
            <Topology elements={elements} onSelectHost={(hostData) => onSelectHost && onSelectHost(hostData)} />
          </ErrorBoundary>
        ) : (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 z-10 pointer-events-none">
            <div className="relative mb-6"><div className="w-20 h-20 rounded-full bg-cyan-500/5 border border-cyan-500/20 flex items-center justify-center"><Radio className="w-9 h-9 text-cyan-500/40" /></div><div className="absolute inset-0 rounded-full border border-cyan-500/10 animate-scan-wave" /></div>
            <p className="text-sm font-medium text-slate-400 mb-2">Ready to discover your network</p>
            <p className="text-xs text-slate-600 max-w-xs text-center">Enter a target above and click Scan — hosts will appear on this canvas one by one.</p>
          </div>
        )}
        {passiveDevices.length > 0 && (
          <div className="absolute bottom-3 left-3 z-30 flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-dark-950/90 border border-slate-700 text-[10px] text-slate-400"><Wifi className="w-3 h-3 text-emerald-400" /><span>{passiveDevices.length} passively discovered</span></div>
        )}
      </div>
      {/* Summary bar */}
      <div className="px-4 py-2.5 bg-dark-900 border-t border-slate-800 flex items-center justify-between shrink-0 text-xs">
        <div className="flex items-center gap-4">
          {lastScan ? (
            <span className="text-slate-400">Last scan: <span className="text-slate-200 font-mono">{lastScan.target || '—'}</span> · <span className="text-brand-cyan font-semibold">{lastScan.hostsCount || 0} hosts</span> · <span className="text-slate-500">{lastScan.timestamp}</span></span>
          ) : (
            <span className="text-slate-500 italic">No scan history yet — run your first scan.</span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {hostsCount > 0 && <span className="text-slate-400">Current: <span className="text-brand-cyan font-semibold">{hostsCount} hosts</span>{scanData?.success && <span className="ml-1 text-emerald-400">· live</span>}</span>}
          <button className="flex items-center gap-1 text-[10px] font-semibold text-slate-500 hover:text-brand-cyan transition-colors" onClick={() => onOpenSuggestions?.()}><Sparkles className="w-3 h-3" /><span>Suggestions</span>{suggestionCount > 0 && <span className="px-1.5 py-0.5 rounded-full bg-amber-500/15 text-amber-300 text-[9px]">{suggestionCount}</span>}</button>
        </div>
      </div>
      {/* Save Profile Modal */}
      {showSaveModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in" onClick={() => setShowSaveModal(false)}>
          <div className="w-80 bg-dark-900 border border-slate-700 rounded-2xl shadow-2xl p-5 animate-slide-up" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-white">Save Custom Profile</h3>
              <button onClick={() => setShowSaveModal(false)} className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"><X className="w-4 h-4" /></button>
            </div>
            <div className="space-y-3">
              <div><label className="text-[10px] font-bold text-slate-400 uppercase block mb-1">Name</label><input type="text" value={newProfileName} onChange={(e) => setNewProfileName(e.target.value)} placeholder="e.g. My Quick Scan" className="w-full bg-dark-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-brand-cyan" /></div>
              <div><label className="text-[10px] font-bold text-slate-400 uppercase block mb-1">Description</label><input type="text" value={newProfileDesc} onChange={(e) => setNewProfileDesc(e.target.value)} placeholder="What this scan does" className="w-full bg-dark-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-brand-cyan" /></div>
              {saveError && <p className="text-[10px] text-rose-400">{saveError}</p>}
              <button onClick={handleSaveProfile} className="w-full py-2 rounded-lg text-xs font-bold bg-brand-cyan hover:bg-cyan-400 text-slate-950 transition-all flex items-center justify-center gap-1.5"><Save className="w-3.5 h-3.5" />Save Profile</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}