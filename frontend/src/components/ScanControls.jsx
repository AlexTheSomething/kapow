import React, { useState } from 'react';
import { Play, Square, Shield, Lock, Unlock, Target, Layers, Zap, Hash, AlertTriangle, Terminal, Sparkles, FileCode, Check, Wifi, Network } from 'lucide-react';

const SCAN_PROFILES = [
  { id: 'quick', name: 'Quick Scan', flags: '-T4 -F', desc: 'Top 100 ports, fast timing (~2s)' },
  { id: 'quick_plus', name: 'Quick + Services', flags: '-sV -T4 -F', desc: 'Service versions + OS hint (~10s)' },
  { id: 'comprehensive', name: 'Comprehensive', flags: '-sV -T4 -F', desc: 'Deep service + OS fingerprint (~15s)' },
  { id: 'ping_sweep', name: 'Ping Sweep', flags: '-sn -T4', desc: 'Host discovery only, no ports (~1s)' },
  { id: 'intense', name: 'Intense + Scripts', flags: '-sV -sC -T4', desc: 'Service scan + default NSE scripts (~15s)' },
  { id: 'ports_only', name: 'Port Sweep (Skip Ping)', flags: '-Pn -T4 -F', desc: 'Direct port scan, bypass host discovery' },
];

const TARGET_PRESETS = [
  { label: 'Localhost', value: '127.0.0.1' },
  { label: 'Gateway', value: '192.168.1.1' },
  { label: 'Nmap Test', value: 'scanme.nmap.org' },
];

const PORT_PRESETS = [
  { label: 'Top 100', value: '1-100' },
  { label: 'Top 1000', value: '1-1024' },
  { label: 'Web (80,443,8080)', value: '80,443,8080,8443,3000,5000,8000' },
  { label: 'All (1-65535)', value: '1-65535' },
];

const NSE_PRESETS = [
  { id: 'vuln', label: 'Vulnerability Audit', script: 'vuln', desc: 'Run all known CVE vulnerability detection scripts' },
  { id: 'discovery', label: 'Service Discovery', script: 'discovery', desc: 'Query active services for extended network info' },
  { id: 'auth', label: 'Authentication Audit', script: 'auth', desc: 'Check default credentials and open authentication' },
  { id: 'ssl', label: 'SSL/TLS Certificates', script: 'ssl-cert,ssl-enum-ciphers', desc: 'Analyze SSL certificates, ciphers and expiry' },
  { id: 'smb', label: 'SMB & Windows Shares', script: 'smb-os-discovery,smb-security-mode', desc: 'Audit Windows SMB security mode and OS version' },
  { id: 'http', label: 'HTTP Title & Headers', script: 'http-title,http-headers', desc: 'Extract web page titles and security headers' },
];

export default function ScanControls({
  target,
  setTarget,
  ports,
  setPorts,
  scanProfile,
  setScanProfile,
  requiresRoot,
  setRequiresRoot,
  scripts,
  setScripts,
  isScanning,
  onStartScan,
  onCancelScan,
  dependencies,
  networkInterfaces = [],
  onScanLan,
}) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const nmapInstalled = dependencies?.nmap?.installed;

  // Compute command preview string
  const activeProfile = SCAN_PROFILES.find((p) => p.id === scanProfile) || SCAN_PROFILES[0];
  const computedCommand = `nmap ${activeProfile.flags}${ports ? ` -p ${ports}` : ''}${scripts ? ` --script ${scripts}` : ''} ${target || '<target>'}`;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!isScanning && target.trim()) {
      onStartScan();
    }
  };

  const toggleNsePreset = (scriptValue) => {
    if (scripts === scriptValue) {
      setScripts('');
    } else {
      setScripts(scriptValue);
    }
  };

  const primaryIface = networkInterfaces[0];

  return (
    <div className="bg-dark-900/80 backdrop-blur-md border-b border-slate-800 px-6 py-4 shrink-0 select-none shadow-lg">
      <form onSubmit={handleSubmit} className="flex flex-col gap-3.5">
        
        {/* Top Target Chips & Target Input Row */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-center">
          
          {/* Target Input with Presets */}
          <div className="lg:col-span-5 relative">
            <div className="flex items-center justify-between mb-1">
              <label htmlFor="input-target" className="text-[11px] font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                <Target className="w-3.5 h-3.5 text-brand-cyan" />
                Target Specification
              </label>
              
              {/* Feature 1: Quick Target Chips & Auto LAN Presets */}
              <div className="flex items-center gap-1">
                {/* 1-Click Auto-Detect My Network */}
                {primaryIface?.cidr && (
                  <button
                    type="button"
                    onClick={() => {
                      setTarget(primaryIface.cidr);
                      if (onScanLan) onScanLan(primaryIface.cidr);
                    }}
                    className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/50 transition-all font-bold flex items-center gap-1 shadow-sm"
                    title={`Auto-detected ${primaryIface.name} subnet: ${primaryIface.cidr}`}
                  >
                    <Wifi className="w-3 h-3 text-cyan-400" />
                    <span>Scan My LAN ({primaryIface.cidr})</span>
                  </button>
                )}

                {TARGET_PRESETS.map((preset) => (
                  <button
                    key={preset.label}
                    type="button"
                    onClick={() => setTarget(preset.value)}
                    className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700/60 transition-all font-mono"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="relative">
              <input
                id="input-target"
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. 192.168.1.0/24, 127.0.0.1, scanme.nmap.org"
                disabled={isScanning}
                className="w-full bg-dark-950/90 border border-slate-700/80 focus:border-brand-cyan rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-brand-cyan font-mono shadow-inner transition-all disabled:opacity-50"
              />
              {target && !isScanning && (
                <button
                  type="button"
                  onClick={() => setTarget('')}
                  className="absolute right-3 top-3 text-xs text-slate-500 hover:text-slate-300"
                >
                  ✕
                </button>
              )}
            </div>
          </div>

          {/* Scan Profile Selector */}
          <div className="lg:col-span-4">
            <label htmlFor="select-profile" className="block text-[11px] font-bold uppercase tracking-wider text-slate-300 mb-1 flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              Scan Profile
            </label>
            <select
              id="select-profile"
              value={scanProfile}
              onChange={(e) => setScanProfile(e.target.value)}
              disabled={isScanning}
              className="w-full bg-dark-950/90 border border-slate-700/80 focus:border-brand-cyan rounded-xl px-3.5 py-2.5 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-brand-cyan transition-all disabled:opacity-50"
            >
              {SCAN_PROFILES.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.flags}) — {p.desc}
                </option>
              ))}
            </select>
          </div>

          {/* Action Buttons (Scan / Cancel) */}
          <div className="lg:col-span-3 flex items-end gap-2 pt-4 lg:pt-0">
            {!isScanning ? (
              <button
                id="btn-start-scan"
                type="submit"
                disabled={!target.trim()}
                className="flex-1 flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl font-bold text-sm bg-gradient-to-r from-brand-cyan to-brand-indigo hover:from-cyan-400 hover:to-indigo-500 text-slate-950 shadow-glow-cyan hover:shadow-cyan-400/50 transition-all transform active:scale-98 disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>Launch Scan</span>
              </button>
            ) : (
              <button
                id="btn-cancel-scan"
                type="button"
                onClick={onCancelScan}
                className="flex-1 flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl font-bold text-sm bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-600/30 transition-all animate-pulse"
              >
                <Square className="w-4 h-4 fill-current" />
                <span>Stop Scan</span>
              </button>
            )}

            {/* Advanced Toggle */}
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className={`p-2.5 rounded-xl border text-xs font-medium transition-all ${
                showAdvanced || scripts
                  ? 'bg-slate-700 text-cyan-300 border-cyan-500/50' 
                  : 'bg-dark-950/80 text-slate-400 border-slate-700/80 hover:text-slate-200'
              }`}
              title="Toggle network adapters, port range, NSE script presets, and elevation settings"
            >
              <Layers className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Real-time Generated CLI Command Bar */}
        <div className="flex items-center justify-between px-3.5 py-1.5 rounded-xl bg-dark-950/80 border border-slate-800 font-mono text-xs text-slate-400">
          <div className="flex items-center gap-2 truncate">
            <Terminal className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="text-slate-500 select-none">Command:</span>
            <span className="text-slate-200 font-semibold truncate">{computedCommand}</span>
          </div>
          {scripts && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-mono">
              NSE: {scripts}
            </span>
          )}
        </div>

        {/* Advanced Options Drawer (Adapters, Ports, NSE Presets, Root Elevation) */}
        {showAdvanced && (
          <div className="pt-3 border-t border-slate-800/80 space-y-3">
            
            {/* Network Adapter Picker */}
            {networkInterfaces.length > 0 && (
              <div className="p-3 rounded-xl bg-dark-950/80 border border-slate-800 flex items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2">
                  <Network className="w-4 h-4 text-cyan-400" />
                  <span className="text-slate-300 font-semibold">Active Adapters:</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {networkInterfaces.map((iface, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => setTarget(iface.cidr || iface.ip)}
                      className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/80 transition-all font-mono text-[11px] flex items-center gap-1.5"
                    >
                      <span className="font-sans text-cyan-300 font-bold">{iface.name}:</span>
                      <span>{iface.cidr || iface.ip}</span>
                      {iface.gateway && <span className="text-slate-500 text-[10px]">GW: {iface.gateway}</span>}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-12 gap-3.5 items-center">
              
              {/* Custom Ports Input */}
              <div className="md:col-span-6">
                <div className="flex items-center justify-between mb-1">
                  <label htmlFor="input-ports" className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Hash className="w-3.5 h-3.5 text-brand-emerald" />
                    Port Range (Optional)
                  </label>
                  <div className="flex items-center gap-1">
                    {PORT_PRESETS.map((preset) => (
                      <button
                        key={preset.label}
                        type="button"
                        onClick={() => setPorts(preset.value)}
                        className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700/60 transition-all font-mono"
                      >
                        {preset.label}
                      </button>
                    ))}
                  </div>
                </div>
                <input
                  id="input-ports"
                  type="text"
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                  placeholder="Leave blank for profile default (e.g. 22,80,443 or 1-10000)"
                  disabled={isScanning}
                  className="w-full bg-dark-950/90 border border-slate-700/80 focus:border-brand-emerald rounded-xl px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-brand-emerald font-mono transition-all"
                />
              </div>

              {/* Root / Admin Privilege Toggle */}
              <div className="md:col-span-6 flex items-center justify-end gap-3 pt-3">
                <label 
                  htmlFor="toggle-root"
                  className={`flex items-center gap-2.5 px-3.5 py-2 rounded-xl border cursor-pointer select-none transition-all ${
                    requiresRoot 
                      ? 'bg-amber-500/10 border-amber-500/40 text-amber-300' 
                      : 'bg-dark-950/80 border-slate-700/80 text-slate-400 hover:text-slate-300'
                  }`}
                >
                  <input
                    id="toggle-root"
                    type="checkbox"
                    checked={requiresRoot}
                    onChange={(e) => setRequiresRoot(e.target.checked)}
                    disabled={isScanning}
                    className="sr-only"
                  />
                  {requiresRoot ? (
                    <Lock className="w-4 h-4 text-amber-400" />
                  ) : (
                    <Unlock className="w-4 h-4 text-slate-400" />
                  )}
                  <div className="text-xs">
                    <span className="font-semibold block">Require Root / Admin (SYN & OS Scan)</span>
                    <span className="text-[10px] text-slate-500">Elevates via pkexec / osascript / UAC</span>
                  </div>
                </label>
              </div>

            </div>

            {/* NSE Script Presets */}
            <div className="pt-2 border-t border-slate-800/60">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-bold uppercase tracking-wider text-indigo-400 flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-indigo-400" />
                  Nmap Scripting Engine (NSE) Presets
                </span>
                {scripts && (
                  <button
                    type="button"
                    onClick={() => setScripts('')}
                    className="text-[10px] text-slate-400 hover:text-white"
                  >
                    Clear Scripts
                  </button>
                )}
              </div>

              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
                {NSE_PRESETS.map((preset) => {
                  const isSelected = scripts === preset.script;
                  return (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => toggleNsePreset(preset.script)}
                      className={`text-left p-2 rounded-xl border text-xs transition-all flex flex-col justify-between ${
                        isSelected 
                          ? 'bg-indigo-600/25 border-indigo-500 text-indigo-200 shadow-sm' 
                          : 'bg-dark-950/80 border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200'
                      }`}
                      title={preset.desc}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-[11px] block">{preset.label}</span>
                        {isSelected && <Check className="w-3 h-3 text-indigo-400" />}
                      </div>
                      <span className="font-mono text-[10px] text-slate-500 block truncate mt-1">
                        --script {preset.script}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

          </div>
        )}
      </form>
    </div>
  );
}
