import React from 'react';
import { Network, Shield, ShieldAlert, Cpu, Download, Sparkles, RefreshCw, Terminal } from 'lucide-react';

export default function Header({ 
  dependencies, 
  onLoadSample, 
  onExport, 
  isScanning, 
  onRefreshDeps,
  scanData 
}) {
  const nmapInstalled = dependencies?.nmap?.installed;
  const rustscanInstalled = dependencies?.rustscan?.installed;
  const masscanInstalled = dependencies?.masscan?.installed;
  const naabuInstalled = dependencies?.naabu?.installed;
  const isElevated = dependencies?.is_elevated;

  return (
    <header className="h-16 px-6 border-b border-slate-800/80 bg-dark-900/90 backdrop-blur-md flex items-center justify-between z-30 shrink-0 select-none">
      {/* Brand & Title */}
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 p-0.5 flex items-center justify-center shadow-glow-cyan">
          <div className="w-full h-full bg-dark-900 rounded-[10px] flex items-center justify-center">
            <Network className="w-5 h-5 text-brand-neon animate-pulse-slow" />
          </div>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold tracking-tight text-white font-sans">
              Kapow <span className="text-brand-cyan">Auditor</span>
            </h1>
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              v1.5
            </span>
          </div>
          <p className="text-xs text-slate-400">Modern Network Security Auditor & Topology Engine</p>
        </div>
      </div>

      {/* System Dependency Status Badges */}
      <div className="hidden md:flex items-center gap-2.5">
        {/* Nmap Status */}
        <div 
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border ${
            nmapInstalled 
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
              : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
          }`}
          title={nmapInstalled ? `Nmap available at: ${dependencies?.nmap?.path}` : 'Nmap CLI not found in PATH'}
        >
          <div className={`w-2 h-2 rounded-full ${nmapInstalled ? 'bg-emerald-400' : 'bg-rose-400'}`} />
          <span>Nmap {nmapInstalled ? 'Active' : 'Missing'}</span>
        </div>

        {/* RustScan Status */}
        <div 
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border ${
            rustscanInstalled 
              ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20' 
              : 'bg-slate-800 text-slate-400 border-slate-700/50'
          }`}
          title={rustscanInstalled ? `RustScan enabled: ${dependencies?.rustscan?.path}` : 'RustScan not installed (optional fast-sweep)'}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>RustScan {rustscanInstalled ? 'Active' : 'Optional'}</span>
        </div>

        {/* Masscan Status */}
        <div 
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border ${
            masscanInstalled 
              ? 'bg-violet-500/10 text-violet-400 border-violet-500/20' 
              : 'bg-slate-800 text-slate-400 border-slate-700/50'
          }`}
          title={masscanInstalled ? `Masscan enabled: ${dependencies?.masscan?.path}` : 'Masscan not installed (optional fast-sweep)'}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>Masscan {masscanInstalled ? 'Active' : 'Optional'}</span>
        </div>

        {/* Naabu Status */}
        <div 
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border ${
            naabuInstalled 
              ? 'bg-teal-500/10 text-teal-400 border-teal-500/20' 
              : 'bg-slate-800 text-slate-400 border-slate-700/50'
          }`}
          title={naabuInstalled ? `Naabu enabled: ${dependencies?.naabu?.path}` : 'Naabu not installed (optional fast-sweep)'}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>Naabu {naabuInstalled ? 'Active' : 'Optional'}</span>
        </div>

        {/* Privilege Elevation */}
        <div 
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border ${
            isElevated 
              ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' 
              : 'bg-slate-800 text-slate-400 border-slate-700/50'
          }`}
          title={isElevated ? 'Running with Root/Admin privileges' : 'Standard user privileges'}
        >
          {isElevated ? <Shield className="w-3.5 h-3.5 text-amber-400" /> : <ShieldAlert className="w-3.5 h-3.5 text-slate-400" />}
          <span>{isElevated ? 'Root / Admin' : 'User Mode'}</span>
        </div>
      </div>

      {/* Action Controls (Demo Data & Export) */}
      <div className="flex items-center gap-2">
        {/* Load Sample Network Button */}
        <button
          id="btn-load-demo"
          onClick={onLoadSample}
          disabled={isScanning}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 hover:from-cyan-500/25 hover:to-indigo-500/25 text-cyan-300 border border-cyan-500/30 hover:border-cyan-400 transition-all shadow-sm active:scale-95 disabled:opacity-50"
          title="Load comprehensive sample network data (routers, workstations, servers)"
        >
          <Sparkles className="w-3.5 h-3.5 text-brand-neon" />
          <span>Demo Data</span>
        </button>

        {/* Export Dropdown */}
        {scanData && (
          <div className="relative group">
            <button
              id="btn-export-dropdown"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 hover:border-slate-600 transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export</span>
            </button>
            <div className="absolute right-0 mt-1 w-32 bg-dark-900 border border-slate-700 rounded-lg shadow-xl py-1 hidden group-hover:block z-50">
              <button
                onClick={() => onExport('json')}
                className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-white flex items-center justify-between"
              >
                <span>JSON</span>
                <span className="text-[10px] text-slate-500">.json</span>
              </button>
              <button
                onClick={() => onExport('csv')}
                className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-white flex items-center justify-between"
              >
                <span>CSV Table</span>
                <span className="text-[10px] text-slate-500">.csv</span>
              </button>
              <button
                onClick={() => onExport('xml')}
                className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-white flex items-center justify-between"
              >
                <span>Nmap XML</span>
                <span className="text-[10px] text-slate-500">.xml</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </header>
  );
}
