import React from 'react';
import { Activity, Server, Layers, Clock, Terminal, AlertCircle } from 'lucide-react';

export default function StatusBar({
  statusMessage,
  isScanning,
  error,
  scanData,
}) {
  const hosts = scanData?.data?.hosts || [];
  const agGridRows = scanData?.ag_grid || [];
  const summary = scanData?.data?.summary || {};
  const elapsed = summary?.elapsed || 0;

  return (
    <footer className="h-9 px-4 border-t border-slate-800 bg-dark-950 flex items-center justify-between text-xs text-slate-400 shrink-0 select-none z-30">
      {/* Left: Status Message & Activity */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          {isScanning ? (
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          ) : error ? (
            <div className="w-2.5 h-2.5 rounded-full bg-rose-500" />
          ) : scanData ? (
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
          ) : (
            <div className="w-2.5 h-2.5 rounded-full bg-slate-600" />
          )}
          <span className={`font-medium ${error ? 'text-rose-400' : isScanning ? 'text-cyan-300' : 'text-slate-300'}`}>
            {error || statusMessage || 'Ready'}
          </span>
        </div>
      </div>

      {/* Right: Metrics & Scan Summary */}
      <div className="flex items-center gap-4 text-[11px] font-mono">
        {scanData && (
          <>
            <div className="flex items-center gap-1.5" title="Discovered Hosts">
              <Server className="w-3.5 h-3.5 text-cyan-400" />
              <span>{hosts.length} Hosts</span>
            </div>

            <div className="flex items-center gap-1.5" title="Open Ports & Services">
              <Layers className="w-3.5 h-3.5 text-emerald-400" />
              <span>{agGridRows.length} Services</span>
            </div>

            {elapsed > 0 && (
              <div className="flex items-center gap-1.5" title="Scan Duration">
                <Clock className="w-3.5 h-3.5 text-amber-400" />
                <span>{elapsed.toFixed(1)}s</span>
              </div>
            )}
          </>
        )}

        <div className="text-slate-600">|</div>
        <span className="text-slate-500 text-[10px]">PyWebView IPC Bridge</span>
      </div>
    </footer>
  );
}
