import React, { useEffect, useRef, useState } from 'react';
import { Terminal, Copy, Check, Trash2, ArrowDownCircle, Download } from 'lucide-react';

export default function LiveConsole({ logs, isScanning, activeCommand }) {
  const terminalEndRef = useRef(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  const handleCopy = () => {
    navigator.clipboard.writeText((logs || []).join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const text = (logs || []).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nmap_scan_${new Date().toISOString().slice(0, 10)}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full bg-dark-950 text-slate-200 font-mono text-xs overflow-hidden select-text">
      {/* Console Top Toolbar */}
      <div className="px-4 py-2 bg-dark-900 border-b border-slate-800 flex items-center justify-between shrink-0 select-none">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
          </div>
          <div className="h-4 w-px bg-slate-700 mx-1.5" />
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span className="font-semibold text-slate-300">Nmap Live Process Console</span>
          {isScanning && (
            <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 animate-pulse">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
              STREAMING
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {activeCommand && (
            <span className="hidden md:inline-block px-2.5 py-1 rounded bg-dark-950 text-[11px] text-slate-400 border border-slate-800 truncate max-w-md">
              $ {activeCommand}
            </span>
          )}

          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`px-2 py-1 rounded text-[11px] font-sans border transition-all ${
              autoScroll ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30' : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}
            title="Auto-scroll to latest log output"
          >
            Auto-scroll: {autoScroll ? 'ON' : 'OFF'}
          </button>

          <button
            onClick={handleCopy}
            className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-all"
            title="Copy logs to clipboard"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>

          <button
            onClick={handleDownload}
            className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-all"
            title="Download log file"
          >
            <Download className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Terminal Output Area */}
      <div className="flex-1 p-4 overflow-y-auto space-y-1 bg-[#060810] font-mono leading-relaxed">
        {(!logs || logs.length === 0) ? (
          <div className="text-slate-500 italic py-8 text-center">
            {isScanning ? 'Waiting for Nmap process output...' : 'No active process logs. Start a scan to view live terminal streaming.'}
          </div>
        ) : (
          logs.map((line, idx) => {
            let colorClass = 'text-slate-300';
            if (line.startsWith('[*]')) colorClass = 'text-cyan-400 font-semibold';
            else if (line.startsWith('[+]')) colorClass = 'text-emerald-400 font-semibold';
            else if (line.startsWith('[!]') || line.includes('error') || line.includes('failed')) colorClass = 'text-rose-400 font-semibold';
            else if (line.startsWith('[stderr]')) colorClass = 'text-amber-400';
            else if (line.includes('open') && line.includes('tcp')) colorClass = 'text-emerald-300';

            return (
              <div key={idx} className={`whitespace-pre-wrap break-all ${colorClass}`}>
                {line}
              </div>
            );
          })
        )}
        <div ref={terminalEndRef} />
      </div>
    </div>
  );
}
