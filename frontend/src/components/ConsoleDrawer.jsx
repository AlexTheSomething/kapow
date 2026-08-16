import React, { useRef, useEffect } from 'react';
import { Terminal, ChevronDown, ChevronUp } from 'lucide-react';

/**
 * ConsoleDrawer — collapsible bottom drawer showing live scan output.
 * Stays out of the way; slides up when scanning or when opened manually.
 */
export default function ConsoleDrawer({ logs = [], isScanning, isOpen, onToggle }) {
  const bodyRef = useRef(null);

  // Auto-scroll to bottom as new logs arrive
  useEffect(() => {
    if (bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [logs, isOpen]);

  return (
    <div className={`shrink-0 border-t border-slate-800 bg-dark-950/95 backdrop-blur-sm transition-all duration-300 ${isOpen ? 'h-56' : 'h-9'}`}>
      {/* Drawer handle */}
      <button
        onClick={onToggle}
        className="w-full h-9 px-4 flex items-center justify-between text-xs font-semibold text-slate-400 hover:text-white transition-colors"
      >
        <span className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5" />
          <span>Scan Console</span>
          {isScanning && (
            <span className="flex items-center gap-1.5 text-[10px] text-brand-cyan">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
              </span>
              live
            </span>
          )}
        </span>
        {isOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronUp className="w-3.5 h-3.5" />}
      </button>

      {/* Log body */}
      <div
        ref={bodyRef}
        className={`h-[calc(100%-2.25rem)] overflow-y-auto px-4 pb-3 font-mono text-[11px] leading-relaxed ${isOpen ? '' : 'hidden'}`}
      >
        {logs.length === 0 ? (
          <p className="text-slate-600 italic py-2">Console output will appear here during scans.</p>
        ) : (
          logs.map((line, idx) => {
            let cls = 'text-slate-400';
            if (line.startsWith('[+]')) cls = 'text-emerald-400';
            else if (line.startsWith('[!]') || line.includes('error') || line.includes('Error')) cls = 'text-rose-400';
            else if (line.startsWith('[*]')) cls = 'text-cyan-400';
            else if (line.includes('Discovered open port')) cls = 'text-brand-neon font-semibold';
            return (
              <div key={idx} className={`whitespace-pre-wrap break-all ${cls} ${idx === logs.length - 1 ? 'animate-fade-in' : ''}`}>
                {line}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}