import React, { useState } from 'react';
import { Sparkles, Check, X } from 'lucide-react';
import TagChip from './TagChip';

/**
 * SuggestionPanel — quiet auto-tag suggestions after a scan.
 * Renders inside a slide-over panel; never pops up on its own.
 */
export default function SuggestionPanel({ suggestions, onAccept, onDismissAll, onClose }) {
  const [dismissed, setDismissed] = useState(new Set());

  if (!suggestions || suggestions.length === 0) return null;

  const visible = suggestions.filter((s) => !dismissed.has(`${s.ip}::${s.tag}`));

  if (visible.length === 0) {
    return (
      <div className="flex items-center justify-between p-4 text-xs text-slate-400 animate-fade-in">
        <span>All suggestions reviewed.</span>
        <button onClick={onClose} className="text-cyan-400 hover:text-cyan-300 font-semibold">Close</button>
      </div>
    );
  }

  const handleAccept = (s) => {
    if (onAccept) onAccept(s);
    setDismissed((prev) => new Set(prev).add(`${s.ip}::${s.tag}`));
  };

  const handleDismiss = (s) => {
    setDismissed((prev) => new Set(prev).add(`${s.ip}::${s.tag}`));
  };

  return (
    <div className="h-full flex flex-col animate-slide-right">
      <div className="p-4 border-b border-slate-800 bg-dark-950 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-brand-neon" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-white">
            Scan Suggestions ({visible.length})
          </h3>
        </div>
        <div className="flex items-center gap-2">
          {onDismissAll && (
            <button
              onClick={onDismissAll}
              className="text-[11px] text-slate-400 hover:text-slate-200 px-2 py-1 rounded-lg hover:bg-slate-800 transition-colors"
            >
              Dismiss all
            </button>
          )}
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {visible.map((s, idx) => (
          <div
            key={idx}
            className="p-3.5 rounded-xl bg-dark-900 border border-slate-800 hover:border-slate-700 transition-colors animate-slide-up"
            style={{ animationDelay: `${idx * 40}ms` }}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm font-bold text-cyan-300">{s.ip}</span>
                  {s.hostname && <span className="text-xs text-slate-400 font-mono">({s.hostname})</span>}
                  <TagChip tag={s.tag} color={s.color} small />
                </div>
                <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">{s.reason}</p>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button
                  onClick={() => handleAccept(s)}
                  className="p-1.5 rounded-lg bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30 transition-all"
                  title="Accept tag — saves to this host permanently"
                >
                  <Check className="w-4 h-4" />
                </button>
                <button
                  onClick={() => handleDismiss(s)}
                  className="p-1.5 rounded-lg bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700 hover:text-white transition-all"
                  title="Dismiss"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}