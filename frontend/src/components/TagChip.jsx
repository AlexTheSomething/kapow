import React from 'react';

const COLORS = {
  emerald: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/25',
  amber: 'bg-amber-500/15 text-amber-300 border-amber-500/25',
  rose: 'bg-rose-500/15 text-rose-300 border-rose-500/25',
  cyan: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/25',
  indigo: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/25',
  violet: 'bg-violet-500/15 text-violet-300 border-violet-500/25',
  slate: 'bg-slate-500/15 text-slate-300 border-slate-500/25',
};

export default function TagChip({ tag, color = 'slate', onRemove, small, className = '', animated }) {
  const c = COLORS[color] || COLORS.slate;
  const size = small ? 'text-[10px] px-1.5 py-0.5' : 'text-[11px] px-2 py-0.5';
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full font-semibold border ${c} ${size} ${className} ${animated ? 'animate-tag-pop' : ''}`}
    >
      <span>{tag}</span>
      {onRemove && (
        <button
          onClick={(e) => { e.stopPropagation(); onRemove(tag); }}
          className="ml-0.5 hover:opacity-70 text-[10px] leading-none"
        >
          ×
        </button>
      )}
    </span>
  );
}