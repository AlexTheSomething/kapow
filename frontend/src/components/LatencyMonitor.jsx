import React, { useState, useEffect, useRef } from 'react';
import { Activity, Play, Pause, RotateCcw, AlertTriangle, ShieldCheck, Wifi, ArrowDown, ArrowUp, Zap, Server } from 'lucide-react';

export default function LatencyMonitor({ monitoredIp, discoveredHosts = [], onPingTelemetry, onResetTelemetry }) {
  const [targetIp, setTargetIp] = useState(monitoredIp || '127.0.0.1');
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [stats, setStats] = useState({
    is_online: false,
    current_latency: null,
    min_latency: 0,
    avg_latency: 0,
    max_latency: 0,
    jitter: 0,
    packet_loss_pct: 0,
    history: [],
  });

  const intervalRef = useRef(null);

  useEffect(() => {
    if (monitoredIp) {
      setTargetIp(monitoredIp);
    }
  }, [monitoredIp]);

  const pollPing = async () => {
    if (!targetIp || !onPingTelemetry) return;
    try {
      const res = await onPingTelemetry(targetIp);
      if (res && res.success) {
        setStats(res);
      }
    } catch (e) {
      console.error('Ping poll error:', e);
    }
  };

  useEffect(() => {
    if (isMonitoring && targetIp) {
      pollPing();
      intervalRef.current = setInterval(pollPing, 900);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isMonitoring, targetIp]);

  const handleReset = async () => {
    if (onResetTelemetry) {
      await onResetTelemetry(targetIp);
    }
    setStats((prev) => ({
      ...prev,
      history: [],
      min_latency: 0,
      avg_latency: 0,
      max_latency: 0,
      jitter: 0,
      packet_loss_pct: 0,
    }));
  };

  // Sparkline SVG Builder
  const history = stats.history || [];
  const svgWidth = 600;
  const svgHeight = 160;
  const padding = 20;

  const validMax = Math.max(10, stats.max_latency * 1.25 || 50);
  const points = history.map((val, idx) => {
    const x = padding + (idx / Math.max(1, history.length - 1)) * (svgWidth - padding * 2);
    const y = svgHeight - padding - (Math.min(val, validMax) / validMax) * (svgHeight - padding * 2);
    return `${x},${y}`;
  }).join(' ');

  return (
    <div className="flex flex-col h-full w-full bg-dark-950 text-slate-200 overflow-hidden select-none">
      {/* Top Header Controls */}
      <div className="p-4 bg-dark-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/15 text-cyan-400">
            <Activity className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-xs font-bold uppercase tracking-wider text-white">
              Live Ping & Latency Jitter Telemetry
            </h2>
            <p className="text-[11px] text-slate-400">Continuous sub-second ICMP telemetry & jitter analysis</p>
          </div>
        </div>

        {/* Target Selector Bar */}
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={targetIp}
            onChange={(e) => setTargetIp(e.target.value)}
            placeholder="e.g. 192.168.1.1, 8.8.8.8"
            className="bg-dark-950 border border-slate-700 rounded-xl px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-brand-cyan w-44"
          />

          {discoveredHosts.length > 0 && (
            <select
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              className="bg-dark-950 border border-slate-700 rounded-xl px-2.5 py-1.5 text-xs text-cyan-300 focus:outline-none"
            >
              <option value="">Quick Pick Host...</option>
              {discoveredHosts.map((h, idx) => {
                const ip = h.ip || h.ipv4;
                return (
                  <option key={idx} value={ip}>
                    {h.alias ? `${h.alias} (${ip})` : ip}
                  </option>
                );
              })}
            </select>
          )}

          <button
            onClick={() => setIsMonitoring(!isMonitoring)}
            className={`flex items-center gap-1 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
              isMonitoring
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 hover:bg-amber-500/30'
                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30'
            }`}
          >
            {isMonitoring ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isMonitoring ? 'Pause' : 'Resume'}</span>
          </button>

          <button
            onClick={handleReset}
            className="p-1.5 rounded-xl bg-dark-950 border border-slate-700 text-slate-400 hover:text-white transition-all"
            title="Reset telemetry history"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Telemetry Body */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        
        {/* Metric Cards Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
          
          {/* Current Latency */}
          <div className="p-4 rounded-2xl glass-panel border border-slate-800">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Current RTT</span>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${stats.is_online ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}`}>
                {stats.is_online ? 'ONLINE' : 'TIMEOUT'}
              </span>
            </div>
            <div className="flex items-baseline gap-1">
              <span className="text-3xl font-bold font-mono text-cyan-300">
                {stats.current_latency !== null ? stats.current_latency : '—'}
              </span>
              <span className="text-xs text-slate-500 font-mono">ms</span>
            </div>
          </div>

          {/* Average Latency */}
          <div className="p-4 rounded-2xl glass-panel border border-slate-800">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1">Average Latency</span>
            <div className="flex items-baseline gap-1">
              <span className="text-3xl font-bold font-mono text-white">{stats.avg_latency}</span>
              <span className="text-xs text-slate-500 font-mono">ms</span>
            </div>
            <div className="flex items-center gap-3 text-[11px] text-slate-400 mt-1">
              <span>Min: {stats.min_latency} ms</span>
              <span>Max: {stats.max_latency} ms</span>
            </div>
          </div>

          {/* Jitter */}
          <div className="p-4 rounded-2xl glass-panel border border-slate-800">
            <span className="text-[11px] font-bold text-indigo-400 uppercase tracking-wider block mb-1">Network Jitter</span>
            <div className="flex items-baseline gap-1">
              <span className="text-3xl font-bold font-mono text-indigo-300">±{stats.jitter}</span>
              <span className="text-xs text-slate-500 font-mono">ms</span>
            </div>
            <span className="text-[11px] text-slate-500 block mt-1">Mean deviation</span>
          </div>

          {/* Packet Loss */}
          <div className="p-4 rounded-2xl glass-panel border border-slate-800">
            <span className="text-[11px] font-bold text-amber-400 uppercase tracking-wider block mb-1">Packet Loss</span>
            <div className="flex items-baseline gap-1">
              <span className={`text-3xl font-bold font-mono ${stats.packet_loss_pct > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                {stats.packet_loss_pct}%
              </span>
            </div>
            <span className="text-[11px] text-slate-500 block mt-1">
              {stats.packet_loss_pct === 0 ? 'Optimal connection' : 'Intermittent drops'}
            </span>
          </div>

        </div>

        {/* Live Animated Latency Chart */}
        <div className="p-5 rounded-2xl bg-dark-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              Real-Time Latency Waveform ({history.length} samples)
            </span>
            <span className="text-[11px] font-mono text-slate-500">Target: {targetIp}</span>
          </div>

          {history.length > 0 ? (
            <div className="w-full overflow-hidden">
              <svg viewBox={`0 0 ${svgWidth} ${svgHeight}`} className="w-full h-48">
                {/* Horizontal Grid Guides */}
                <line x1="20" y1="20" x2="580" y2="20" stroke="#334155" strokeDasharray="3 3" opacity="0.4" />
                <line x1="20" y1="80" x2="580" y2="80" stroke="#334155" strokeDasharray="3 3" opacity="0.4" />
                <line x1="20" y1="140" x2="580" y2="140" stroke="#334155" strokeDasharray="3 3" opacity="0.4" />

                {/* Gradient Definition */}
                <defs>
                  <linearGradient id="latencyGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00f2ff" stopOpacity="0.4" />
                    <stop offset="100%" stopColor="#00f2ff" stopOpacity="0.0" />
                  </linearGradient>
                </defs>

                {/* Polyline Path */}
                {points && (
                  <>
                    <polygon
                      points={`20,140 ${points} 580,140`}
                      fill="url(#latencyGradient)"
                    />
                    <polyline
                      fill="none"
                      stroke="#00f2ff"
                      strokeWidth="2.5"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      points={points}
                    />
                  </>
                )}
              </svg>
            </div>
          ) : (
            <div className="h-48 flex flex-col items-center justify-center text-slate-500 text-xs italic">
              <Activity className="w-8 h-8 mb-2 text-slate-600 animate-spin" />
              <span>Gathering telemetry probes...</span>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
