import React, { useState } from 'react';
import { Globe, Monitor, Terminal, Folder, Zap, Activity, Check, AlertCircle } from 'lucide-react';

export default function QuickActions({ ip, mac, ports = [], onLaunchProtocol, onSendWol, onOpenTelemetry }) {
  const [feedback, setFeedback] = useState(null);

  if (!ip) return null;

  const handleAction = async (protocol, port, extra) => {
    if (onLaunchProtocol) {
      const res = await onLaunchProtocol(protocol, ip, port, extra);
      if (res && res.success) {
        setFeedback(`Launched ${protocol.toUpperCase()}`);
        setTimeout(() => setFeedback(null), 2000);
      } else if (res && res.error) {
        setFeedback(`Error: ${res.error}`);
        setTimeout(() => setFeedback(null), 3000);
      }
    }
  };

  const handleWol = async () => {
    if (!mac) {
      setFeedback('MAC address required for WoL');
      setTimeout(() => setFeedback(null), 2500);
      return;
    }
    if (onSendWol) {
      const res = await onSendWol(mac);
      if (res && res.success) {
        setFeedback('WoL Magic Packet Sent!');
        setTimeout(() => setFeedback(null), 2500);
      } else {
        setFeedback(res?.error || 'WoL Failed');
        setTimeout(() => setFeedback(null), 3000);
      }
    }
  };

  // Check detected ports
  const openPortNumbers = (ports || []).map((p) => p.portid || p.port);
  const hasHttp = openPortNumbers.includes(80) || openPortNumbers.includes(8080) || openPortNumbers.includes(3000) || openPortNumbers.includes(5000);
  const hasHttps = openPortNumbers.includes(443) || openPortNumbers.includes(8443);
  const hasSsh = openPortNumbers.includes(22);
  const hasRdp = openPortNumbers.includes(3389);
  const hasSmb = openPortNumbers.includes(445) || openPortNumbers.includes(139);

  return (
    <div className="p-3.5 rounded-2xl bg-dark-900 border border-slate-800 flex flex-wrap items-center justify-between gap-3 select-none">
      <div className="flex items-center gap-2">
        <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Quick Actions:</span>
        {feedback && (
          <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 animate-fade-in">
            {feedback}
          </span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        {/* HTTP / HTTPS */}
        <button
          onClick={() => handleAction(hasHttps ? 'https' : 'http', hasHttps ? 443 : 80)}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-semibold border transition-all ${
            hasHttp || hasHttps
              ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40 hover:bg-cyan-500/25 shadow-sm'
              : 'bg-dark-950/80 text-slate-400 border-slate-800 hover:text-slate-200'
          }`}
          title="Open in default web browser"
        >
          <Globe className="w-3.5 h-3.5" />
          <span>Browser</span>
        </button>

        {/* SSH Terminal */}
        <button
          onClick={() => handleAction('ssh', 22)}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-semibold border transition-all ${
            hasSsh
              ? 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40 hover:bg-indigo-500/30'
              : 'bg-dark-950/80 text-slate-400 border-slate-800 hover:text-slate-200'
          }`}
          title="Launch SSH session in terminal"
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>SSH</span>
        </button>

        {/* Remote Desktop (RDP) */}
        <button
          onClick={() => handleAction('rdp', 3389)}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-semibold border transition-all ${
            hasRdp
              ? 'bg-blue-500/20 text-blue-300 border-blue-500/40 hover:bg-blue-500/30'
              : 'bg-dark-950/80 text-slate-400 border-slate-800 hover:text-slate-200'
          }`}
          title="Connect via Windows Remote Desktop (mstsc)"
        >
          <Monitor className="w-3.5 h-3.5" />
          <span>RDP</span>
        </button>

        {/* Windows SMB Share */}
        <button
          onClick={() => handleAction('smb', 445)}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-semibold border transition-all ${
            hasSmb
              ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 hover:bg-emerald-500/30'
              : 'bg-dark-950/80 text-slate-400 border-slate-800 hover:text-slate-200'
          }`}
          title="Open shared folder in Windows Explorer"
        >
          <Folder className="w-3.5 h-3.5" />
          <span>SMB</span>
        </button>

        {/* Wake-on-LAN */}
        <button
          onClick={handleWol}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-semibold border transition-all ${
            mac 
              ? 'bg-amber-500/15 text-amber-300 border-amber-500/40 hover:bg-amber-500/25' 
              : 'bg-dark-950/60 text-slate-500 border-slate-800 cursor-not-allowed opacity-60'
          }`}
          title={mac ? `Send Wake-on-LAN magic packet to ${mac}` : 'WoL requires known MAC address'}
        >
          <Zap className="w-3.5 h-3.5" />
          <span>Wake-on-LAN</span>
        </button>

        {/* Live Telemetry Ping */}
        {onOpenTelemetry && (
          <button
            onClick={() => onOpenTelemetry(ip)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-semibold bg-cyan-500/10 text-brand-cyan border border-cyan-500/30 hover:bg-cyan-500/20 transition-all"
            title="Open real-time ICMP ping telemetry chart"
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Ping Telemetry</span>
          </button>
        )}
      </div>
    </div>
  );
}
