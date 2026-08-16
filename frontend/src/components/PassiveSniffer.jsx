import React, { useState, useEffect } from 'react';
import { Eye, EyeOff, Radio, RefreshCw, Server, Laptop, Cpu, ShieldCheck, Play, ArrowRight } from 'lucide-react';

export default function PassiveSniffer({ onGetPassiveDevices, onTargetSelect }) {
  const [devices, setDevices] = useState([]);
  const [isListening, setIsListening] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchDevices = async () => {
    if (!onGetPassiveDevices) return;
    setIsRefreshing(true);
    try {
      const res = await onGetPassiveDevices();
      if (res && res.success) {
        setDevices(res.devices || []);
      }
    } catch (e) {
      console.error('Passive sniffer error:', e);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDevices();
    let interval = null;
    if (isListening) {
      interval = setInterval(fetchDevices, 3000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isListening]);

  return (
    <div className="flex flex-col h-full w-full bg-dark-950 text-slate-200 overflow-hidden select-none">
      {/* Top Header & Status */}
      <div className="p-4 bg-dark-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-indigo-500/15 text-indigo-400">
            <Radio className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xs font-bold uppercase tracking-wider text-white">
                ARP Cache Device Discovery
              </h2>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                PASSIVE LISTENER
              </span>
            </div>
            <p className="text-[11px] text-slate-400">Reads the local OS ARP table (no SYN probes). Shows hosts the machine has recently contacted.</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsListening(!isListening)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
              isListening
                ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/50'
                : 'bg-dark-950 text-slate-400 border border-slate-700'
            }`}
          >
            {isListening ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
            <span>{isListening ? 'Listening Live' : 'Paused'}</span>
          </button>

          <button
            onClick={fetchDevices}
            disabled={isRefreshing}
            className="p-1.5 rounded-xl bg-dark-950 border border-slate-700 text-slate-300 hover:text-white transition-all disabled:opacity-40"
            title="Refresh ARP table cache"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        
        {/* Banner Notice */}
        <div className="p-4 rounded-2xl bg-indigo-500/10 border border-indigo-500/30 text-xs text-indigo-200 flex items-start gap-3">
          <ShieldCheck className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5" />
          <p>
            <strong>Stealth Operating Mode:</strong> In passive mode, Kapow sends <strong>0 probe packets</strong>. Devices are identified strictly by listening to local ARP announcements, broadcast queries, and local OS cache.
          </p>
        </div>

        {/* Discovered Devices Table */}
        <div className="border border-slate-800 rounded-2xl overflow-hidden bg-dark-900 shadow-xl">
          <div className="p-3 border-b border-slate-800 bg-dark-950 flex items-center justify-between">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Passively Discovered Devices ({devices.length})
            </span>
          </div>

          {devices.length > 0 ? (
            <table className="w-full text-left text-xs">
              <thead className="bg-dark-950/80 text-slate-400 font-semibold border-b border-slate-800">
                <tr>
                  <th className="p-3">IP Address</th>
                  <th className="p-3">Physical MAC</th>
                  <th className="p-3">Hardware Manufacturer / Vendor</th>
                  <th className="p-3">Discovery Method</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {devices.map((d, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="p-3 font-bold text-cyan-300">
                      {d.ip}
                    </td>
                    <td className="p-3 text-slate-300">
                      {d.mac || '—'}
                    </td>
                    <td className="p-3 font-sans text-white font-medium">
                      {d.vendor || 'Unknown Vendor'}
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-indigo-500/20 text-indigo-300 font-semibold">
                        {d.discovery_method || 'ARP Cache'}
                      </span>
                    </td>
                    <td className="p-3 text-right font-sans">
                      {onTargetSelect && (
                        <button
                          onClick={() => onTargetSelect(d.ip)}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/25 transition-all inline-flex items-center gap-1"
                        >
                          <span>Scan Host</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="p-12 text-center text-slate-500 text-xs italic">
              <Radio className="w-8 h-8 mx-auto mb-2 text-slate-600 animate-pulse" />
              <span>Listening for local broadcast packets. Devices will appear here as they communicate on the LAN.</span>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
