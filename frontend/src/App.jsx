import React, { useState, useEffect, useCallback } from 'react';
import Topology from './components/Topology';
import ErrorBoundary from './components/ErrorBoundary';

// Minimal bootstrap baseline: header + topology canvas that auto-loads a
// sample network so SOMETHING is always visible. Premium panels (tabs,
// inventory, alerts, console, settings) are layered back on once this
// renders reliably.

const buildSample = () => {
  const hosts = [
    { ip: '192.168.1.1', type: 'router', label: 'gateway', risk_level: 'LOW' },
    { ip: '192.168.1.20', type: 'host', label: 'pi-homelab', risk_level: 'LOW' },
    { ip: '192.168.1.35', type: 'host', label: 'router.asus', risk_level: 'MEDIUM' },
    { ip: '192.168.1.77', type: 'host', label: 'nas', risk_level: 'HIGH' },
    { ip: '192.168.1.90', type: 'host', label: 'vm-win', risk_level: 'CRITICAL' },
  ];
  const nodes = [
    { data: { id: 'subnet-0', type: 'subnet', label: '192.168.1.0/24' } },
    ...hosts.map((h) => ({ data: { id: `host-${h.ip}`, type: h.type, label: h.label, ip: h.ip } })),
  ];
  const edges = hosts.map((h) => ({ data: { id: `e-${h.ip}`, source: 'subnet-0', target: `host-${h.ip}` } }));
  return { nodes, edges };
};

export default function App() {
  const [elements, setElements] = useState(() => buildSample());

  const handleSelectHost = useCallback((data) => {
    // eslint-disable-next-line no-console
    console.log('selected host:', data);
  }, []);

  return (
    <div className="flex flex-col h-screen w-full bg-dark-950 text-slate-100">
      <header className="flex items-center gap-3 px-4 py-2 bg-dark-900 border-b border-slate-800 shrink-0">
        <span className="font-bold text-brand-cyan">Kapow</span>
        <span className="text-xs text-slate-400">Network Security Auditor</span>
        <span className="ml-auto text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">v1.5</span>
      </header>
      <main className="flex-1 min-h-0">
        <ErrorBoundary>
          <Topology elements={elements} onSelectHost={handleSelectHost} />
        </ErrorBoundary>
      </main>
    </div>
  );
}
