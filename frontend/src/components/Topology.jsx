import React, { useEffect, useRef, useState, useCallback } from 'react';
import cytoscape from 'cytoscape';
import fcose from 'cytoscape-fcose';
import { ZoomIn, ZoomOut, Maximize2, RefreshCw, Eye, EyeOff, Layers, Info, Laptop, Server, Router as RouterIcon, Shield, ShieldAlert, Sparkles, Orbit, GitBranch, Grid, Circle, Cpu, Printer, Smartphone, Wifi, Tv } from 'lucide-react';

// Register fcose layout extension
try {
  cytoscape.use(fcose);
} catch (e) {
  // Already registered
}

// Device glyphs rendered as SVG data-URIs so they sit on the node surface
const glyph = (path, color = '#e2e8f0') =>
  `data:image/svg+xml;utf8,${encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="${path}"/></svg>`
  )}`;

const GLYPHS = {
  router: glyph('M3 13h2l2 4h6l2-4h2a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2H3a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2z M8 18v3 M16 18v3 M8 13v4 M16 13v4'),
  host: glyph('M4 5h16v10H4z M2 19h20 M9 19v-4 M15 19v-4'),
  server: glyph('M3 4h18v6H3z M3 14h18v6H3z M7 7h.01 M7 17h.01'),
  printer: glyph('M6 9V3h12v6 M6 18H4a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2h-2 M6 14h12v7H6z'),
  mobile: glyph('M7 2h10a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z M11 18h2'),
  iot: glyph('M5 12a7 7 0 0 1 14 0 M8.5 12a3.5 3.5 0 0 1 7 0 M12 12v.01'),
  service: glyph('M12 2v4 M12 18v4 M2 12h4 M18 12h4 M5 5l3 3 M16 16l3 3 M19 5l-3 3 M8 16l-3 3'),
  subnet: glyph('M12 2 2 7l10 5 10-5z M2 17l10 5 10-5 M2 12l10 5 10-5'),
};

const glyphFor = (type, data) => {
  if (type === 'router') return GLYPHS.router;
  if (type === 'subnet') return GLYPHS.subnet;
  if (type === 'service') return GLYPHS.service;
  if (type === 'host') {
    const v = (data.vendor || '').toLowerCase();
    const os = (data.os || '').toLowerCase();
    if (/printer|brother|epson|canon|hp /.test(v)) return GLYPHS.printer;
    if (/phone|samsung|xiaomi|oneplus|oppo|vivo|iphone|android/.test(os + v)) return GLYPHS.mobile;
    if (/raspberry|espressif|iot/.test(v + os)) return GLYPHS.iot;
    if (/server|linux|windows server|nas|synology|qnap/.test(os + v)) return GLYPHS.server;
    return GLYPHS.host;
  }
  return null;
};

const LAYOUT_OPTIONS = [
  { id: 'fcose', label: 'Force-Directed', icon: Orbit, desc: 'Organic physics-based clustering' },
  { id: 'concentric', label: 'Radial / Concentric', icon: Circle, desc: 'Gateway in center, hosts in orbit' },
  { id: 'breadthfirst', label: 'Hierarchical Tree', icon: GitBranch, desc: 'Top-down router to subnet tree' },
  { id: 'circle', label: 'Circular Ring', icon: Circle, desc: 'Perimeter ring network layout' },
  { id: 'grid', label: 'Matrix Grid', icon: Grid, desc: 'Aligned structured asset grid' },
];

export default function Topology({ elements, onSelectHost }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const tickerRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [showServices, setShowServices] = useState(true);
  const [currentLayout, setCurrentLayout] = useState('fcose');

  const getLayoutConfig = (layoutName) => {
    switch (layoutName) {
      case 'concentric':
        return {
          name: 'concentric',
          animate: true,
          animationDuration: 600,
          concentric: (node) => {
            if (node.data('type') === 'router') return 10;
            if (node.data('type') === 'subnet') return 8;
            if (node.data('type') === 'host') return 5;
            return 2;
          },
          levelWidth: () => 2,
          padding: 60,
        };
      case 'breadthfirst':
        return {
          name: 'breadthfirst',
          animate: true,
          animationDuration: 600,
          directed: true,
          padding: 60,
          spacingFactor: 1.25,
        };
      case 'circle':
        return { name: 'circle', animate: true, animationDuration: 600, padding: 60 };
      case 'grid':
        return { name: 'grid', animate: true, animationDuration: 600, padding: 60, avoidOverlap: true };
      case 'fcose':
      default:
        return {
          name: 'fcose',
          quality: 'default',
          randomize: false,
          animate: true,
          animationDuration: 700,
          nodeDimensionsIncludeLabels: true,
          fit: true,
          padding: 60,
          nodeRepulsion: 9000,
          idealEdgeLength: 110,
          edgeElasticity: 0.45,
          nestingFactor: 0.1,
        };
    }
  };

  // Initialize Cytoscape Instance
  useEffect(() => {
    if (!containerRef.current) return;

    const nodes = (elements?.nodes || []).map((n) => {
      const isCritical = n.data.risk_level === 'CRITICAL' || n.data.max_cvss >= 9.0;
      const alias = n.data.alias;
      const baseLabel = alias ? `${alias}\n(${n.data.ip})` : n.data.label;
      const g = glyphFor(n.data.type, n.data);
      return {
        ...n,
        data: {
          ...n.data,
          display_label: baseLabel,
          is_critical: isCritical,
          glyph_url: g || '',
        },
      };
    }).filter((n) => {
      if (!showServices && n.data.type === 'service') return false;
      return true;
    });

    const nodeIds = new Set(nodes.map((n) => n.data.id));
    const edges = (elements?.edges || []).filter((e) => {
      if (!showServices && (e.data.source.startsWith('service-') || e.data.target.startsWith('service-'))) return false;
      return nodeIds.has(e.data.source) && nodeIds.has(e.data.target);
    });

    const cy = cytoscape({
      container: containerRef.current,
      elements: { nodes, edges },
      style: [
        // Ambient substrate is handled by the DOM layer behind; canvas stays transparent
        {
          selector: 'node[type="subnet"]',
          style: {
            'shape': 'round-rectangle',
            'background-color': 'rgba(8, 15, 30, 0.85)',
            'background-gradient-stop-colors': '#0e7490 #0b1220',
            'background-gradient-stop-positions': '0 100',
            'background-gradient-direction': 'to-bottom',
            'border-width': 1.5,
            'border-color': 'rgba(6, 182, 212, 0.55)',
            'border-style': 'dashed',
            'label': 'data(label)',
            'color': '#7dd3fc',
            'font-size': 12,
            'font-weight': 700,
            'font-family': 'Inter, sans-serif',
            'text-valign': 'top',
            'text-margin-y': -10,
            'padding': '26px',
            'shadow-blur': 18,
            'shadow-color': 'rgba(6, 182, 212, 0.3)',
          },
        },
        {
          selector: 'node[type="host"]',
          style: {
            'shape': 'round-rectangle',
            'width': 118,
            'height': 60,
            'background-color': 'rgba(16, 185, 129, 0.10)',
            'background-gradient-stop-colors': '#1e293b #0f1b2e',
            'background-gradient-stop-positions': '0 100',
            'background-gradient-direction': 'to-bottom',
            'background-opacity': 0.95,
            'border-width': 1.5,
            'border-color': 'rgba(16, 185, 129, 0.55)',
            'label': 'data(display_label)',
            'color': '#f1f5f9',
            'font-size': 10.5,
            'font-weight': 600,
            'font-family': 'Inter, sans-serif',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '104px',
            'shadow-blur': 14,
            'shadow-color': 'rgba(16, 185, 129, 0.28)',
            'shadow-opacity': 0.85,
          },
        },
        {
          selector: 'node[type="host"][?is_critical]',
          style: {
            'border-color': 'rgba(244, 63, 94, 0.85)',
            'border-width': 2.2,
            'shadow-color': 'rgba(244, 63, 94, 0.5)',
            'shadow-blur': 24,
            'background-color': 'rgba(244, 63, 94, 0.12)',
          },
        },
        {
          selector: 'node[type="router"]',
          style: {
            'shape': 'hexagon',
            'width': 100,
            'height': 70,
            'background-color': 'rgba(6, 182, 212, 0.18)',
            'background-gradient-stop-colors': '#0e7490 #082f49',
            'background-gradient-stop-positions': '0 100',
            'background-gradient-direction': 'to-bottom',
            'border-width': 2,
            'border-color': 'rgba(0, 242, 255, 0.8)',
            'label': 'data(display_label)',
            'color': '#ffffff',
            'font-size': 10.5,
            'font-weight': 700,
            'font-family': 'Inter, sans-serif',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'shadow-blur': 22,
            'shadow-color': 'rgba(0, 242, 255, 0.45)',
          },
        },
        {
          selector: 'node[type="service"]',
          style: {
            'shape': 'ellipse',
            'width': 46,
            'height': 46,
            'background-color': 'rgba(99, 102, 241, 0.18)',
            'background-gradient-stop-colors': '#3730a3 #1e1b4b',
            'background-gradient-stop-positions': '0 100',
            'background-gradient-direction': 'to-bottom',
            'border-width': 1.4,
            'border-color': 'rgba(129, 140, 248, 0.7)',
            'label': 'data(label)',
            'color': '#c7d2fe',
            'font-size': 8,
            'font-family': 'JetBrains Mono, monospace',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '42px',
            'shadow-blur': 12,
            'shadow-color': 'rgba(99, 102, 241, 0.4)',
          },
        },
        {
          selector: 'node[glyph_url != ""]',
          style: {
            'background-image': 'data(glyph_url)',
            'background-fit': 'none',
            'background-width': '26px',
            'background-height': '26px',
            'background-position-x': '50%',
            'background-position-y': '24%',
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 1.6,
            'line-color': 'rgba(71, 85, 105, 0.6)',
            'target-arrow-color': 'rgba(6, 182, 212, 0.8)',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.8,
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': 8,
            'color': '#94a3b8',
            'font-family': 'JetBrains Mono, monospace',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
            'line-dash-pattern': [6, 8],
            'line-dash-offset': 0,
          },
        },
        {
          selector: 'edge[?critical]',
          style: {
            'line-color': 'rgba(244, 63, 94, 0.7)',
            'target-arrow-color': 'rgba(244, 63, 94, 0.9)',
          },
        },
        {
          selector: ':selected',
          style: {
            'border-color': 'rgba(0, 242, 255, 1)',
            'border-width': 3,
            'shadow-color': 'rgba(0, 242, 255, 0.7)',
            'shadow-blur': 26,
            'shadow-opacity': 1,
          },
        },
      ],
      layout: getLayoutConfig(currentLayout),
    });

    // Animated data-flow on edges (drive line-dash-offset)
    let offset = 0;
    const tick = () => {
      offset = (offset - 0.6) % 1000;
      cy.edges().forEach((e) => e.style('line-dash-offset', offset));
      tickerRef.current = requestAnimationFrame(tick);
    };
    tickerRef.current = requestAnimationFrame(tick);

    cy.on('tap', 'node', (evt) => setSelectedNode(evt.target.data()));
    cy.on('tap', (evt) => { if (evt.target === cy) setSelectedNode(null); });
    cyRef.current = cy;

    return () => {
      if (tickerRef.current) cancelAnimationFrame(tickerRef.current);
      cy.destroy();
    };
  }, [elements, showServices, currentLayout]);

  const handleZoomIn = () => cyRef.current && cyRef.current.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current && cyRef.current.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current && cyRef.current.fit(undefined, 50);

  const handleSwitchLayout = (newLayout) => {
    setCurrentLayout(newLayout);
    if (cyRef.current) cyRef.current.layout(getLayoutConfig(newLayout)).run();
  };

  return (
    <div className="relative w-full h-full bg-dark-950 overflow-hidden flex select-none">
      {/* Ambient substrate: radial vignette + dot mesh + blurred brand glows */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(circle at 30% 20%, rgba(6,182,212,0.10), transparent 55%), radial-gradient(circle at 78% 75%, rgba(99,102,241,0.12), transparent 55%), radial-gradient(circle at 50% 50%, #070a13 0%, #04060d 100%)',
        }}
      />
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.18]"
        style={{
          backgroundImage:
            'radial-gradient(rgba(148,163,184,0.35) 1px, transparent 1px)',
          backgroundSize: '26px 26px',
          maskImage: 'radial-gradient(circle at 50% 50%, black 30%, transparent 85%)',
          WebkitMaskImage: 'radial-gradient(circle at 50% 50%, black 30%, transparent 85%)',
        }}
      />
      <div className="absolute -top-32 -left-32 w-96 h-96 rounded-full bg-brand-cyan/10 blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-24 w-[28rem] h-[28rem] rounded-full bg-brand-indigo/10 blur-3xl pointer-events-none" />

      {/* Cytoscape Canvas */}
      <div ref={containerRef} className="absolute inset-0 cursor-grab active:cursor-grabbing" style={{ background: 'transparent' }} />

      {/* Floating Canvas Controls */}
      <div className="absolute top-4 left-4 z-20 flex items-center gap-2 p-1.5 rounded-2xl glass-edge shadow-2xl">
        <div className="flex items-center gap-1">
          <button onClick={handleZoomIn} className="p-2 rounded-xl bg-dark-900/70 hover:bg-slate-800 text-slate-300 hover:text-white transition-all" title="Zoom In"><ZoomIn className="w-4 h-4" /></button>
          <button onClick={handleZoomOut} className="p-2 rounded-xl bg-dark-900/70 hover:bg-slate-800 text-slate-300 hover:text-white transition-all" title="Zoom Out"><ZoomOut className="w-4 h-4" /></button>
          <button onClick={handleFit} className="p-2 rounded-xl bg-dark-900/70 hover:bg-slate-800 text-slate-300 hover:text-white transition-all" title="Fit Network to Screen"><Maximize2 className="w-4 h-4" /></button>
        </div>
        <div className="w-px h-5 bg-slate-700/70 mx-0.5" />
        <div className="flex items-center gap-1">
          <Layers className="w-3.5 h-3.5 text-cyan-400 ml-1" />
          <select
            value={currentLayout}
            onChange={(e) => handleSwitchLayout(e.target.value)}
            className="bg-dark-900/90 border border-slate-700/80 rounded-xl px-2.5 py-1.5 text-xs text-cyan-300 font-semibold focus:outline-none focus:border-brand-cyan"
          >
            {LAYOUT_OPTIONS.map((lo) => (<option key={lo.id} value={lo.id}>{lo.label}</option>))}
          </select>
        </div>
        <div className="w-px h-5 bg-slate-700/70 mx-0.5" />
        <button
          onClick={() => setShowServices(!showServices)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${showServices ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' : 'bg-dark-900/80 text-slate-400 hover:text-slate-200'}`}
          title="Toggle port service leaves"
        >
          {showServices ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
          <span>Services</span>
        </button>
      </div>

      {/* Floating Legend Overlay */}
      <div className="absolute bottom-4 left-4 z-20 p-3 rounded-2xl glass-edge text-[11px] text-slate-300 flex items-center gap-4 shadow-xl">
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-sm bg-dark-900 border border-cyan-400 border-dashed" /><span>Subnet</span></div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 bg-cyan-600 border border-cyan-400 rotate-45" /><span>Router</span></div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-sm bg-slate-800 border border-emerald-400" /><span>Secure Host</span></div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-sm bg-slate-800 border border-rose-500 shadow-glow-rose" /><span>Vulnerable Host</span></div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-indigo-900 border border-indigo-400" /><span>Service</span></div>
      </div>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="absolute top-4 right-4 z-20 w-84 rounded-2xl glass-edge p-4 shadow-2xl animate-fade-in border border-slate-700/60">
          <div className="flex items-start justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className={`p-2 rounded-xl ${selectedNode.is_critical ? 'bg-rose-500/20 text-rose-400' : 'bg-cyan-500/15 text-cyan-400'}`}>
                {selectedNode.is_critical ? <ShieldAlert className="w-4 h-4" /> : <Info className="w-4 h-4" />}
              </div>
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                  {selectedNode.alias || selectedNode.type || 'Node'}
                </h3>
                <span className="text-[11px] font-mono text-cyan-300 block">{selectedNode.ip || selectedNode.id}</span>
              </div>
            </div>
            <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-white text-xs p-1">✕</button>
          </div>

          <div className="py-3 space-y-2 text-xs">
            {selectedNode.alias && (<div className="flex justify-between"><span className="text-slate-400">Custom Alias:</span><span className="text-emerald-400 font-semibold truncate max-w-[160px]">{selectedNode.alias}</span></div>)}
            {selectedNode.hostname && (<div className="flex justify-between"><span className="text-slate-400">Hostname:</span><span className="text-slate-200 font-mono font-medium truncate max-w-[160px]">{selectedNode.hostname}</span></div>)}
            {selectedNode.mac && (<div className="flex justify-between"><span className="text-slate-400">MAC:</span><span className="text-slate-200 font-mono">{selectedNode.mac}</span></div>)}
            {selectedNode.vendor && (<div className="flex justify-between"><span className="text-slate-400">Vendor:</span><span className="text-slate-200">{selectedNode.vendor}</span></div>)}
            {selectedNode.os && (<div className="flex justify-between"><span className="text-slate-400">OS:</span><span className="text-slate-200 truncate max-w-[160px]">{selectedNode.os}</span></div>)}
            {selectedNode.service && (<div className="flex justify-between"><span className="text-slate-400">Service:</span><span className="text-emerald-400 font-mono font-semibold">{selectedNode.service} ({selectedNode.port}/{selectedNode.protocol})</span></div>)}

            {selectedNode.is_critical && (
              <div className="p-2.5 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-300 text-[11px] mt-2">
                <strong className="block font-bold">⚠️ Critical Vulnerabilities Found</strong>
                <span>Max CVSS: {selectedNode.max_cvss || '9.0+'}</span>
              </div>
            )}
          </div>

          {selectedNode.type === 'host' && (
            <button onClick={() => onSelectHost(selectedNode)} className="w-full mt-2 py-2 rounded-xl text-xs font-bold bg-brand-cyan hover:bg-cyan-400 text-slate-950 shadow-glow-cyan transition-all">
              Inspect & Tag Host Profile
            </button>
          )}
          {selectedNode.type === 'service' && selectedNode.host_ip && (
            <button onClick={() => onSelectHost(selectedNode)} className="w-full mt-2 py-2 rounded-xl text-xs font-bold bg-brand-cyan/20 hover:bg-brand-cyan/30 text-brand-cyan border border-brand-cyan/30 transition-all">
              Inspect Host ({selectedNode.host_ip})
            </button>
          )}
        </div>
      )}
    </div>
  );
}
