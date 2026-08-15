import React, { useEffect, useRef, useState, useCallback } from 'react';
import cytoscape from 'cytoscape';
import fcose from 'cytoscape-fcose';
import { ZoomIn, ZoomOut, Maximize2, RefreshCw, Eye, EyeOff, Layers, Info, Laptop, Server, Router as RouterIcon, Shield, ShieldAlert, Sparkles, Orbit, GitBranch, Grid, Circle } from 'lucide-react';

// Register fcose layout extension
try {
  cytoscape.use(fcose);
} catch (e) {
  // Already registered
}

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
        return {
          name: 'circle',
          animate: true,
          animationDuration: 600,
          padding: 60,
        };
      case 'grid':
        return {
          name: 'grid',
          animate: true,
          animationDuration: 600,
          padding: 60,
          avoidOverlap: true,
        };
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
          nodeRepulsion: 7500,
          idealEdgeLength: 100,
          edgeElasticity: 0.45,
          nestingFactor: 0.1,
        };
    }
  };

  // Initialize Cytoscape Instance
  useEffect(() => {
    if (!containerRef.current) return;

    // Filter elements based on showServices toggle
    const nodes = (elements?.nodes || []).map((n) => {
      const isCritical = n.data.risk_level === 'CRITICAL' || n.data.max_cvss >= 9.0;
      const alias = n.data.alias;
      const baseLabel = alias ? `${alias}\n(${n.data.ip})` : n.data.label;

      return {
        ...n,
        data: {
          ...n.data,
          display_label: baseLabel,
          is_critical: isCritical,
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
      elements: {
        nodes: nodes,
        edges: edges,
      },
      style: [
        // Subnet Compound Nodes
        {
          selector: 'node[type="subnet"]',
          style: {
            'shape': 'round-rectangle',
            'background-color': '#0f172a',
            'background-opacity': 0.65,
            'border-width': 2,
            'border-color': '#06b6d4',
            'border-opacity': 0.4,
            'border-style': 'dashed',
            'label': 'data(label)',
            'color': '#38bdf8',
            'font-size': 12,
            'font-weight': 'bold',
            'text-valign': 'top',
            'text-margin-y': -10,
            'padding': '24px',
          },
        },
        // Standard Host Nodes
        {
          selector: 'node[type="host"]',
          style: {
            'shape': 'round-rectangle',
            'width': 110,
            'height': 54,
            'background-color': '#1e293b',
            'border-width': 2,
            'border-color': '#10b981',
            'label': 'data(display_label)',
            'color': '#f8fafc',
            'font-size': 10,
            'font-weight': 600,
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '100px',
            'shadow-blur': 12,
            'shadow-color': 'rgba(16, 185, 129, 0.25)',
            'shadow-opacity': 0.8,
          },
        },
        // Critical Vulnerability Host Nodes (Red Glow)
        {
          selector: 'node[type="host"][?is_critical]',
          style: {
            'border-color': '#f43f5e',
            'border-width': 2.5,
            'shadow-color': '#f43f5e',
            'shadow-blur': 18,
            'shadow-opacity': 0.9,
          },
        },
        // Router / Gateway Nodes
        {
          selector: 'node[type="router"]',
          style: {
            'shape': 'hexagon',
            'width': 95,
            'height': 64,
            'background-color': '#0e7490',
            'border-width': 2,
            'border-color': '#00f2ff',
            'label': 'data(display_label)',
            'color': '#ffffff',
            'font-size': 10,
            'font-weight': 'bold',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'shadow-blur': 15,
            'shadow-color': 'rgba(6, 182, 212, 0.4)',
          },
        },
        // Traceroute Hop Nodes
        {
          selector: 'node[type="hop"]',
          style: {
            'shape': 'ellipse',
            'width': 50,
            'height': 50,
            'background-color': '#334155',
            'border-width': 2,
            'border-color': '#64748b',
            'label': 'data(label)',
            'color': '#cbd5e1',
            'font-size': 9,
            'text-valign': 'bottom',
            'text-margin-y': 4,
            'text-wrap': 'wrap',
          },
        },
        // Service Nodes
        {
          selector: 'node[type="service"]',
          style: {
            'shape': 'ellipse',
            'width': 44,
            'height': 44,
            'background-color': '#312e81',
            'border-width': 1.5,
            'border-color': '#818cf8',
            'label': 'data(label)',
            'color': '#c7d2fe',
            'font-size': 8,
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '40px',
          },
        },
        // Edges
        {
          selector: 'edge',
          style: {
            'width': 1.8,
            'line-color': '#475569',
            'target-arrow-color': '#06b6d4',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.8,
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': 8,
            'color': '#94a3b8',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
          },
        },
        // Selected Node
        {
          selector: ':selected',
          style: {
            'border-color': '#00f2ff',
            'border-width': 3,
            'shadow-color': '#00f2ff',
            'shadow-blur': 22,
            'shadow-opacity': 1,
          },
        },
      ],
      layout: getLayoutConfig(currentLayout),
    });

    // Event Handlers
    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      setSelectedNode(node.data());
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [elements, showServices, currentLayout]);

  // Layout & Navigation controls
  const handleZoomIn = () => cyRef.current && cyRef.current.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current && cyRef.current.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current && cyRef.current.fit(undefined, 50);
  
  const handleSwitchLayout = (newLayout) => {
    setCurrentLayout(newLayout);
    if (cyRef.current) {
      cyRef.current.layout(getLayoutConfig(newLayout)).run();
    }
  };

  return (
    <div className="relative w-full h-full bg-dark-950 overflow-hidden flex select-none">
      {/* Cytoscape Canvas */}
      <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Floating Canvas Controls & Layout Switcher */}
      <div className="absolute top-4 left-4 z-20 flex items-center gap-2 p-1.5 rounded-2xl glass-panel shadow-2xl">
        
        {/* Zoom & Fit */}
        <div className="flex items-center gap-1">
          <button
            onClick={handleZoomIn}
            className="p-2 rounded-xl bg-dark-900/80 hover:bg-slate-800 text-slate-300 hover:text-white transition-all"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-2 rounded-xl bg-dark-900/80 hover:bg-slate-800 text-slate-300 hover:text-white transition-all"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={handleFit}
            className="p-2 rounded-xl bg-dark-900/80 hover:bg-slate-800 text-slate-300 hover:text-white transition-all"
            title="Fit Network to Screen"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>

        <div className="w-px h-5 bg-slate-700 mx-0.5" />

        {/* Feature 6: Dynamic Multi-Layout Selector */}
        <div className="flex items-center gap-1">
          <Layers className="w-3.5 h-3.5 text-cyan-400 ml-1" />
          <select
            value={currentLayout}
            onChange={(e) => handleSwitchLayout(e.target.value)}
            className="bg-dark-900/90 border border-slate-700/80 rounded-xl px-2.5 py-1.5 text-xs text-cyan-300 font-semibold focus:outline-none focus:border-brand-cyan"
          >
            {LAYOUT_OPTIONS.map((lo) => (
              <option key={lo.id} value={lo.id}>{lo.label}</option>
            ))}
          </select>
        </div>

        <div className="w-px h-5 bg-slate-700 mx-0.5" />

        {/* Service Nodes Toggle */}
        <button
          onClick={() => setShowServices(!showServices)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
            showServices 
              ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' 
              : 'bg-dark-900/80 text-slate-400 hover:text-slate-200'
          }`}
          title="Toggle port service leaves"
        >
          {showServices ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
          <span>Services</span>
        </button>
      </div>

      {/* Floating Legend Overlay */}
      <div className="absolute bottom-4 left-4 z-20 p-3 rounded-2xl glass-panel text-[11px] text-slate-300 flex items-center gap-4 shadow-xl">
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-sm bg-dark-900 border border-cyan-400 border-dashed" />
          <span>Subnet</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 bg-cyan-600 border border-cyan-400 rotate-45" />
          <span>Router</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-sm bg-slate-800 border border-emerald-400" />
          <span>Secure Host</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-sm bg-slate-800 border border-rose-500 shadow-glow-rose" />
          <span>Vulnerable Host</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full bg-indigo-900 border border-indigo-400" />
          <span>Service</span>
        </div>
      </div>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="absolute top-4 right-4 z-20 w-84 rounded-2xl glass-panel p-4 shadow-2xl animate-in fade-in slide-in-from-right-4 duration-200 border border-slate-700/80">
          <div className="flex items-start justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className={`p-2 rounded-xl ${selectedNode.is_critical ? 'bg-rose-500/20 text-rose-400' : 'bg-cyan-500/15 text-cyan-400'}`}>
                {selectedNode.is_critical ? <ShieldAlert className="w-4 h-4" /> : <Info className="w-4 h-4" />}
              </div>
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                  {selectedNode.alias || selectedNode.type || 'Node'}
                </h3>
                <span className="text-[11px] font-mono text-cyan-300 block">
                  {selectedNode.ip || selectedNode.id}
                </span>
              </div>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-slate-400 hover:text-white text-xs p-1"
            >
              ✕
            </button>
          </div>

          <div className="py-3 space-y-2 text-xs">
            {selectedNode.alias && (
              <div className="flex justify-between">
                <span className="text-slate-400">Custom Alias:</span>
                <span className="text-emerald-400 font-semibold truncate max-w-[160px]">{selectedNode.alias}</span>
              </div>
            )}
            {selectedNode.hostname && (
              <div className="flex justify-between">
                <span className="text-slate-400">Hostname:</span>
                <span className="text-slate-200 font-mono font-medium truncate max-w-[160px]">{selectedNode.hostname}</span>
              </div>
            )}
            {selectedNode.mac && (
              <div className="flex justify-between">
                <span className="text-slate-400">MAC:</span>
                <span className="text-slate-200 font-mono">{selectedNode.mac}</span>
              </div>
            )}
            {selectedNode.vendor && (
              <div className="flex justify-between">
                <span className="text-slate-400">Vendor:</span>
                <span className="text-slate-200">{selectedNode.vendor}</span>
              </div>
            )}
            {selectedNode.os && (
              <div className="flex justify-between">
                <span className="text-slate-400">OS:</span>
                <span className="text-slate-200 truncate max-w-[160px]">{selectedNode.os}</span>
              </div>
            )}
            {selectedNode.service && (
              <div className="flex justify-between">
                <span className="text-slate-400">Service:</span>
                <span className="text-emerald-400 font-mono font-semibold">{selectedNode.service} ({selectedNode.port}/{selectedNode.protocol})</span>
              </div>
            )}

            {/* CVE Warning */}
            {selectedNode.is_critical && (
              <div className="p-2.5 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-300 text-[11px] mt-2">
                <strong className="block font-bold">⚠️ Critical Vulnerabilities Found</strong>
                <span>Max CVSS: {selectedNode.max_cvss || '9.0+'}</span>
              </div>
            )}
          </div>

          {selectedNode.type === 'host' && (
            <button
              onClick={() => onSelectHost(selectedNode)}
              className="w-full mt-2 py-2 rounded-xl text-xs font-bold bg-brand-cyan hover:bg-cyan-400 text-slate-950 shadow-glow-cyan transition-all"
            >
              Inspect & Tag Host Profile
            </button>
          )}
        </div>
      )}
    </div>
  );
}
