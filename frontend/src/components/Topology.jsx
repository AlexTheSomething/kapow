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

// Device glyphs (monochrome line icons) rendered as cytoscape background images.
const GLYPHS = {
  host: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI0IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxyZWN0IHg9IjEwIiB5PSIxNCIgd2lkdGg9IjQ0IiBoZWlnaHQ9IjMwIiByeD0iMyIvPjxwYXRoIGQ9Ik0yNCA1MiBoMTYiLz48cGF0aCBkPSJNMzIgNDQgdjgiLz48L2c+PC9zdmc+',
  router: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI0IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwYXRoIGQ9Ik0yNCAyNiBMMjAgMTQiLz48cGF0aCBkPSJNNDAgMjYgTDQ0IDE0Ii8+PHJlY3QgeD0iMTQiIHk9IjI2IiB3aWR0aD0iMzYiIGhlaWdodD0iMjIiIHJ4PSI0Ii8+PHBhdGggZD0iTTIyIDM1IGgyMCIvPjwvZz48L3N2Zz4=',
  switch: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI0IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxyZWN0IHg9IjEwIiB5PSIyMCIgd2lkdGg9IjQ0IiBoZWlnaHQ9IjI0IiByeD0iMyIvPjxwYXRoIGQ9Ik0xOCA0MiB2NiIvPjxwYXRoIGQ9Ik0yOCA0MiB2NiIvPjxwYXRoIGQ9Ik0zOCA0MiB2NiIvPjxwYXRoIGQ9Ik00OCA0MiB2NiIvPjwvZz48L3N2Zz4=',
  server: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI0IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxyZWN0IHg9IjE0IiB5PSIxNCIgd2lkdGg9IjM2IiBoZWlnaHQ9IjEzIiByeD0iMiIvPjxyZWN0IHg9IjE0IiB5PSIzMSIgd2lkdGg9IjM2IiBoZWlnaHQ9IjEzIiByeD0iMiIvPjxjaXJjbGUgY3g9IjIyIiBjeT0iMjAuNSIgcj0iMiIgZmlsbD0id2hpdGUiLz48Y2lyY2xlIGN4PSIyMiIgY3k9IjM3LjUiIHI9IjIiIGZpbGw9IndoaXRlIi8+PC9nPjwvc3ZnPg==',
  nas: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI0IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxyZWN0IHg9IjE0IiB5PSIxMiIgd2lkdGg9IjM2IiBoZWlnaHQ9IjQwIiByeD0iMyIvPjxwYXRoIGQ9Ik0yMiAyNCBoMjAiLz48cGF0aCBkPSJNMjIgMzIgaDIwIi8+PHBhdGggZD0iTTIyIDQwIGgyMCIvPjxjaXJjbGUgY3g9IjQ2IiBjeT0iMTgiIHI9IjIiIGZpbGw9IndoaXRlIi8+PC9nPjwvc3ZnPg==',
  printer: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI0IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxyZWN0IHg9IjE2IiB5PSIyNCIgd2lkdGg9IjMyIiBoZWlnaHQ9IjIyIiByeD0iMiIvPjxyZWN0IHg9IjIyIiB5PSIxNCIgd2lkdGg9IjIwIiBoZWlnaHQ9IjEwIiByeD0iMSIvPjxwYXRoIGQ9Ik0yNCA0NiBoMTYiLz48Y2lyY2xlIGN4PSI0NCIgY3k9IjMwIiByPSIyIiBmaWxsPSJ3aGl0ZSIvPjwvZz48L3N2Zz4=',
  camera: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI0IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwYXRoIGQ9Ik0xOCA0MiBhMTQgMTQgMCAwIDEgMjggMCIvPjxwYXRoIGQ9Ik0zMiAyOCB2LTEyIi8+PHBhdGggZD0iTTE0IDQyIGgzNiIvPjwvZz48L3N2Zz4=',
  phone: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI0IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxyZWN0IHg9IjIyIiB5PSIxMCIgd2lkdGg9IjIwIiBoZWlnaHQ9IjQ0IiByeD0iNCIvPjxwYXRoIGQ9Ik0yOCAxNiBoOCIvPjxjaXJjbGUgY3g9IjMyIiBjeT0iNDYiIHI9IjEuNSIgZmlsbD0id2hpdGUiLz48L2c+PC9zdmc+',
  iot: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI0IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxjaXJjbGUgY3g9IjMyIiBjeT0iMjYiIHI9IjEwIi8+PHBhdGggZD0iTTI2IDM2IGgxMiIvPjxwYXRoIGQ9Ik0yOCA0MCBoOCIvPjxwYXRoIGQ9Ik0zMCA0NCBoNCIvPjwvZz48L3N2Zz4=',
  ap: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI0IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxyZWN0IHg9IjIyIiB5PSIzOCIgd2lkdGg9IjIwIiBoZWlnaHQ9IjE0IiByeD0iMiIvPjxwYXRoIGQ9Ik0yMiAzMCBhMTIgMTIgMCAwIDEgMjAgMCIvPjxwYXRoIGQ9Ik0yNiAyNCBhNyA3IDAgMCAxIDEyIDAiLz48L2c+PC9zdmc+',
};

// Derive a glyph kind from a node's data (prefers explicit type, else infers from os/vendor).
const deviceKind = (d) => {
  const t = (d.type || '').toLowerCase();
  if (t === 'router' || t === 'gateway') return 'router';
  if (t === 'service') return 'service';
  const vendor = (d.vendor || '').toLowerCase();
  const os = (d.os || '').toLowerCase();
  const ports = Array.isArray(d.ports) ? d.ports.map((p) => (String(p.portid || '') + ' ' + String(p.service?.name || '')).toLowerCase()) : [];
  const openFor = (s) => ports.some((p) => p.includes(s));
  if (/router|gateway|firewall|modem|access point|ubiquiti|mikrotik|asus|netgear|tp-link|linksys|dd-wrt/i.test(vendor + ' ' + os)) return 'router';
  if (/switch|catalyst|junos|brocade/i.test(vendor)) return 'switch';
  if (/nas|synology|qnap|freenas|truenas|readynas/i.test(vendor + ' ' + os) || openFor('nfs') || openFor('smb') || openFor('microsoft-ds') || openFor('445')) return 'nas';
  if (/printer|epson|canon|brother|lexmark/i.test(vendor) || openFor('ipp') || openFor('9100') || openFor('631')) return 'printer';
  if (/camera|hikvision|dahua|axis|foscam|reolink|webcam/i.test(vendor + ' ' + os) || openFor('rtsp')) return 'camera';
  if (/iphone|ipad|android|samsung|pixel|tablet/i.test(os + ' ' + vendor)) return 'phone';
  if (/nest|echo|alexa|ring|hue|sonoff|esp|arduino|iot|smart|thermostat|tuya/i.test(vendor + ' ' + os)) return 'iot';
  if (/unifi|omada|wifi|wireless/i.test(vendor + ' ' + os)) return 'ap';
  if (/server|windows server|ubuntu|debian|centos|rhel|proxmox|esxi|hypervisor/i.test(os) || /dell|hp|lenovo|supermicro/i.test(vendor)) return 'server';
  return 'host';
};

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
          nodeDimensionsIncludeLabels: false,
          fit: true,
          padding: 50,
          nodeRepulsion: 4500,
          idealEdgeLength: 65,
          edgeElasticity: 0.45,
          nestingFactor: 0.2,
          gravity: 0.5,
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
      const kind = deviceKind(n.data);
      return {
        ...n,
        data: {
          ...n.data,
          display_label: baseLabel,
          is_critical: isCritical,
          device_kind: kind,
          glyph: kind === 'service' ? '' : (GLYPHS[kind] || GLYPHS.host),
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
            'background-fill': 'radial-gradient',
            'background-gradient-stop-colors': '#1e293b #0f172a',
            'background-gradient-stop-positions': '0% 100%',
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
            'background-fill': 'radial-gradient',
            'background-gradient-stop-colors': '#34d399 #064e3b',
            'background-gradient-stop-positions': '0% 100%',
            'background-image': 'data(glyph)',
            'background-fit': 'contain',
            'background-width': '36px',
            'background-height': '36px',
            'background-position-x': '50%',
            'background-position-y': '42%',
            'border-width': 2,
            'border-color': '#34d399',
            'label': 'data(display_label)',
            'color': '#e2e8f0',
            'font-size': 10,
            'font-weight': 600,
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 6,
            'text-wrap': 'wrap',
            'text-max-width': '110px',
            'text-background-color': 'rgba(2, 6, 23, 0.85)',
            'text-background-opacity': 1,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'underlay-color': 'rgba(16, 185, 129, 0.45)',
            'underlay-opacity': 0.8,
            'underlay-padding': 8,
          },
        },
        // Critical Vulnerability Host Nodes (Red Glow)
        {
          selector: 'node[type="host"][?is_critical]',
          style: {
            'border-color': '#fb7185',
            'border-width': 2.5,
            'background-fill': 'radial-gradient',
            'background-gradient-stop-colors': '#fb7185 #7f1d1d',
            'background-gradient-stop-positions': '0% 100%',
            'underlay-color': '#f43f5e',
            'underlay-opacity': 0.9,
            'underlay-padding': 10,
          },
        },
        // Router / Gateway Nodes
        {
          selector: 'node[type="router"]',
          style: {
            'shape': 'hexagon',
            'width': 95,
            'height': 64,
            'background-fill': 'radial-gradient',
            'background-gradient-stop-colors': '#22d3ee #0e7490',
            'background-gradient-stop-positions': '0% 100%',
            'background-image': 'data(glyph)',
            'background-fit': 'contain',
            'background-width': '42px',
            'background-height': '42px',
            'background-position-x': '50%',
            'background-position-y': '42%',
            'border-width': 2,
            'border-color': '#22d3ee',
            'label': 'data(display_label)',
            'color': '#f0fdff',
            'font-size': 10,
            'font-weight': 'bold',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 6,
            'text-wrap': 'wrap',
            'text-background-color': 'rgba(2, 6, 23, 0.85)',
            'text-background-opacity': 1,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'underlay-color': 'rgba(6, 182, 212, 0.5)',
            'underlay-opacity': 0.6,
            'underlay-padding': 9,
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
            'background-fill': 'radial-gradient',
            'background-gradient-stop-colors': '#818cf8 #312e81',
            'background-gradient-stop-positions': '0% 100%',
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
        // Selected Node — brighter animated halo
        {
          selector: ':selected',
          style: {
            'border-color': '#67e8f9',
            'border-width': 3.5,
            'border-opacity': 1,
            'underlay-color': '#22d3ee',
            'underlay-opacity': 0.9,
            'underlay-padding': 12,
            'overlay-color': '#22d3ee',
            'overlay-opacity': 0.12,
            'overlay-padding': 6,
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
    <div className="relative w-full h-full overflow-hidden flex select-none ambient-substrate animate-topo-entrance">
      {/* Cytoscape Canvas */}
      <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Floating Canvas Controls & Layout Switcher */}
      <div className="absolute top-4 left-4 z-20 flex items-center gap-2 p-1.5 rounded-2xl glass-strong shadow-2xl border border-cyan-400/15 ring-1 ring-cyan-400/5">
        
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
      <div className="absolute bottom-4 left-4 z-20 p-3 rounded-2xl glass-strong text-[11px] text-slate-300 flex items-center gap-4 shadow-xl border border-cyan-400/10">
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-sm" style={{ background: 'linear-gradient(135deg,#1e293b,#0f172a)', border: '1px dashed #22d3ee' }} />
          <span>Subnet</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rotate-45" style={{ background: 'linear-gradient(135deg,#22d3ee,#0e7490)', border: '1px solid #67e8f9' }} />
          <span>Router</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-sm" style={{ background: 'linear-gradient(135deg,#34d399,#064e3b)', border: '1px solid #34d399' }} />
          <span>Secure Host</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-sm" style={{ background: 'linear-gradient(135deg,#fb7185,#7f1d1d)', border: '1px solid #fb7185', boxShadow: '0 0 6px rgba(244,63,94,0.6)' }} />
          <span>Vulnerable Host</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full" style={{ background: 'linear-gradient(135deg,#818cf8,#312e81)', border: '1px solid #818cf8' }} />
          <span>Service</span>
        </div>
      </div>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="absolute top-4 right-4 z-20 w-84 rounded-2xl glass-strong p-4 shadow-2xl animate-drawer-in border border-slate-700/80">
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
