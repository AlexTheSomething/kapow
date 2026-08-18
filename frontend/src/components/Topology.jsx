import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';

// Step 2 (final): device type shown as a clean letter badge prefixed into the
// node label (e.g. "[R] gateway"). cytoscape background-image data-URIs clip/
// garble in this environment, so we use text — 100% reliable, no clipping.

const GRAD = {
  subnet: ['#0e7490', '#0b1220'],
  router: ['#0891b2', '#082f49'],
  host: ['#1e293b', '#0f1b2e'],
  service: ['#3730a3', '#1e1b4b'],
};

const BADGE = { subnet: 'N', router: 'R', host: 'H', service: 'S' };

export default function Topology({ elements, onSelectHost }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  // Prefix the type badge letter into the visible label (truncated to fit).
  const decorated = (() => {
    if (!elements || !elements.nodes) return elements;
    return {
      ...elements,
      nodes: elements.nodes.map((n) => {
        const raw = n.data.label || n.data.ip || '';
        const name = raw.length > 16 ? `${raw.slice(0, 15)}…` : raw;
        return {
          ...n,
          data: { ...n.data, label: `${BADGE[n.data.type] || '?'}\u2002${name}` },
        };
      }),
    };
  })();

  useEffect(() => {
    if (!containerRef.current) return undefined;
    const cy = cytoscape({
      container: containerRef.current,
      elements: decorated || { nodes: [], edges: [] },
      style: [
        {
          selector: 'node',
          style: {
            'background-color': (ele) => (GRAD[ele.data('type')] || ['#475569', '#334155'])[0],
            'background-fill': 'linear-gradient',
            'background-gradient-stop-colors': (ele) => (GRAD[ele.data('type')] || ['#475569', '#334155']).join(' '),
            'background-gradient-stop-positions': '0 100',
            'background-gradient-direction': 'to-bottom',
            shape: 'round-rectangle',
            width: 104,
            height: 64,
            'border-width': 2,
            'border-color': '#0b0f19',
            label: 'data(label)',
            color: '#cbd5e1',
            'font-size': 9.5,
            'font-weight': 500,
            'font-family': 'Inter, sans-serif',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '92px',
            'text-outline-width': 2,
            'text-outline-color': '#04060d',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.6,
            'line-color': 'rgba(71, 85, 105, 0.7)',
            'target-arrow-color': '#06b6d4',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'line-dash-pattern': [6, 8],
          },
        },
      ],
      layout: { name: 'cose', animate: false, fit: true, padding: 50 },
    });
    cyRef.current = cy;
    if (onSelectHost) {
      cy.on('tap', 'node', (evt) => onSelectHost(evt.target.data()));
    }
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [decorated, onSelectHost]);

  return (
    <div className="relative w-full h-full bg-dark-950 overflow-hidden">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(circle at 30% 20%, rgba(6,182,212,0.10), transparent 55%), radial-gradient(circle at 78% 75%, rgba(99,102,241,0.12), transparent 55%), radial-gradient(circle at 50% 50%, #070a13 0%, #04060d 100%)',
        }}
      />
      <div ref={containerRef} className="absolute inset-0" />
    </div>
  );
}
