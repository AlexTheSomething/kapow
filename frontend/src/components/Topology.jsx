import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';

// Step 1 of premium layering: gradient-filled nodes by type + ambient glass
// substrate. No glyphs / rAF flow animation yet (those come after this
// renders reliably). Robust: plain solid fallbacks if gradient props ignored.

const GRAD = {
  subnet: ['#0e7490', '#0b1220'],
  router: ['#0891b2', '#082f49'],
  host: ['#1e293b', '#0f1b2e'],
  service: ['#3730a3', '#1e1b4b'],
};

export default function Topology({ elements, onSelectHost }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return undefined;
    const cy = cytoscape({
      container: containerRef.current,
      elements: elements || { nodes: [], edges: [] },
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            color: '#e2e8f0',
            'font-size': 10,
            'font-family': 'Inter, sans-serif',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '90px',
            width: 76,
            height: 54,
            shape: 'round-rectangle',
            'background-color': (ele) => (GRAD[ele.data('type')] || ['#475569', '#334155'])[0],
            'background-fill': 'linear-gradient',
            'background-gradient-stop-colors': (ele) => (GRAD[ele.data('type')] || ['#475569', '#334155']).join(' '),
            'background-gradient-stop-positions': '0 100',
            'background-gradient-direction': 'to-bottom',
            'border-width': 2,
            'border-color': '#0b0f19',
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
  }, [elements, onSelectHost]);

  return (
    <div className="relative w-full h-full bg-dark-950 overflow-hidden">
      {/* Ambient glass substrate */}
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
