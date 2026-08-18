import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';

// Minimal, robust topology: solid-color nodes by type, plain edges,
// basic layout. No gradients / glyphs / animations — those are layered
// back on once this baseline is confirmed rendering.
const COLOR = {
  subnet: '#0e7490',
  router: '#06b6d4',
  host: '#10b981',
  service: '#6366f1',
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
            width: 72,
            height: 52,
            'background-color': (ele) => COLOR[ele.data('type')] || '#475569',
            'border-width': 2,
            'border-color': '#0b0f19',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.5,
            'line-color': '#475569',
            'target-arrow-color': '#06b6d4',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
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

  return <div ref={containerRef} className="w-full h-full" />;
}
