import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';

// Step 2 of premium layering: device glyphs on nodes (SVG data-URI backgrounds).
// Gradient + ambient substrate from step 1 retained. Glyph is applied via a
// data-mapper on nodes that have a non-empty glyph_url; others stay glyph-less.

const GRAD = {
  subnet: ['#0e7490', '#0b1220'],
  router: ['#0891b2', '#082f49'],
  host: ['#1e293b', '#0f1b2e'],
  service: ['#3730a3', '#1e1b4b'],
};

const glyph = (path, color = '#e2e8f0') =>
  `data:image/svg+xml;utf8,${encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="${path}"/></svg>`
  )}`;

const GLYPHS = {
  router: glyph('M3 13h2l2 4h6l2-4h2a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2H3a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2z'),
  host: glyph('M4 5h16v10H4z M2 19h20 M9 19v-4 M15 19v-4'),
  service: glyph('M12 2v4 M12 18v4 M2 12h4 M18 12h4 M5 5l3 3 M16 16l3 3 M19 5l-3 3 M8 16l-3 3'),
  subnet: glyph('M12 2 2 7l10 5 10-5z M2 17l10 5 10-5 M2 12l10 5 10-5'),
};

const glyphFor = (type) => GLYPHS[type] || '';

export default function Topology({ elements, onSelectHost }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return undefined;
    const cy = cytoscape({
      container: containerRef.current,
      elements: decorated || { nodes: [], edges: [] },
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
          selector: 'node[glyph_url != ""]',
          style: {
            'background-image': 'data(glyph_url)',
            'background-fit': 'none',
            'background-width': '24px',
            'background-height': '24px',
            'background-position-x': '50%',
            'background-position-y': '22%',
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

  // Attach glyph_url to incoming elements (sample already has typed nodes).
  const decorated = (() => {
    if (!elements || !elements.nodes) return elements;
    return {
      ...elements,
      nodes: elements.nodes.map((n) => ({
        ...n,
        data: { ...n.data, glyph_url: n.data.glyph_url || glyphFor(n.data.type) },
      })),
    };
  })();

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
