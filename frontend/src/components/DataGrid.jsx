import React, { useMemo, useState, useRef, useCallback } from 'react';
import { AgGridReact } from 'ag-grid-react';
import { Search, Copy, Check, ExternalLink, ShieldCheck, Laptop, Server, Router as RouterIcon, ShieldAlert, Tag, Filter, Sparkles, X } from 'lucide-react';
import TagChip from './TagChip';

const QUICK_FILTERS = [
  { id: 'all', label: 'All records', icon: Filter },
  { id: 'tagged', label: 'Has tags', icon: Tag },
  { id: 'cves', label: 'Has CVEs', icon: ShieldAlert },
  { id: 'critical', label: 'Critical only', icon: Sparkles },
  { id: 'needs_update', label: '"needs update" tag', icon: ShieldAlert },
];

export default function DataGrid({ rowData, onSelectHost }) {
  const gridRef = useRef(null);
  const [quickFilterText, setQuickFilterText] = useState('');
  const [activeFilter, setActiveFilter] = useState('all');
  const [copiedId, setCopiedId] = useState(null);

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  // Filter the data client-side based on the selected preset
  const filteredData = useMemo(() => {
    if (!rowData || activeFilter === 'all') return rowData || [];
    return rowData.filter((r) => {
      switch (activeFilter) {
        case 'tagged':
          return (r.tags || []).length > 0;
        case 'cves':
          return (r.cves || []).length > 0;
        case 'critical':
          return r.severity === 'CRITICAL' || (r.max_cvss || 0) >= 9.0;
        case 'needs_update':
          return (r.tags || []).includes('needs update');
        default:
          return true;
      }
    });
  }, [rowData, activeFilter]);

  // ── Cell Renderers ──

  const IpCellRenderer = useCallback((params) => {
    const ip = params.value;
    const isCopied = copiedId === `ip-${ip}-${params.node.id}`;
    const alias = params.data.alias;
    const hostTags = params.data.tags || [];

    return (
      <div className="flex items-center gap-1.5 w-full min-w-0 group">
        <span className="font-mono text-xs font-bold text-cyan-300 shrink-0">{ip}</span>
        {alias && (
          <span className="text-[10px] font-sans px-1.5 py-0.1 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 truncate">
            {alias}
          </span>
        )}
        {hostTags.slice(0, 2).map((t) => (
          <TagChip key={t} tag={t} color={t === 'needs update' ? 'amber' : t === 'new device' ? 'emerald' : t === 'exposed file share' ? 'rose' : 'slate'} small />
        ))}
        {hostTags.length > 2 && (
          <span className="text-[9px] text-slate-500 font-sans">+{hostTags.length - 2}</span>
        )}
        <button
          onClick={(e) => { e.stopPropagation(); handleCopy(ip, `ip-${ip}-${params.node.id}`); }}
          className="ml-auto opacity-0 group-hover:opacity-100 p-0.5 hover:text-white transition-opacity shrink-0"
          title="Copy IP"
        >
          {isCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-slate-500" />}
        </button>
      </div>
    );
  }, [copiedId]);

  const StatusCellRenderer = useCallback((params) => {
    const state = (params.value || '').toLowerCase();
    const isOpen = state === 'open' || state === 'up';
    const isFiltered = state === 'filtered';
    return (
      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${
        isOpen ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' :
        isFiltered ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' :
        'bg-rose-500/15 text-rose-400 border border-rose-500/30'
      }`}>
        <span className={`w-1.5 h-1.5 rounded-full ${isOpen ? 'bg-emerald-400' : isFiltered ? 'bg-amber-400' : 'bg-rose-400'}`} />
        {params.value || 'unknown'}
      </span>
    );
  }, []);

  const CveCellRenderer = useCallback((params) => {
    const cves = params.data.cves || [];
    const severity = params.data.severity;
    const maxCvss = params.data.max_cvss;
    if (!cves || cves.length === 0) return <span className="text-[10px] text-slate-500 font-mono">Clean</span>;
    const isCritical = severity === 'CRITICAL' || maxCvss >= 9.0;
    return (
      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
        isCritical ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' :
        'bg-amber-500/20 text-amber-400 border border-amber-500/40'
      }`} title={`${cves.length} CVEs: ${cves.map((c) => c.cve_id).join(', ')}`}>
        <ShieldAlert className="w-3 h-3" />
        {severity || 'VULN'} {maxCvss ? `(${maxCvss})` : ''}
      </span>
    );
  }, []);

  const PortCellRenderer = useCallback((params) => {
    const port = params.data.port;
    const protocol = params.data.protocol || 'tcp';
    if (!port) return <span className="text-slate-500 text-xs">—</span>;
    const isHttp = port === 80 || port === 443 || port === 8080 || port === 8443;
    const isSsh = port === 22;
    const isRdp = port === 3389;
    const color = isHttp ? 'text-cyan-400' : isSsh ? 'text-indigo-400' : isRdp ? 'text-violet-400' : 'text-indigo-300';
    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded-md font-mono text-[11px] bg-slate-800 border border-slate-700 ${color}`}>
        {port}/{protocol.toUpperCase()}
      </span>
    );
  }, []);

  const OsCellRenderer = useCallback((params) => {
    const os = params.value || params.data.os_name || '';
    if (!os) return <span className="text-slate-500 text-xs">—</span>;
    let Icon = Laptop;
    const lower = os.toLowerCase();
    if (lower.includes('router') || lower.includes('openwrt') || lower.includes('cisco')) Icon = RouterIcon;
    else if (lower.includes('server') || lower.includes('linux') || lower.includes('bsd')) Icon = Server;
    return (
      <div className="flex items-center gap-1.5 text-[11px] text-slate-300 truncate" title={os}>
        <Icon className="w-3 h-3 text-slate-400 shrink-0" />
        <span className="truncate">{os}</span>
      </div>
    );
  }, []);

  const ActionCellRenderer = useCallback((params) => (
    <button
      onClick={(e) => { e.stopPropagation(); onSelectHost(params.data); }}
      className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-[10px] font-semibold transition-all"
      title="Inspect host — drill into full profile"
    >
      Inspect
      <ExternalLink className="w-3 h-3" />
    </button>
  ), [onSelectHost]);

  // ── Column Definitions ──
  const columnDefs = useMemo(() => [
    {
      field: 'ip',
      headerName: 'IP / Tags',
      cellRenderer: IpCellRenderer,
      minWidth: 220,
      filter: 'agTextColumnFilter',
      pinned: 'left',
      // Show tag chips inline
      cellClass: 'flex items-center',
    },
    {
      field: 'hostname',
      headerName: 'Hostname',
      minWidth: 140,
      filter: 'agTextColumnFilter',
      valueFormatter: (p) => p.value || '—',
    },
    {
      headerName: 'CVEs',
      cellRenderer: CveCellRenderer,
      width: 115,
      sortable: true,
      comparator: (a, b, nodeA, nodeB) => (nodeA.data.max_cvss || 0) - (nodeB.data.max_cvss || 0),
    },
    {
      field: 'port',
      headerName: 'Port',
      cellRenderer: PortCellRenderer,
      width: 105,
      filter: 'agNumberColumnFilter',
    },
    {
      field: 'port_state',
      headerName: 'State',
      cellRenderer: StatusCellRenderer,
      width: 95,
      filter: 'agTextColumnFilter',
    },
    {
      field: 'service',
      headerName: 'Service',
      minWidth: 100,
      filter: 'agTextColumnFilter',
      cellClass: 'font-mono text-xs text-emerald-400',
    },
    {
      field: 'product',
      headerName: 'Product / Version',
      minWidth: 150,
      filter: 'agTextColumnFilter',
      valueGetter: (p) => {
        const prod = p.data.product || '';
        const ver = p.data.version || '';
        return ver ? `${prod} ${ver}` : prod || '—';
      },
    },
    {
      field: 'os_name',
      headerName: 'OS',
      cellRenderer: OsCellRenderer,
      minWidth: 160,
      filter: 'agTextColumnFilter',
    },
    {
      headerName: 'Actions',
      cellRenderer: ActionCellRenderer,
      width: 90,
      sortable: false,
      filter: false,
      pinned: 'right',
    },
  ], [IpCellRenderer, CveCellRenderer, StatusCellRenderer, PortCellRenderer, OsCellRenderer, ActionCellRenderer]);

  const defaultColDef = useMemo(() => ({
    sortable: true,
    filter: true,
    resizable: true,
    floatingFilter: false,
  }), []);

  // Group rows by IP — same-IP rows share a subtle background tint
  const ipGroups = useMemo(() => {
    const seen = [];
    return (rowData || []).reduce((acc, row) => {
      const ip = row.ip || '';
      if (!acc[ip]) {
        seen.push(ip);
        acc[ip] = seen.length % 2 === 0;
      }
      return acc;
    }, {});
  }, [rowData]);

  const getRowStyle = useCallback((params) => {
    const ip = params.data?.ip || '';
    const alt = ipGroups[ip];
    return alt ? { background: 'rgba(15, 23, 42, 0.4)' } : null;
  }, [ipGroups]);

  return (
    <div className="flex flex-col h-full bg-dark-900 overflow-hidden">
      {/* Filter bar */}
      <div className="p-3 border-b border-slate-800 bg-dark-950/90 flex items-center justify-between gap-3 shrink-0 flex-wrap">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-brand-cyan" />
          <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">Inventory</span>
          <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
            {filteredData.length} records
          </span>
        </div>

        {/* Quick filter chips */}
        <div className="flex items-center gap-1.5">
          {QUICK_FILTERS.map((f) => (
            <button
              key={f.id}
              onClick={() => setActiveFilter(activeFilter === f.id ? 'all' : f.id)}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold transition-all ${
                activeFilter === f.id
                  ? 'bg-brand-cyan text-slate-950 shadow-glow-cyan'
                  : 'bg-slate-800 text-slate-400 border border-slate-700 hover:text-slate-200 hover:border-slate-600'
              }`}
            >
              <f.icon className="w-3 h-3" />
              {f.label}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative w-64">
          <Search className="w-3 h-3 text-slate-400 absolute left-2.5 top-2" />
          <input
            type="text"
            placeholder="Search..."
            value={quickFilterText}
            onChange={(e) => setQuickFilterText(e.target.value)}
            className="w-full bg-dark-900 border border-slate-700 focus:border-brand-cyan rounded-lg pl-8 pr-7 py-1.5 text-[11px] text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-brand-cyan transition-all"
          />
          {quickFilterText && (
            <button onClick={() => setQuickFilterText('')} className="absolute right-2 top-2 text-slate-400 hover:text-white">
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Grid */}
      <div className="ag-theme-quartz-dark flex-1 w-full h-full">
        <AgGridReact
          ref={gridRef}
          rowData={filteredData}
          columnDefs={columnDefs}
          defaultColDef={defaultColDef}
          quickFilterText={quickFilterText}
          pagination={true}
          paginationPageSize={50}
          paginationPageSizeSelector={[25, 50, 100]}
          rowSelection="single"
          onRowDoubleClicked={(params) => onSelectHost(params.data)}
          getRowStyle={getRowStyle}
          animateRows={true}
        />
      </div>
    </div>
  );
}