import React, { useMemo, useState, useRef, useCallback } from 'react';
import { AgGridReact } from 'ag-grid-react';
import { Search, Copy, Check, ExternalLink, ShieldCheck, Laptop, Server, Router as RouterIcon, ShieldAlert, Tag } from 'lucide-react';

export default function DataGrid({ rowData, onSelectHost }) {
  const gridRef = useRef(null);
  const [quickFilterText, setQuickFilterText] = useState('');
  const [copiedId, setCopiedId] = useState(null);

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  // Custom Cell Renderers
  const IpCellRenderer = useCallback((params) => {
    const ip = params.value;
    const isCopied = copiedId === `ip-${ip}-${params.node.id}`;
    const alias = params.data.alias;

    return (
      <div className="flex items-center justify-between w-full font-mono text-cyan-300 font-semibold group">
        <div className="flex items-center gap-1.5 truncate">
          <span>{ip}</span>
          {alias && (
            <span className="text-[10px] font-sans px-1.5 py-0.2 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 truncate">
              {alias}
            </span>
          )}
        </div>
        <button
          onClick={(e) => {
            e.stopPropagation();
            handleCopy(ip, `ip-${ip}-${params.node.id}`);
          }}
          className="opacity-0 group-hover:opacity-100 p-1 hover:text-white transition-opacity shrink-0"
          title="Copy IP"
        >
          {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
        </button>
      </div>
    );
  }, [copiedId]);

  const StatusCellRenderer = useCallback((params) => {
    const state = (params.value || '').toLowerCase();
    const isOpen = state === 'open' || state === 'up';
    const isFiltered = state === 'filtered';

    return (
      <div className="flex items-center">
        <span
          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider ${
            isOpen
              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
              : isFiltered
              ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
              : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
          }`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${isOpen ? 'bg-emerald-400' : isFiltered ? 'bg-amber-400' : 'bg-rose-400'}`} />
          {params.value || 'unknown'}
        </span>
      </div>
    );
  }, []);

  const CveCellRenderer = useCallback((params) => {
    const cves = params.data.cves || [];
    const severity = params.data.severity;
    const maxCvss = params.data.max_cvss;

    if (!cves || cves.length === 0) {
      return (
        <span className="text-[11px] text-slate-500 font-mono">
          Clean
        </span>
      );
    }

    const isCritical = severity === 'CRITICAL' || maxCvss >= 9.0;

    return (
      <div className="flex items-center gap-1.5">
        <span
          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
            isCritical
              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
              : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
          }`}
          title={`${cves.length} CVEs: ${cves.map((c) => c.cve_id).join(', ')}`}
        >
          <ShieldAlert className="w-3 h-3" />
          <span>{severity || 'VULN'} {maxCvss ? `(${maxCvss})` : ''}</span>
        </span>
      </div>
    );
  }, []);

  const PortCellRenderer = useCallback((params) => {
    const port = params.data.port;
    const protocol = params.data.protocol || 'tcp';
    if (!port) return <span className="text-slate-500">—</span>;

    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded-md font-mono text-xs bg-slate-800 border border-slate-700 text-indigo-300">
        {port} / {protocol.toUpperCase()}
      </span>
    );
  }, []);

  const OsCellRenderer = useCallback((params) => {
    const os = params.value || params.data.os_name || '';
    if (!os) return <span className="text-slate-500">—</span>;

    let Icon = Laptop;
    const lower = os.toLowerCase();
    if (lower.includes('router') || lower.includes('openwrt') || lower.includes('cisco')) {
      Icon = RouterIcon;
    } else if (lower.includes('server') || lower.includes('linux') || lower.includes('bsd')) {
      Icon = Server;
    }

    return (
      <div className="flex items-center gap-1.5 text-xs text-slate-300 truncate" title={os}>
        <Icon className="w-3.5 h-3.5 text-slate-400 shrink-0" />
        <span className="truncate">{os}</span>
      </div>
    );
  }, []);

  const ActionCellRenderer = useCallback((params) => {
    return (
      <button
        onClick={(e) => {
          e.stopPropagation();
          onSelectHost(params.data);
        }}
        className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-semibold transition-all"
        title="Inspect host details and edit metadata"
      >
        <span>Inspect</span>
        <ExternalLink className="w-3 h-3" />
      </button>
    );
  }, [onSelectHost]);

  // Column Definitions
  const columnDefs = useMemo(() => [
    {
      field: 'ip',
      headerName: 'IP / Device Alias',
      cellRenderer: IpCellRenderer,
      minWidth: 180,
      filter: 'agTextColumnFilter',
      pinned: 'left',
    },
    {
      field: 'hostname',
      headerName: 'Hostname',
      minWidth: 150,
      filter: 'agTextColumnFilter',
      valueFormatter: (p) => p.value || '—',
    },
    {
      headerName: 'Vulnerability (CVE)',
      cellRenderer: CveCellRenderer,
      width: 140,
      sortable: true,
      comparator: (a, b, nodeA, nodeB) => {
        const valA = nodeA.data.max_cvss || 0;
        const valB = nodeB.data.max_cvss || 0;
        return valA - valB;
      },
    },
    {
      field: 'port',
      headerName: 'Port / Proto',
      cellRenderer: PortCellRenderer,
      width: 120,
      filter: 'agNumberColumnFilter',
    },
    {
      field: 'port_state',
      headerName: 'Port State',
      cellRenderer: StatusCellRenderer,
      width: 120,
      filter: 'agTextColumnFilter',
    },
    {
      field: 'service',
      headerName: 'Service',
      minWidth: 120,
      filter: 'agTextColumnFilter',
      cellClass: 'font-mono text-xs text-emerald-400',
    },
    {
      field: 'product',
      headerName: 'Product / Software',
      minWidth: 160,
      filter: 'agTextColumnFilter',
      valueGetter: (p) => {
        const prod = p.data.product || '';
        const ver = p.data.version || '';
        return ver ? `${prod} ${ver}` : prod || '—';
      },
    },
    {
      field: 'os_name',
      headerName: 'Operating System',
      cellRenderer: OsCellRenderer,
      minWidth: 180,
      filter: 'agTextColumnFilter',
    },
    {
      field: 'banner',
      headerName: 'Banner / Title',
      minWidth: 180,
      flex: 1,
      filter: 'agTextColumnFilter',
      valueFormatter: (p) => p.value || '—',
      cellClass: 'text-xs text-slate-400 truncate',
    },
    {
      headerName: 'Actions',
      cellRenderer: ActionCellRenderer,
      width: 105,
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

  return (
    <div className="flex flex-col h-full bg-dark-900 overflow-hidden">
      {/* Table Header Filter Bar */}
      <div className="p-3 border-b border-slate-800 bg-dark-950/80 flex items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-brand-cyan" />
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Asset Inventory & CVE Audit
          </span>
          <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
            {rowData?.length || 0} records
          </span>
        </div>

        {/* Global Search Bar */}
        <div className="relative w-80">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search assets, ports, software, CVEs..."
            value={quickFilterText}
            onChange={(e) => setQuickFilterText(e.target.value)}
            className="w-full bg-dark-900 border border-slate-700 focus:border-brand-cyan rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-brand-cyan transition-all"
          />
          {quickFilterText && (
            <button
              onClick={() => setQuickFilterText('')}
              className="absolute right-2.5 top-1.5 text-xs text-slate-400 hover:text-white"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      {/* AG Grid Canvas */}
      <div className="ag-theme-quartz-dark flex-1 w-full h-full">
        <AgGridReact
          ref={gridRef}
          rowData={rowData}
          columnDefs={columnDefs}
          defaultColDef={defaultColDef}
          quickFilterText={quickFilterText}
          pagination={true}
          paginationPageSize={50}
          paginationPageSizeSelector={[25, 50, 100]}
          rowSelection="single"
          onRowDoubleClicked={(params) => onSelectHost(params.data)}
          animateRows={true}
        />
      </div>
    </div>
  );
}
