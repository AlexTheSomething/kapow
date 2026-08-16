import React, { useState, useEffect, useCallback, useRef } from 'react';
import Header from './components/Header';
import Home from './components/Home';
import DataGrid from './components/DataGrid';
import ScanDiff from './components/ScanDiff';
import HostProfiler from './components/HostProfiler';
import ConsoleDrawer from './components/ConsoleDrawer';
import SuggestionPanel from './components/SuggestionPanel';
import StatusBar from './components/StatusBar';
import { Network, Table, GitCompare, Terminal, Sparkles, Settings, X } from 'lucide-react';

export default function App() {
  // ── Scan Form State ──
  const [target, setTarget] = useState('127.0.0.1');
  const [ports, setPorts] = useState('');
  const [scanProfile, setScanProfile] = useState('quick');
  const [requiresRoot, setRequiresRoot] = useState(false);
  const [scripts, setScripts] = useState('');

  // ── App State ──
  const [isScanning, setIsScanning] = useState(false);
  const [statusMessage, setStatusMessage] = useState('Ready');
  const [error, setError] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [selectedHost, setSelectedHost] = useState(null);    // drill-down host
  const [activeTab, setActiveTab] = useState('home');
  const [liveLogs, setLiveLogs] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);
  const [networkInterfaces, setNetworkInterfaces] = useState([]);
  const [monitoredPingIp, setMonitoredPingIp] = useState('127.0.0.1');
  const [passiveDevices, setPassiveDevices] = useState([]);
  const [suggestions, setSuggestions] = useState([]);
  const [showConsole, setShowConsole] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  const [dependencies, setDependencies] = useState({
    nmap: { installed: false, path: '' },
    rustscan: { installed: false, path: '' },
    masscan: { installed: false, path: '' },
    naabu: { installed: false, path: '' },
    is_elevated: false,
    platform: 'unknown',
  });

  const pollingRef = useRef(null);

  // ── IPC helper ──
  const getPyApi = useCallback(() => {
    if (window.pywebview && window.pywebview.api) return window.pywebview.api;
    return null;
  }, []);

  // ── Environment load ──
  const refreshEnvironment = useCallback(async () => {
    const api = getPyApi();
    if (!api) return;
    try {
      if (api.check_dependencies) {
        const deps = await api.check_dependencies();
        setDependencies(deps);
      }
      if (api.get_network_interfaces) {
        const ifaces = await api.get_network_interfaces();
        if (ifaces?.success) {
          setNetworkInterfaces(ifaces.interfaces || []);
          if (ifaces.primary?.cidr) setTarget(ifaces.primary.cidr);
        }
      }
      // Hydrate scan history
      if (api.list_scan_history && api.get_scan_history_item) {
        const listed = await api.list_scan_history(20);
        if (listed?.success && Array.isArray(listed.scans)) {
          const hydrated = [];
          for (const meta of listed.scans) {
            try {
              const full = await api.get_scan_history_item(meta.id);
              if (full?.success && full.scan) {
                hydrated.push({
                  id: meta.id,
                  target: meta.target,
                  scanProfile: meta.scan_profile,
                  timestamp: new Date((meta.created_at || 0) * 1000).toLocaleString(),
                  hostsCount: meta.hosts_count,
                  data: full.scan,
                  persisted: true,
                });
              }
            } catch (e) { /* skip */ }
          }
          if (hydrated.length) setScanHistory(hydrated);
        }
      }
      // Start passive device polling
      if (api.get_passive_discovered_devices) {
        const pollPassive = async () => {
          const res = await api.get_passive_discovered_devices();
          if (res?.success) setPassiveDevices(res.devices || []);
        };
        pollPassive();
        setInterval(pollPassive, 5000);
      }
    } catch (err) {
      console.error('Environment fetch failed:', err);
    }
  }, [getPyApi]);

  useEffect(() => {
    window.addEventListener('pywebviewready', refreshEnvironment);
    refreshEnvironment();
    return () => {
      window.removeEventListener('pywebviewready', refreshEnvironment);
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [refreshEnvironment]);

  // ── Start Scan ──
  const handleStartScan = async (customTarget = null) => {
    const scanTarget = (customTarget || target).trim();
    if (!scanTarget) return;
    setError(null);
    setIsScanning(true);
    setActiveTab('home');
    setShowConsole(true);
    setLiveLogs([`[*] Initializing ${scanProfile} scan against ${scanTarget}...`]);
    setStatusMessage(`Scanning ${scanTarget}...`);

    const api = getPyApi();
    if (pollingRef.current) clearInterval(pollingRef.current);
    pollingRef.current = setInterval(async () => {
      const a = getPyApi();
      if (a?.get_live_state) {
        try {
          const state = await a.get_live_state();
          if (state?.logs?.length) setLiveLogs(state.logs);
          if (state?.status) setStatusMessage(state.status);
        } catch (_) {}
      }
    }, 600);

    if (api?.start_scan) {
      try {
        const result = await api.start_scan(scanTarget, ports, requiresRoot, scanProfile, scripts);
        if (pollingRef.current) clearInterval(pollingRef.current);
        if (result.success) {
          setScanData(result);
          if (result.logs) setLiveLogs(result.logs);
          const hostCount = result.data?.hosts?.length || 0;
          setStatusMessage(`Scan complete: ${hostCount} host(s) discovered.`);
          setError(null);

          // Local history fallback
          setScanHistory((prev) => [{
            id: Date.now(),
            target: scanTarget,
            scanProfile,
            timestamp: new Date().toLocaleTimeString(),
            hostsCount: hostCount,
            data: result,
          }, ...prev.slice(0, 9)]);

          // Load tag suggestions
          if (api.suggest_tags) {
            const sug = await api.suggest_tags(result);
            if (sug?.success && sug.count > 0) {
              setSuggestions(sug.suggestions);
            }
          }
        } else {
          setError(result.error || 'Scan failed.');
          if (result.logs) setLiveLogs(result.logs);
          setStatusMessage('Scan terminated with errors.');
        }
      } catch (err) {
        if (pollingRef.current) clearInterval(pollingRef.current);
        setError(`Scan error: ${err.message || err}`);
        setStatusMessage('Scan failed.');
      } finally {
        setIsScanning(false);
      }
    }
  };

  const handleCancelScan = async () => {
    if (pollingRef.current) clearInterval(pollingRef.current);
    const api = getPyApi();
    if (api?.cancel_scan) await api.cancel_scan();
    setIsScanning(false);
  };

  const handleLoadSample = async () => {
    setError(null);
    const api = getPyApi();
    if (api?.load_sample_scan) {
      const sample = await api.load_sample_scan();
      setScanData(sample);
      if (sample.logs) setLiveLogs(sample.logs);
      setStatusMessage('Sample network loaded.');
    }
  };

  // ── Asset / Protocol / Telemetry ──
  const handleSaveAsset = async (assetData) => {
    const api = getPyApi();
    if (api?.save_asset_metadata) {
      try {
        return await api.save_asset_metadata(assetData);
      } catch (e) { return { success: false, error: String(e) }; }
    }
    return { success: true };
  };

  const handleLaunchProtocol = async (protocol, ip, port = null) => {
    const api = getPyApi();
    if (api?.launch_remote_tool) {
      try { return await api.launch_remote_tool(protocol, ip, port); } catch (_) {}
    }
  };

  const handlePingTelemetry = async (ip) => {
    const api = getPyApi();
    if (api?.ping_host_telemetry) {
      try { return await api.ping_host_telemetry(ip); } catch (_) {}
    }
  };

  const handleCompareScans = async (scanA, scanB) => {
    const api = getPyApi();
    if (api?.compare_scan_snapshots) {
      try { return await api.compare_scan_snapshots(scanA, scanB); } catch (_) {}
    }
    return null;
  };

  const handleExport = async (format) => {
    if (!scanData) return;
    const api = getPyApi();
    if (api?.export_results) {
      const exp = await api.export_results(scanData, format);
      if (exp.success) {
        const blob = new Blob([exp.content], {
          type: format === 'json' ? 'application/json' : format === 'xml' ? 'text/xml' : 'text/csv'
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = exp.filename || `scan.${format}`; a.click();
        URL.revokeObjectURL(url);
      }
    }
  };

  // ── Suggestion handlers ──
  const handleAcceptSuggestion = async (s) => {
    // Fetch current host tags, add the accepted one, save
    setSuggestions((prev) => prev.filter((x) => x !== s));
    await handleSaveAsset({ ip: s.ip, tags: [s.tag], risk_level: 'LOW' });
  };

  const handleDismissAllSuggestions = () => setSuggestions([]);

  // ── Render helpers ──
  const hostsList = scanData?.data?.hosts || [];

  const TABS = [
    { id: 'home', label: 'Home', icon: Network, badge: hostsList.length || null },
    { id: 'grid', label: 'Inventory', icon: Table, badge: scanData?.ag_grid?.length || null },
    { id: 'diff', label: 'Changes', icon: GitCompare },
  ];

  // If a host is selected for drill-down, show the profiler instead of tabs
  if (selectedHost) {
    return (
      <div className="flex flex-col h-screen w-screen bg-dark-950 text-slate-100 overflow-hidden select-none">
        <HostProfiler
          host={selectedHost}
          scanData={scanData}
          onBack={() => setSelectedHost(null)}
          onSaveAsset={handleSaveAsset}
          onLaunchProtocol={handleLaunchProtocol}
          onPingTelemetry={handlePingTelemetry}
        />
        <ConsoleDrawer
          logs={liveLogs}
          isScanning={isScanning}
          isOpen={showConsole}
          onToggle={() => setShowConsole(!showConsole)}
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen w-screen bg-dark-950 text-slate-100 overflow-hidden select-none">
      {/* ── Header ── */}
      <Header
        dependencies={dependencies}
        onLoadSample={handleLoadSample}
        onExport={handleExport}
        isScanning={isScanning}
        onRefreshDeps={refreshEnvironment}
        scanData={scanData}
      />

      {/* ── Tab Bar ── */}
      <div className="px-6 border-b border-slate-800 bg-dark-950/90 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-1">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3 text-xs font-bold border-b-2 transition-all ${
                activeTab === tab.id
                  ? 'border-brand-cyan text-brand-cyan bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              <span className="hidden sm:inline">{tab.label}</span>
              {tab.badge ? (
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-mono">
                  {tab.badge}
                </span>
              ) : null}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          {/* Settings */}
          <button
            onClick={() => setShowSettings(!showSettings)}
            className={`p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-all ${showSettings ? 'bg-slate-800 text-white' : ''}`}
          >
            <Settings className="w-4 h-4" />
          </button>
          {/* Toggle console */}
          <button
            onClick={() => setShowConsole(!showConsole)}
            className={`p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-all ${showConsole ? 'bg-slate-800 text-cyan-400' : ''}`}
          >
            <Terminal className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* ── Main Content ── */}
      <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
        {/* Tab content + suggestion panel */}
        <div className="flex-1 flex min-h-0 overflow-hidden">
          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
            <div className="flex-1 min-h-0 overflow-hidden">
              {activeTab === 'home' && (
                <Home
                  target={target}
                  setTarget={setTarget}
                  scanProfile={scanProfile}
                  setScanProfile={setScanProfile}
                  isScanning={isScanning}
                  onStartScan={handleStartScan}
                  onCancelScan={handleCancelScan}
                  networkInterfaces={networkInterfaces}
                  scanData={scanData}
                  scanHistory={scanHistory}
                  passiveDevices={passiveDevices}
                  suggestionCount={suggestions.filter((s) => s.color !== 'slate').length}
                  onOpenSuggestions={() => setShowSuggestions(true)}
                  onSelectHost={(hostData) => {
                    // Map topology click to full host data
                    const ip = hostData?.data?.ip || hostData?.ip || '';
                    const found = hostsList.find((h) => h.ip === ip || h.ipv4 === ip);
                    setSelectedHost(found || hostData);
                  }}
                  onScanLan={(cidr) => handleStartScan(cidr)}
                />
              )}

              {activeTab === 'grid' && (
                <DataGrid
                  rowData={scanData?.ag_grid || []}
                  onSelectHost={(row) => {
                    const ip = row?.data?.ip || row?.ip || '';
                    const found = hostsList.find((h) => h.ip === ip || h.ipv4 === ip);
                    if (found) setSelectedHost(found);
                  }}
                />
              )}

              {activeTab === 'diff' && (
                <ScanDiff
                  scanHistory={scanHistory}
                  currentScan={scanData}
                  onCompareScans={handleCompareScans}
                />
              )}
            </div>

            {/* Error banner */}
            {error && (
              <div className="mx-4 mb-1 p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 flex items-center justify-between animate-slide-up">
                <span>{error}</span>
                <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200"><X className="w-3.5 h-3.5" /></button>
              </div>
            )}

            {/* Status bar */}
            <StatusBar
              isScanning={isScanning}
              statusMessage={statusMessage}
              error={error}
              scanData={scanData}
            />
          </div>

          {/* Suggestion side panel */}
          {showSuggestions && (
            <div className="w-80 border-l border-slate-800 bg-dark-900 flex flex-col animate-slide-right overflow-hidden shrink-0">
              <SuggestionPanel
                suggestions={suggestions}
                onAccept={handleAcceptSuggestion}
                onDismissAll={handleDismissAllSuggestions}
                onClose={() => setShowSuggestions(false)}
              />
            </div>
          )}
        </div>

        {/* Console drawer (docked bottom) */}
        <ConsoleDrawer
          logs={liveLogs}
          isScanning={isScanning}
          isOpen={showConsole}
          onToggle={() => setShowConsole(!showConsole)}
        />
      </div>
    </div>
  );
}