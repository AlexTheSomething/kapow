import React, { useState, useEffect, useCallback, useRef } from 'react';
import Header from './components/Header';
import ScanControls from './components/ScanControls';
import DataGrid from './components/DataGrid';
import Topology from './components/Topology';
import LiveConsole from './components/LiveConsole';
import HostProfiler from './components/HostProfiler';
import ScanDiff from './components/ScanDiff';
import LatencyMonitor from './components/LatencyMonitor';
import PassiveSniffer from './components/PassiveSniffer';
import HostDetailModal from './components/HostDetailModal';
import StatusBar from './components/StatusBar';
import { Table, Network, Terminal, Code, Server, Sparkles, GitCompare, History, Activity, Radio } from 'lucide-react';

export default function App() {
  // Scan Form State
  const [target, setTarget] = useState('127.0.0.1');
  const [ports, setPorts] = useState('');
  const [scanProfile, setScanProfile] = useState('quick');
  const [requiresRoot, setRequiresRoot] = useState(false);
  const [scripts, setScripts] = useState('');

  // Application State
  const [isScanning, setIsScanning] = useState(false);
  const [statusMessage, setStatusMessage] = useState('Ready');
  const [error, setError] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [selectedHost, setSelectedHost] = useState(null);
  const [activeTab, setActiveTab] = useState('topology'); // 'topology' | 'grid' | 'profiler' | 'diff' | 'telemetry' | 'sniffer' | 'console' | 'raw_xml'
  const [liveLogs, setLiveLogs] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);
  const [networkInterfaces, setNetworkInterfaces] = useState([]);
  const [monitoredPingIp, setMonitoredPingIp] = useState('127.0.0.1');

  const [dependencies, setDependencies] = useState({
    nmap: { installed: false, path: '' },
    rustscan: { installed: false, path: '' },
    is_elevated: false,
    platform: 'unknown',
  });

  const pollingRef = useRef(null);

  // Helper to safely access PyWebView bridge
  const getPyApi = useCallback(() => {
    if (window.pywebview && window.pywebview.api) {
      return window.pywebview.api;
    }
    return null;
  }, []);

  // Fetch CLI Dependencies and Network Interfaces on Mount
  const refreshEnvironment = useCallback(async () => {
    const api = getPyApi();
    if (api) {
      try {
        if (api.check_dependencies) {
          const deps = await api.check_dependencies();
          setDependencies(deps);
        }
        if (api.get_network_interfaces) {
          const ifaces = await api.get_network_interfaces();
          if (ifaces && ifaces.success) {
            setNetworkInterfaces(ifaces.interfaces || []);
            if (ifaces.primary?.cidr) {
              setTarget(ifaces.primary.cidr);
            }
          }
        }
      } catch (err) {
        console.error('Failed fetching environment info:', err);
      }
    }
  }, [getPyApi]);

  useEffect(() => {
    window.addEventListener('pywebviewready', refreshEnvironment);
    refreshEnvironment();

    // Auto-load sample scan for initial instant demonstration
    const timer = setTimeout(() => {
      handleLoadSample();
    }, 400);

    return () => {
      window.removeEventListener('pywebviewready', refreshEnvironment);
      clearTimeout(timer);
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [refreshEnvironment]);

  // Start Network Diagnostic Scan
  const handleStartScan = async (customTarget = null) => {
    const scanTarget = (customTarget || target).trim();
    if (!scanTarget) return;

    setError(null);
    setIsScanning(true);
    setLiveLogs([`[*] Initializing ${scanProfile} scan against ${scanTarget}...`]);
    setStatusMessage(`Scanning ${scanTarget} (${scanProfile})...`);

    const api = getPyApi();

    // Start background live status polling
    if (pollingRef.current) clearInterval(pollingRef.current);
    pollingRef.current = setInterval(async () => {
      const activeApi = getPyApi();
      if (activeApi && activeApi.get_live_state) {
        try {
          const state = await activeApi.get_live_state();
          if (state && state.logs && state.logs.length > 0) {
            setLiveLogs(state.logs);
          }
          if (state && state.status) {
            setStatusMessage(state.status);
          }
        } catch (e) {
          // ignore poll error
        }
      }
    }, 600);

    if (api && api.start_scan) {
      try {
        const result = await api.start_scan(scanTarget, ports, requiresRoot, scanProfile, scripts);
        if (pollingRef.current) clearInterval(pollingRef.current);

        if (result.success) {
          setScanData(result);
          if (result.logs) setLiveLogs(result.logs);
          const hostCount = result.data?.hosts?.length || 0;
          setStatusMessage(`Scan complete: ${hostCount} host(s) discovered.`);
          setError(null);

          // Add to scan history
          setScanHistory((prev) => [
            {
              id: Date.now(),
              target: scanTarget,
              scanProfile,
              timestamp: new Date().toLocaleTimeString(),
              hostsCount: hostCount,
              data: result,
            },
            ...prev.slice(0, 9),
          ]);
        } else {
          setError(result.error || 'Scan failed.');
          if (result.logs) setLiveLogs(result.logs);
          setStatusMessage('Scan terminated with errors.');
        }
      } catch (err) {
        if (pollingRef.current) clearInterval(pollingRef.current);
        setError(`IPC Scan Error: ${err.message || err}`);
        setStatusMessage('Scan failed.');
      } finally {
        setIsScanning(false);
      }
    } else {
      setTimeout(() => {
        if (pollingRef.current) clearInterval(pollingRef.current);
        setIsScanning(false);
        setError('PyWebView IPC backend not connected. Running in demo mode.');
        handleLoadSample();
      }, 1000);
    }
  };

  // Cancel Scan Execution
  const handleCancelScan = async () => {
    if (pollingRef.current) clearInterval(pollingRef.current);
    const api = getPyApi();
    if (api && api.cancel_scan) {
      try {
        await api.cancel_scan();
        setStatusMessage('Scan cancellation requested.');
      } catch (err) {
        console.error('Cancel scan error:', err);
      }
    }
    setIsScanning(false);
  };

  // Load Built-in Demo Network
  const handleLoadSample = async () => {
    setError(null);
    const api = getPyApi();
    if (api && api.load_sample_scan) {
      try {
        const sample = await api.load_sample_scan();
        setScanData(sample);
        if (sample.logs) setLiveLogs(sample.logs);
        setStatusMessage('Sample network dataset loaded (3 hosts, 8 services).');
      } catch (err) {
        console.error('Failed to load sample scan:', err);
      }
    }
  };

  // Save Asset Metadata to SQLite
  const handleSaveAsset = async (assetData) => {
    const api = getPyApi();
    if (api && api.save_asset_metadata) {
      try {
        const res = await api.save_asset_metadata(assetData);
        if (scanData && scanData.data) {
          const updatedHosts = (scanData.data.hosts || []).map((h) => {
            if ((h.ip || h.ipv4) === assetData.ip) {
              return {
                ...h,
                alias: assetData.alias,
                owner: assetData.owner,
                tags: assetData.tags,
                notes: assetData.notes,
                risk_level: assetData.risk_level,
              };
            }
            return h;
          });

          const updatedGrid = (scanData.ag_grid || []).map((r) => {
            if (r.ip === assetData.ip) {
              return { ...r, alias: assetData.alias, risk_level: assetData.risk_level };
            }
            return r;
          });

          const updatedNodes = (scanData.cytoscape?.nodes || []).map((n) => {
            if (n.data.ip === assetData.ip) {
              return {
                ...n,
                data: {
                  ...n.data,
                  alias: assetData.alias,
                  risk_level: assetData.risk_level,
                },
              };
            }
            return n;
          });

          setScanData({
            ...scanData,
            data: { ...scanData.data, hosts: updatedHosts },
            ag_grid: updatedGrid,
            cytoscape: { ...scanData.cytoscape, nodes: updatedNodes },
          });
        }
        return res;
      } catch (e) {
        console.error('Failed to save asset:', e);
        return { success: false, error: String(e) };
      }
    }
    return { success: true };
  };

  // Protocol Launcher
  const handleLaunchProtocol = async (protocol, ip, port = null, username = '') => {
    const api = getPyApi();
    if (api && api.launch_remote_tool) {
      try {
        return await api.launch_remote_tool(protocol, ip, port, username);
      } catch (e) {
        return { success: false, error: String(e) };
      }
    }
    return { success: false, error: 'IPC not ready' };
  };

  // Wake-on-LAN
  const handleSendWol = async (mac) => {
    const api = getPyApi();
    if (api && api.send_wake_on_lan_packet) {
      try {
        return await api.send_wake_on_lan_packet(mac);
      } catch (e) {
        return { success: false, error: String(e) };
      }
    }
    return { success: false, error: 'IPC not ready' };
  };

  // Ping Telemetry
  const handlePingTelemetry = async (ip) => {
    const api = getPyApi();
    if (api && api.ping_host_telemetry) {
      try {
        return await api.ping_host_telemetry(ip);
      } catch (e) {
        return { success: false, error: String(e) };
      }
    }
    return { success: false, error: 'IPC not ready' };
  };

  // Reset Telemetry
  const handleResetTelemetry = async (ip) => {
    const api = getPyApi();
    if (api && api.reset_host_telemetry) {
      try {
        return await api.reset_host_telemetry(ip);
      } catch (e) {
        return { success: false, error: String(e) };
      }
    }
    return { success: true };
  };

  // Passive Discovered Devices
  const handleGetPassiveDevices = async () => {
    const api = getPyApi();
    if (api && api.get_passive_discovered_devices) {
      try {
        return await api.get_passive_discovered_devices();
      } catch (e) {
        return { success: false, error: String(e) };
      }
    }
    return { success: true, devices: [] };
  };

  // Compare Two Scans
  const handleCompareScans = async (scanA, scanB) => {
    const api = getPyApi();
    if (api && api.compare_scan_snapshots) {
      try {
        return await api.compare_scan_snapshots(scanA, scanB);
      } catch (e) {
        console.error('Diff error:', e);
      }
    }
    return null;
  };

  // Open Telemetry for Host
  const handleOpenTelemetryForHost = (ip) => {
    setMonitoredPingIp(ip);
    setActiveTab('telemetry');
  };

  // Export Results
  const handleExport = async (format) => {
    if (!scanData) return;
    const api = getPyApi();
    if (api && api.export_results) {
      try {
        const exp = await api.export_results(scanData, format);
        if (exp.success) {
          const blob = new Blob([exp.content], { 
            type: format === 'json' ? 'application/json' : format === 'xml' ? 'text/xml' : 'text/csv' 
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = exp.filename || `scan_results.${format}`;
          a.click();
          URL.revokeObjectURL(url);
          setStatusMessage(`Exported scan results to ${exp.filename}`);
        }
      } catch (err) {
        console.error('Export error:', err);
      }
    }
  };

  const hostsList = scanData?.data?.hosts || [];

  return (
    <div className="flex flex-col h-screen w-screen bg-dark-950 text-slate-100 overflow-hidden select-none">
      {/* Top Application Header */}
      <Header
        dependencies={dependencies}
        onLoadSample={handleLoadSample}
        onExport={handleExport}
        isScanning={isScanning}
        onRefreshDeps={refreshEnvironment}
        scanData={scanData}
      />

      {/* Interactive Scan Control Bar */}
      <ScanControls
        target={target}
        setTarget={setTarget}
        ports={ports}
        setPorts={setPorts}
        scanProfile={scanProfile}
        setScanProfile={setScanProfile}
        requiresRoot={requiresRoot}
        setRequiresRoot={setRequiresRoot}
        scripts={scripts}
        setScripts={setScripts}
        isScanning={isScanning}
        onStartScan={handleStartScan}
        onCancelScan={handleCancelScan}
        dependencies={dependencies}
        networkInterfaces={networkInterfaces}
        onScanLan={(cidr) => handleStartScan(cidr)}
      />

      {/* Main Content Area with Navigation Tabs */}
      <div className="flex-1 flex flex-col min-h-0 bg-dark-900">
        
        {/* Navigation Tab Bar */}
        <div className="px-6 border-b border-slate-800 bg-dark-950/80 flex items-center justify-between shrink-0 overflow-x-auto">
          <div className="flex items-center gap-1">
            
            {/* Topology Canvas Tab */}
            <button
              id="tab-topology"
              onClick={() => setActiveTab('topology')}
              className={`flex items-center gap-2 px-4 py-3 text-xs font-bold border-b-2 transition-all ${
                activeTab === 'topology'
                  ? 'border-brand-cyan text-brand-cyan bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Network className="w-4 h-4" />
              <span>Topology Canvas</span>
              {scanData?.cytoscape?.nodes && (
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-mono">
                  {scanData.cytoscape.nodes.length}
                </span>
              )}
            </button>

            {/* Asset Inventory Table Tab */}
            <button
              id="tab-grid"
              onClick={() => setActiveTab('grid')}
              className={`flex items-center gap-2 px-4 py-3 text-xs font-bold border-b-2 transition-all ${
                activeTab === 'grid'
                  ? 'border-brand-cyan text-brand-cyan bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Table className="w-4 h-4" />
              <span>Asset Inventory</span>
              {scanData?.ag_grid && (
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-mono">
                  {scanData.ag_grid.length}
                </span>
              )}
            </button>

            {/* Host Profiler & Asset Tagging Tab */}
            <button
              id="tab-profiler"
              onClick={() => setActiveTab('profiler')}
              className={`flex items-center gap-2 px-4 py-3 text-xs font-bold border-b-2 transition-all ${
                activeTab === 'profiler'
                  ? 'border-brand-cyan text-brand-cyan bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Server className="w-4 h-4" />
              <span>Host Profiler & Actions</span>
              {hostsList.length > 0 && (
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-mono">
                  {hostsList.length}
                </span>
              )}
            </button>

            {/* Live Ping Telemetry Tab */}
            <button
              id="tab-telemetry"
              onClick={() => setActiveTab('telemetry')}
              className={`flex items-center gap-2 px-4 py-3 text-xs font-bold border-b-2 transition-all ${
                activeTab === 'telemetry'
                  ? 'border-brand-cyan text-brand-cyan bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Activity className="w-4 h-4" />
              <span>Ping Telemetry</span>
            </button>

            {/* Passive Device Sniffer Tab */}
            <button
              id="tab-sniffer"
              onClick={() => setActiveTab('sniffer')}
              className={`flex items-center gap-2 px-4 py-3 text-xs font-bold border-b-2 transition-all ${
                activeTab === 'sniffer'
                  ? 'border-brand-cyan text-brand-cyan bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Radio className="w-4 h-4" />
              <span>Passive Sniffer</span>
            </button>

            {/* Scan Diff & Drift Tab */}
            <button
              id="tab-diff"
              onClick={() => setActiveTab('diff')}
              className={`flex items-center gap-2 px-4 py-3 text-xs font-bold border-b-2 transition-all ${
                activeTab === 'diff'
                  ? 'border-brand-cyan text-brand-cyan bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <GitCompare className="w-4 h-4" />
              <span>Scan Diff</span>
            </button>

            {/* Live Terminal Console Tab */}
            <button
              id="tab-console"
              onClick={() => setActiveTab('console')}
              className={`flex items-center gap-2 px-4 py-3 text-xs font-bold border-b-2 transition-all ${
                activeTab === 'console'
                  ? 'border-brand-cyan text-brand-cyan bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Terminal className="w-4 h-4" />
              <span>Console</span>
              {isScanning && (
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              )}
            </button>

            {/* Raw Nmap XML Tab */}
            <button
              id="tab-raw"
              onClick={() => setActiveTab('raw_xml')}
              className={`flex items-center gap-2 px-4 py-3 text-xs font-bold border-b-2 transition-all ${
                activeTab === 'raw_xml'
                  ? 'border-brand-cyan text-brand-cyan bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Code className="w-4 h-4" />
              <span>XML</span>
            </button>
          </div>

          {/* Quick Indicator */}
          <div className="flex items-center gap-3">
            {scanHistory.length > 0 && (
              <div className="hidden sm:flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                <History className="w-3.5 h-3.5 text-slate-500" />
                <span className="text-[11px]">{scanHistory.length} scan(s)</span>
              </div>
            )}
          </div>
        </div>

        {/* Tab View Canvas */}
        <div className="flex-1 min-h-0 relative">
          {activeTab === 'topology' && (
            <Topology
              elements={scanData?.cytoscape}
              onSelectHost={(host) => setSelectedHost(host)}
            />
          )}

          {activeTab === 'grid' && (
            <DataGrid
              rowData={scanData?.ag_grid || []}
              onSelectHost={(host) => setSelectedHost(host)}
            />
          )}

          {activeTab === 'profiler' && (
            <HostProfiler
              hosts={hostsList}
              onSaveAsset={handleSaveAsset}
              onSelectHostModal={(host) => setSelectedHost(host)}
              onLaunchProtocol={handleLaunchProtocol}
              onSendWol={handleSendWol}
              onOpenTelemetry={handleOpenTelemetryForHost}
            />
          )}

          {activeTab === 'telemetry' && (
            <LatencyMonitor
              monitoredIp={monitoredPingIp}
              discoveredHosts={hostsList}
              onPingTelemetry={handlePingTelemetry}
              onResetTelemetry={handleResetTelemetry}
            />
          )}

          {activeTab === 'sniffer' && (
            <PassiveSniffer
              onGetPassiveDevices={handleGetPassiveDevices}
              onTargetSelect={(ip) => {
                setTarget(ip);
                handleStartScan(ip);
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

          {activeTab === 'console' && (
            <LiveConsole
              logs={liveLogs}
              isScanning={isScanning}
              activeCommand={scanData?.stage_info?.nmap_args?.join(' ')}
            />
          )}

          {activeTab === 'raw_xml' && (
            <div className="h-full w-full p-4 overflow-auto bg-[#060810] font-mono text-xs text-slate-300 select-text">
              <pre className="whitespace-pre-wrap">{scanData?.raw_xml || 'No XML scan output available.'}</pre>
            </div>
          )}

          {/* Scanning Floating Notification */}
          {isScanning && activeTab !== 'console' && (
            <div className="absolute bottom-4 right-4 z-40 p-4 rounded-2xl glass-panel border border-cyan-500/40 shadow-2xl flex items-center gap-3 animate-in fade-in slide-in-from-bottom-2">
              <div className="w-6 h-6 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
              <div>
                <span className="text-xs font-bold text-white block">Scanning in progress...</span>
                <span className="text-[11px] text-cyan-300">{statusMessage}</span>
              </div>
              <button
                onClick={() => setActiveTab('console')}
                className="ml-2 px-2.5 py-1 rounded-lg bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 text-xs font-semibold"
              >
                View Console
              </button>
            </div>
          )}
        </div>

      </div>

      {/* Host Detail Modal */}
      {selectedHost && (
        <HostDetailModal
          host={selectedHost}
          allHostsData={hostsList}
          onClose={() => setSelectedHost(null)}
          onLaunchProtocol={handleLaunchProtocol}
          onSendWol={handleSendWol}
          onOpenTelemetry={handleOpenTelemetryForHost}
        />
      )}

      {/* Bottom Status Bar */}
      <StatusBar
        statusMessage={statusMessage}
        isScanning={isScanning}
        error={error}
        scanData={scanData}
      />
    </div>
  );
}
