import React, { useState, useEffect, useRef } from 'react';
import { Bell, Wifi, WifiOff, PlusCircle, ShieldAlert, CheckCheck } from 'lucide-react';

const KIND_META = {
  new_device: { icon: Wifi, color: 'text-cyan-400', bg: 'bg-cyan-500/10 border-cyan-500/20' },
  device_offline: { icon: WifiOff, color: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/20' },
  port_opened: { icon: PlusCircle, color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20' },
  port_closed: { icon: ShieldAlert, color: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/20' },
  service_changed: { icon: ShieldAlert, color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20' },
};

/**
 * AlertsBell — quiet notification bell in the header.
 * Polls the backend for unread alert count; clicking opens a dropdown
 * with recent alerts. No popups, no nagging.
 */
export default function AlertsBell() {
  const [unread, setUnread] = useState(0);
  const [alerts, setAlerts] = useState([]);
  const [open, setOpen] = useState(false);
  const dropdownRef = useRef(null);

  const api = () => window.pywebview?.api;

  const refreshCount = async () => {
    try {
      const a = api();
      if (a?.get_unread_alert_count) {
        const res = await a.get_unread_alert_count();
        if (res?.success) setUnread(res.unread || 0);
      }
    } catch (_) {}
  };

  const loadAlerts = async () => {
    try {
      const a = api();
      if (a?.get_alerts) {
        const res = await a.get_alerts(false, 30);
        if (res?.success) setAlerts(res.alerts || []);
      }
    } catch (_) {}
  };

  useEffect(() => {
    refreshCount();
    const interval = setInterval(refreshCount, 15000);
    // Close dropdown on outside click
    const onClick = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => {
      clearInterval(interval);
      document.removeEventListener('mousedown', onClick);
    };
  }, []);

  const handleToggle = async () => {
    const next = !open;
    setOpen(next);
    if (next) {
      await loadAlerts();
      // Mark as read after showing
      try {
        const a = api();
        if (a?.mark_alerts_read) {
          await a.mark_alerts_read();
          setUnread(0);
        }
      } catch (_) {}
    }
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={handleToggle}
        className={`relative p-2 rounded-lg transition-all ${
          open ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-800'
        }`}
        title="Network change alerts"
      >
        <Bell className="w-4 h-4" />
        {unread > 0 && (
          <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-1 rounded-full bg-rose-500 text-white text-[9px] font-bold flex items-center justify-center animate-tag-pop">
            {unread > 99 ? '99+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-96 bg-dark-900 border border-slate-700 rounded-2xl shadow-2xl z-50 animate-slide-up overflow-hidden">
          <div className="p-3.5 border-b border-slate-800 flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-white">Network Changes</span>
            {unread === 0 && alerts.length > 0 && (
              <span className="flex items-center gap-1 text-[10px] text-emerald-400 font-semibold">
                <CheckCheck className="w-3 h-3" /> all caught up
              </span>
            )}
          </div>

          <div className="max-h-80 overflow-y-auto">
            {alerts.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 italic">
                <Bell className="w-6 h-6 mx-auto mb-2 text-slate-600" />
                No changes detected yet. Run a second scan to establish a baseline.
              </div>
            ) : (
              alerts.map((a) => {
                const meta = KIND_META[a.kind] || KIND_META.service_changed;
                const Icon = meta.icon;
                const time = a.created_at ? new Date(a.created_at * 1000).toLocaleString() : '';
                return (
                  <div key={a.id} className="p-3 border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
                    <div className="flex items-start gap-2.5">
                      <div className={`p-1.5 rounded-lg border shrink-0 ${meta.bg}`}>
                        <Icon className={`w-3.5 h-3.5 ${meta.color}`} />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-xs font-semibold text-slate-200 leading-snug">{a.title}</p>
                        {a.detail && <p className="text-[10px] text-slate-500 mt-0.5 leading-relaxed">{a.detail}</p>}
                        <p className="text-[9px] text-slate-600 mt-1">{time}</p>
                      </div>
                      {a.severity === 'critical' && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30 shrink-0">CRIT</span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}