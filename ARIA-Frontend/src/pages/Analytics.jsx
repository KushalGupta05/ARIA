import React, { useEffect, useState } from 'react';
import { TopNav } from '../components/ui.jsx';
import { fetchAnalytics } from '../api/ariaClient.js';
import { BarChart3, ShieldAlert, CheckCircle2, Clock, Activity, RefreshCw } from 'lucide-react';

function formatDuration(seconds) {
  if (!seconds || seconds <= 0) return '—';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) {
    const m = Math.floor(seconds / 60);
    const s = Math.round(seconds % 60);
    return `${m}m ${s}s`;
  }
  const h = Math.floor(seconds / 3600);
  const m = Math.round((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

export default function Analytics() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const res = await fetchAnalytics();
      setData(res);
      setError(null);
    } catch (err) {
      console.error('Failed to load analytics:', err);
      setError('Unable to connect to the Analytics API.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, []);

  const total = data?.total_alerts || 0;
  const openAlerts = data?.open_alerts || 0;
  const resolved = data?.resolved_alerts || 0;
  const fpRate = data?.false_positive_rate != null ? `${data.false_positive_rate}%` : '0.0%';
  const mttt = formatDuration(data?.mean_time_to_triage_sec);

  // Volume Timeline Calculations
  const timeline = data?.volume_timeline || [];
  const maxVolume = Math.max(...timeline.map(t => t.count), 1);

  const dispositions = data?.disposition_breakdown || {};
  const classes = data?.top_classes || [];
  const hosts = data?.top_hosts || [];

  return (
    <div className="app-layout">
      <TopNav />

      {/* KPI Summary Strip */}
      <div className="kpi-strip">
        <div className="kpi-item">
          <span className="kpi-label">Total Ingested</span>
          <span className="kpi-val">{total}</span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Open / Active</span>
          <span className="kpi-val" style={{ color: openAlerts > 0 ? 'var(--amber)' : 'inherit' }}>
            {openAlerts}
          </span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Resolved (Analyst / ARIA)</span>
          <span className="kpi-val">
            {data?.closed_by_analyst || 0} / {data?.closed_by_aria || 0}
          </span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">False positives among resolved</span>
          <span className="kpi-val" style={{ color: 'var(--blue)' }}>{fpRate}</span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Mean time to resolution</span>
          <span className="kpi-val">{mttt}</span>
        </div>
      </div>

      <main style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div>
            <h1 style={{ fontSize: 18, fontWeight: 600, margin: '0 0 4px 0' }}>Security Operations Analytics</h1>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
              Real-time pipeline metrics, resolution performance, and attack classification distribution.
            </p>
          </div>
          <button className="btn" onClick={loadData} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>

        {error && (
          <div style={{ padding: '12px 16px', background: 'rgba(239,68,68,0.1)', border: '1px solid var(--red)', borderRadius: 4, color: 'var(--red)', marginBottom: 20 }}>
            {error}
          </div>
        )}

        {/* Top Grid: Volume Timeline & Resolution Breakdown */}
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 20, marginBottom: 20 }}>
          {/* Alert Volume Timeline */}
          <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Activity size={15} style={{ color: 'var(--blue)' }} />
                <strong style={{ fontSize: 13, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Alert Volume Over Time</strong>
              </div>
              <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>Hourly Buckets</span>
            </div>

            {timeline.length === 0 ? (
              <div style={{ height: 160, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                No volume data recorded yet.
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'flex-end', gap: 6, height: 160, paddingTop: 10, borderBottom: '1px solid var(--border)' }}>
                {timeline.map((t, idx) => {
                  const heightPct = t.count === 0 ? 2 : Math.max(8, (t.count / maxVolume) * 100);
                  const label = (t.label || t.time.split(' ')[1]) + ((idx === 0 || (t.label || '').startsWith('00')) ? ' ' + t.time.slice(5, 10) : '');
                  return (
                    <div
                      key={idx}
                      style={{
                        flex: 1,
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        height: '100%',
                        justifyContent: 'flex-end',
                      }}
                      title={`${t.time}: ${t.count} alert(s)`}
                    >
                      <span className="mono" style={{ fontSize: 10, color: 'var(--text-secondary)', marginBottom: 4 }}>
                        {t.count}
                      </span>
                      <div
                        style={{
                          width: '100%',
                          minWidth: 12,
                          height: `${heightPct}%`,
                          background: 'var(--blue)',
                          borderRadius: '2px 2px 0 0',
                          opacity: 0.85,
                          transition: 'height 0.2s ease',
                        }}
                      />
                      <span className="mono" style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 6, whiteSpace: 'nowrap' }}>
                        {label}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Disposition Breakdown */}
          <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: 18 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
              <CheckCircle2 size={15} style={{ color: 'var(--green)' }} />
              <strong style={{ fontSize: 13, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Resolution Dispositions</strong>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {[
                { key: 'True Positive', label: 'True Positive', color: 'var(--red)' },
                { key: 'False Positive', label: 'False Positive', color: 'var(--amber)' },
                { key: 'Benign', label: 'Benign / Clean', color: 'var(--green)' },
                { key: 'Duplicate', label: 'Duplicate', color: 'var(--blue)' },
                { key: 'Unresolved', label: 'Open / Unresolved', color: 'var(--text-muted)' },
              ].map(({ key, label, color }) => {
                const count = dispositions[key] || 0;
                const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                return (
                  <div key={key}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                      <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
                      <span className="mono">
                        {count} <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>({pct}%)</span>
                      </span>
                    </div>
                    <div style={{ height: 6, width: '100%', background: 'var(--elevated)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2 }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Bottom Grid: Top Targeted Hosts & Top Prediction Classes */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
          {/* Top Targeted Hosts */}
          <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: 18 }}>
            <h3 style={{ fontSize: 13, textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 16px 0', color: 'var(--text-secondary)' }}>
              Top Targeted Hosts
            </h3>
            <table className="telemetry-table">
              <thead>
                <tr>
                  <th>Host / Agent Name</th>
                  <th>Alert Count</th>
                  <th>Share</th>
                </tr>
              </thead>
              <tbody>
                {hosts.length === 0 ? (
                  <tr>
                    <td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 16 }}>
                      No host telemetry recorded
                    </td>
                  </tr>
                ) : (
                  hosts.map(h => (
                    <tr key={h.host}>
                      <td className="mono" style={{ fontWeight: 600 }}>{h.host}</td>
                      <td className="mono">{h.count}</td>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>
                        {total > 0 ? `${Math.round((h.count / total) * 100)}%` : '0%'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Top Prediction Classes */}
          <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: 18 }}>
            <h3 style={{ fontSize: 13, textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 16px 0', color: 'var(--text-secondary)' }}>
              ML Attack Categories
            </h3>
            <table className="telemetry-table">
              <thead>
                <tr>
                  <th>Class</th>
                  <th>Category</th>
                  <th>Alerts</th>
                </tr>
              </thead>
              <tbody>
                {classes.length === 0 ? (
                  <tr>
                    <td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 16 }}>
                      No class detections
                    </td>
                  </tr>
                ) : (
                  classes.map(c => {
                    const CLASS_LABELS = {
                      0: 'DDoS',
                      1: 'DoS / Resource Exhaustion',
                      2: 'Code Injection',
                      3: 'MITM',
                      4: 'Normal Baseline',
                      5: 'Password / Brute Force',
                      6: 'Network Scanning',
                      7: 'XSS / Web Attack',
                    };
                    const categoryName = CLASS_LABELS[c.class] || c.name || `Class ${c.class}`;
                    return (
                      <tr key={c.class}>
                        <td className="mono" style={{ color: 'var(--blue)' }}>Class {c.class}</td>
                        <td>{categoryName}</td>
                        <td className="mono">{c.count}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
}
