import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useLiveAlerts } from '../hooks/useLiveAlerts.js';
import { toDbId, resolveAlerts, updateAlertStatus, fetchSettings } from '../api/ariaClient.js';
import { TopNav } from '../components/ui.jsx';
import { openReport } from '../utils/report.js';
import { Shield, Cpu, Network, FileJson, CheckCircle2, AlertTriangle, ExternalLink } from 'lucide-react';

function ResolutionModal({ isOpen, onClose, onResolve }) {
  const [disposition, setDisposition] = useState('True Positive');
  const [reason, setReason] = useState('');
  if (!isOpen) return null;
  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h3 style={{ marginTop: 0, marginBottom: '16px', fontSize: '15px' }}>Resolve Alert</h3>
        <div style={{ marginBottom: '16px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontSize: '12px', color: 'var(--text-muted)' }}>
            Disposition
          </label>
          <select
            value={disposition}
            onChange={e => setDisposition(e.target.value)}
            style={{ width: '100%', padding: '8px', background: 'var(--bg)', border: '1px solid var(--border)', color: 'white', borderRadius: 2 }}
          >
            <option value="True Positive">True Positive</option>
            <option value="False Positive">False Positive</option>
            <option value="Benign">Benign</option>
            <option value="Duplicate">Duplicate</option>
          </select>
        </div>
        <div style={{ marginBottom: '24px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontSize: '12px', color: 'var(--text-muted)' }}>
            Resolution Reason
          </label>
          <input
            type="text"
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="1-line justification for audit trail"
            style={{ width: '100%', padding: '8px', background: 'var(--bg)', border: '1px solid var(--border)', color: 'white', borderRadius: 2 }}
          />
        </div>
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={() => onResolve(disposition, reason)}>
            Confirm Resolution
          </button>
        </div>
      </div>
    </div>
  );
}

function QueueRow({ alert, selected, onClick }) {
  return (
    <button className={`queue-row ${selected ? 'selected' : ''}`} onClick={onClick}>
      <div className="queue-top mono" style={{ fontSize: '11px', lineHeight: 1.4, wordBreak: 'break-word' }}>
        <strong>{alert.title}{alert.count > 1 && <span style={{ marginLeft: 6, color: 'var(--text-muted)' }}>×{alert.count}</span>}</strong>
      </div>
      <div className="queue-meta mono" style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
        <span>{alert.id}</span>
        <span className={`risk-txt ${alert.severity.toLowerCase()}`}>Risk: {alert.score}</span>
      </div>
    </button>
  );
}

function groupQueue(list) {
  const groups = {};
  list.forEach(a => {
    const d = new Date(a.timestamp || a.time);
    const hour = Number.isNaN(d.getTime()) ? 'x' : d.toISOString().slice(0, 13);
    const key = [a.agent, a.ip, a.title, a.status === 'RESOLVED' ? 'R' : 'A', hour].join('_');
    if (!groups[key]) groups[key] = { ...a, count: 0 };
    groups[key].count += 1;
  });
  return Object.values(groups).sort((x, y) => y.dbId - x.dbId);
}

export default function Triage() {
  const { alertId } = useParams();
  const nav = useNavigate();
  const { alerts, error, refresh } = useLiveAlerts();
  const [queueFilter, setQueueFilter] = useState('Active');

  const isResolved = a => String(a.status).toUpperCase() === 'RESOLVED';
  const queue = useMemo(() => groupQueue(alerts.filter(a =>
    queueFilter === 'All' ? true : queueFilter === 'Active' ? !isResolved(a) : isResolved(a))), [alerts, queueFilter]);

  // Selected alert: URL id wins, otherwise top-most alert of the visible queue
  const selected = useMemo(() => {
    if (alertId) return alerts.find(a => a.id === alertId) || null;
    return queue[0] ? alerts.find(a => a.id === queue[0].id) || queue[0] : null;
  }, [alerts, alertId, queue]);

  // Auto-select the top active alert on page load
  useEffect(() => {
    if (!alertId && queue.length > 0) nav(`/triage/${queue[0].id}`, { replace: true });
  }, [alertId, queue, nav]);

  const [doneSteps, setDoneSteps] = useState({});
  const [showRaw, setShowRaw] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [analystName, setAnalystName] = useState('Analyst');

  const [openedAt] = useState(new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC'));

  useEffect(() => {
    fetchSettings()
      .then(cfg => {
        if (cfg && cfg.analyst_name) setAnalystName(cfg.analyst_name);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    setDoneSteps({});
    setShowRaw(false);
  }, [alertId]);

  const handleResolve = async (disposition, reason) => {
    if (!selected) return;
    try {
      await resolveAlerts(toDbId(selected.id), disposition, reason, analystName);
      setIsModalOpen(false);
      await refresh();
    } catch (e) {
      console.error(e);
      alert("Failed to resolve alert");
    }
  };

  const handleEscalate = async () => {
    if (!selected) return;
    try {
      await updateAlertStatus(toDbId(selected.id), 'ESCALATED', null, null, analystName);
      await refresh();
    } catch (e) {
      console.error(e);
      alert("Failed to escalate alert");
    }
  };

  const topProcesses = selected?.topProcesses || [];
  const externalConnections = selected?.externalConnections || [];
  const telemetry = selected?.telemetry || {};

  return (
    <div className="app-layout" style={{ height: '100vh', overflow: 'hidden' }}>
      <TopNav triage />

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Left Side: Alert Queue List */}
        <aside className="queue-panel">
          <div className="queue-heading" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <strong>Alert Queue ({queue.length})</strong>
            <button className="btn" onClick={() => refresh()} style={{ padding: '2px 8px', fontSize: 11 }}>
              Refresh
            </button>
          </div>
          <div style={{ display: 'flex', gap: 4, padding: '8px 12px', borderBottom: '1px solid var(--border)' }}>
            {['Active', 'Resolved', 'All'].map(f => (
              <button key={f} className={queueFilter === f ? 'btn primary' : 'btn'} style={{ flex: 1, padding: '3px 0', fontSize: 11 }} onClick={() => setQueueFilter(f)}>{f}</button>
            ))}
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {queue.length === 0 ? (
              <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)' }}>
                No {queueFilter.toLowerCase()} alerts in queue
              </div>
            ) : (
              queue.map(a => (
                <QueueRow
                  key={a.id}
                  alert={a}
                  selected={selected?.id === a.id}
                  onClick={() => nav(`/triage/${a.id}`)}
                />
              ))
            )}
          </div>
        </aside>

        {/* Right Side: Detail Panel */}
        <main className="detail-panel">
          {!selected ? (
            <div className="empty-state">Select an alert to view investigation details</div>
          ) : (
            <>
              {/* Sheet Header */}
              <div className="sheet-header">
                <h1 className="sheet-title mono" style={{ fontSize: 16 }}>{selected.title}</h1>
                <div className="sheet-meta mono">
                  <span>ID: {selected.id}</span>
                  <span>STATUS: <strong style={{ color: selected.status === 'RESOLVED' ? 'var(--green)' : 'var(--amber)' }}>{selected.status}</strong></span>
                  <span>HOST: {selected.agent} ({selected.ip})</span>
                  <span>INGEST TIME: {selected.time}</span>
                  {selected.occurrenceCount > 1 && (
                    <span style={{ color: 'var(--blue)' }}>AGGREGATED: {selected.occurrenceCount}x</span>
                  )}
                </div>
              </div>

              {/* Verdict KPI Line */}
              <div className="verdict-line">
                <div className="verdict-box">
                  <label>Risk Score</label>
                  <strong className={`risk-txt ${selected.severity.toLowerCase()}`}>{selected.score}/100</strong>
                </div>
                <div className="verdict-box">
                  <label>Confidence</label>
                  <strong>{selected.confidence || 'Moderate'}</strong>
                </div>
                <div className="verdict-box">
                  <label>Triage Action</label>
                  <strong style={{ color: 'var(--amber)' }}>{selected.triageAction}</strong>
                </div>
              </div>

              {/* Section 1: Automated Triage Summary */}
              <div className="result-section">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <h3 style={{ margin: 0 }}>Automated Triage Summary</h3>
                  <button className="btn" onClick={() => setShowRaw(!showRaw)} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
                    <FileJson size={13} />
                    {showRaw ? 'Hide Raw Telemetry JSON' : 'View Raw Telemetry JSON'}
                  </button>
                </div>

                <div style={{ background: 'var(--bg)', padding: 16, border: '1px solid var(--border)', borderRadius: 2, marginBottom: 12 }}>
                  <p style={{ margin: 0, fontSize: 13, lineHeight: 1.5, color: 'var(--text-body)' }}>
                    {selected.reasoning}
                  </p>
                </div>

              </div>

              {/* Collapsible Raw Telemetry Drawer */}
              {showRaw && (
                <div className="result-section" style={{ background: '#050505', borderBottom: '2px solid var(--blue)' }}>
                  <h3 style={{ margin: '0 0 12px 0', color: 'var(--blue)' }}>Raw Telemetry & Context JSON</h3>
                  <pre className="mono" style={{ background: 'var(--bg)', padding: 16, border: '1px solid var(--border)', overflowX: 'auto', maxHeight: 350, fontSize: 11, whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify({
                      alert_id: selected.dbId,
                      timestamp: selected.timestamp,
                      agent_name: selected.agent,
                      agent_ip: selected.ip,
                      host_context: selected.hostContext,
                      feature_snapshot: selected.telemetry,
                      rag_analysis: selected.raw
                    }, null, 2)}
                  </pre>
                </div>
              )}

              {/* Section 2: Host Observations & Process Attribution */}
              <div className="result-section">
                <h3 style={{ margin: '0 0 16px 0' }}>Host Observations & Process Attribution</h3>

                {/* Top Offending Processes Table */}
                <div style={{ marginBottom: 20 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                    <Cpu size={14} style={{ color: 'var(--blue)' }} />
                    <strong style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Top Processes (Resource Consumption)</strong>
                  </div>
                  <table className="telemetry-table mono">
                    <thead>
                      <tr>
                        <th style={{ width: '80px' }}>PID</th>
                        <th>Process Name</th>
                        <th style={{ width: '140px' }}>Working Set (MB)</th>
                        <th>Executable Path</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topProcesses.length === 0 ? (
                        <tr>
                          <td colSpan="4" style={{ color: 'var(--text-muted)', textAlign: 'center', padding: 12 }}>
                            Process details were not recorded for this alert.
                          </td>
                        </tr>
                      ) : (
                        topProcesses.map((proc, idx) => {
                          const pName = proc.name || proc.Name || 'proc';
                          const pid = proc.pid ?? proc.Id ?? proc.PID ?? 'N/A';
                          const ws = proc.working_set_mb ?? proc.WorkingSet64 ?? '—';
                          const path = proc.path || proc.Path || '—';
                          return (
                            <tr key={idx}>
                              <td style={{ color: 'var(--blue)', fontWeight: 600 }}>{pid}</td>
                              <td style={{ fontWeight: 600 }}>{pName}</td>
                              <td>{typeof ws === 'number' ? `${Math.round(ws)} MB` : ws}</td>
                              <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>{path}</td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>

                {/* External Sockets & Network Connections Table */}
                <div style={{ marginBottom: 20 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                    <Network size={14} style={{ color: 'var(--green)' }} />
                    <strong style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Active External Connections (Non-Loopback)</strong>
                  </div>
                  <table className="telemetry-table mono">
                    <thead>
                      <tr>
                        <th style={{ width: '100px' }}>Local Port</th>
                        <th>Remote Address</th>
                        <th style={{ width: '100px' }}>Remote Port</th>
                        <th style={{ width: '90px' }}>Owning PID</th>
                      </tr>
                    </thead>
                    <tbody>
                      {externalConnections.length === 0 ? (
                        <tr>
                          <td colSpan="4" style={{ color: 'var(--text-muted)', textAlign: 'center', padding: 12 }}>
                            No active non-loopback external TCP connections observed during spike cycle
                          </td>
                        </tr>
                      ) : (
                        externalConnections.map((conn, idx) => {
                          const localPort = conn.local_port || conn.LocalPort || '—';
                          const remoteAddr = conn.remote_address || conn.RemoteAddress || '—';
                          const remotePort = conn.remote_port || conn.RemotePort || '—';
                          const owningPid = conn.owning_process || conn.OwningProcess || conn.pid || '—';
                          return (
                            <tr key={idx}>
                              <td>{localPort}</td>
                              <td style={{ color: 'var(--amber)', fontWeight: 600 }}>{remoteAddr}</td>
                              <td>{remotePort}</td>
                              <td style={{ color: 'var(--blue)' }}>{owningPid}</td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Key Performance Metrics Table */}
                <div>
                  <strong style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.04em', display: 'block', marginBottom: 8 }}>
                    Raw TON_IoT Performance Telemetry Counters
                  </strong>
                  <table className="telemetry-table mono">
                    <thead>
                      <tr>
                        <th>Performance Counter Metric</th>
                        <th style={{ width: '220px' }}>Observed Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.keys(telemetry).length === 0 ? (
                        <tr>
                          <td colSpan="2" style={{ color: 'var(--text-muted)', textAlign: 'center', padding: 12 }}>
                            Performance feature vector stored in queue database
                          </td>
                        </tr>
                      ) : (
                        Object.entries(telemetry).map(([k, v]) => (
                          <tr key={k}>
                            <td style={{ color: 'var(--text-secondary)' }}>{k}</td>
                            <td style={{ fontWeight: 600 }}>
                              {typeof v === 'number' ? v.toLocaleString() : String(v)}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Section 3: MITRE ATT&CK Mapping (Hidden if empty or unmapped) */}
              {selected.mitre && selected.mitre.length > 0 && (
                <div className="result-section">
                  <h3 style={{ margin: '0 0 12px 0' }}>Correlated MITRE ATT&CK Techniques</h3>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {selected.mitre.map(t => (
                      <span
                        key={t}
                        className="mono"
                        style={{ padding: '6px 12px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 2, fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 6 }}
                      >
                        <Shield size={12} style={{ color: 'var(--blue)' }} />
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Section 4: Retrieved Threat Intel Evidence (Hidden if empty) */}
              {selected.evidence && selected.evidence.length > 0 && (
                <div className="result-section">
                  <h3 style={{ margin: '0 0 16px 0' }}>Retrieved Threat Intelligence Context</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    {selected.evidence.map((e, i) => (
                      <div key={i} style={{ padding: 14, background: 'var(--bg)', border: '1px solid var(--border)', borderLeft: `3px solid ${e.tier === 'PRIMARY' ? 'var(--blue)' : 'var(--border)'}`, borderRadius: 2 }}>
                        <div className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
                          {e.source} • Relevance: {e.score}
                        </div>
                        <div style={{ fontSize: 13, lineHeight: 1.4 }}>{e.body}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Section 5: Investigation Steps */}
              <div className="result-section">
                <h3 style={{ margin: '0 0 16px 0' }}>Investigation Steps</h3>
                <div style={{ border: '1px solid var(--border)', borderRadius: 2 }}>
                  {selected.steps.map((s, i) => {
                    const completed = !!doneSteps[i];
                    return (
                      <div
                        key={i}
                        style={{
                          padding: 12,
                          borderBottom: i < selected.steps.length - 1 ? '1px solid var(--border)' : 'none',
                          display: 'flex',
                          gap: 12,
                          alignItems: 'flex-start',
                          background: completed ? 'rgba(34, 197, 94, 0.04)' : 'transparent',
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={completed}
                          onChange={() => setDoneSteps(d => ({ ...d, [i]: !d[i] }))}
                          style={{ marginTop: 3 }}
                        />
                        <div style={{ flex: 1 }}>
                          <div style={{ textDecoration: completed ? 'line-through' : 'none', color: completed ? 'var(--text-muted)' : 'inherit', fontSize: 13 }}>
                            {s}
                          </div>
                          {completed && (
                            <div className="mono" style={{ fontSize: 10, color: 'var(--green)', marginTop: 4 }}>
                              Step verified by {analystName}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Section 6: Activity & Disposition Audit Log */}
              <div className="result-section">
                <h3 style={{ margin: '0 0 14px 0' }}>Activity & Audit Log</h3>
                <table className="telemetry-table mono" style={{ fontSize: 11 }}>
                  <tbody>
                    <tr>
                      <td style={{ width: '180px' }}>{selected.time}</td>
                      <td>Alert ingested by Wazuh Collector & classified by Random Forest ({selected.severity})</td>
                    </tr>
                    <tr>
                      <td>{openedAt}</td>
                      <td>Alert opened in SOC Console by {analystName}</td>
                    </tr>
                    {String(selected.status).toUpperCase() === 'RESOLVED' && (
                      <tr style={{ background: 'rgba(34, 197, 94, 0.05)' }}>
                        <td style={{ color: 'var(--green)' }}>{selected.closedAt || 'RESOLVED'}</td>
                        <td style={{ color: 'var(--green)' }}>
                          Closed by {selected.closedBy || 'Analyst'} · Disposition: <strong>{selected.disposition}</strong> {selected.reason ? `("${selected.reason}")` : ''}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Sticky Action Bar */}
              <div className="sticky-action-bar">
                {String(selected.status).toUpperCase() !== 'RESOLVED' ? (
                  <>
                    <button className="btn primary" onClick={() => setIsModalOpen(true)}>
                      Resolve Alert
                    </button>
                    <button className="btn danger" onClick={handleEscalate}>
                      Escalate to Tier-2
                    </button>
                  </>
                ) : (
                  <button className="btn" onClick={() => setIsModalOpen(true)}>
                    Re-open / Update Disposition
                  </button>
                )}
                <button className="btn" onClick={() => openReport(selected)}>
                  Print / Export Summary
                </button>
              </div>

              <ResolutionModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                onResolve={handleResolve}
              />
            </>
          )}
        </main>
      </div>
    </div>
  );
}
