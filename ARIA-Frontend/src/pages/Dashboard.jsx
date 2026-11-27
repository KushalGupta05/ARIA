import React, { useMemo, useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useLiveAlerts } from '../hooks/useLiveAlerts.js';
import { resolveAlerts, updateAlertStatus, fetchSettings } from '../api/ariaClient.js';
import { TopNav } from '../components/ui.jsx';
import { Filter, X, CheckSquare, AlertCircle } from 'lucide-react';

function groupAlerts(alertsList) {
  const groups = {};
  alertsList.forEach(a => {
    const date = new Date(a.timestamp || a.time);
    const hourKey = Number.isNaN(date.getTime()) ? 'unknown' : date.toISOString().slice(0, 13);
    const key = `${a.agent}_${a.ip}_${a.title}_${hourKey}`;

    if (!groups[key]) {
      groups[key] = { ...a, groupedIds: [], count: 0 };
    }
    groups[key].groupedIds.push(a.dbId);
    groups[key].count += 1;

    if (new Date(a.time) > new Date(groups[key].time)) {
      groups[key].time = a.time;
      groups[key].timestamp = a.timestamp;
      groups[key].id = a.id;
    }
  });
  return Object.values(groups).sort((a,b) => b.dbId - a.dbId);
}

function ResolutionModal({ isOpen, onClose, onResolve, selectedCount }) {
  const [disposition, setDisposition] = useState('True Positive');
  const [reason, setReason] = useState('');

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h3 style={{ marginTop: 0, marginBottom: '16px', fontSize: '15px' }}>
          Resolve {selectedCount} Alert{selectedCount > 1 ? 's' : ''}
        </h3>
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
            Resolution Reason / Note
          </label>
          <input
            type="text"
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="1-line explanation for closure audit log"
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

export default function Dashboard() {
  const { alerts, loading, error, refresh } = useLiveAlerts();
  const [activeTab, setActiveTab] = useState('ACTIVE');
  const [selectedAlerts, setSelectedAlerts] = useState(new Set());
  const [focusedIndex, setFocusedIndex] = useState(0);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [analystName, setAnalystName] = useState('Analyst');
  const [searchParams, setSearchParams] = useSearchParams();
  const nav = useNavigate();

  const techniqueFilter = searchParams.get('technique');

  useEffect(() => {
    fetchSettings()
      .then(cfg => {
        if (cfg && cfg.analyst_name) setAnalystName(cfg.analyst_name);
      })
      .catch(() => {});
  }, []);

  const tabData = useMemo(() => {
    let list = alerts.filter(a => activeTab === 'ACTIVE'
      ? String(a.status).toUpperCase() !== 'RESOLVED'
      : String(a.status).toUpperCase() === 'RESOLVED'
    );
    if (techniqueFilter) {
      list = list.filter(a => (a.mitre || []).some(m => m.includes(techniqueFilter)));
    }
    return list;
  }, [alerts, activeTab, techniqueFilter]);

  const groupedData = useMemo(() => groupAlerts(tabData), [tabData]);

  // KPIs
  const activeCount = alerts.filter(a => String(a.status).toUpperCase() !== 'RESOLVED').length;
  const unassigned = alerts.filter(a => String(a.status).toUpperCase() !== 'RESOLVED' && !a.owner).length;
  const oldestOpen = activeCount > 0
    ? (alerts.filter(a => String(a.status).toUpperCase() !== 'RESOLVED').sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp))[0]?.time || 'N/A')
    : 'None';
  const closedByAnalyst = alerts.filter(a => String(a.status).toUpperCase() === 'RESOLVED' && (a.closedBy && !['ARIA', 'RULE'].includes(a.closedBy.toUpperCase()))).length;
  const closedByAria = alerts.filter(a => String(a.status).toUpperCase() === 'RESOLVED' && ['ARIA', 'RULE'].includes(a.closedBy.toUpperCase())).length;

  useEffect(() => {
    setSelectedAlerts(new Set());
    setFocusedIndex(0);
  }, [activeTab, techniqueFilter]);

  // Keyboard Navigation
  useEffect(() => {
    if (isModalOpen) return;
    const handleKeyDown = (e) => {
      if (e.key === 'j') setFocusedIndex(prev => Math.min(groupedData.length - 1, prev + 1));
      if (e.key === 'k') setFocusedIndex(prev => Math.max(0, prev - 1));
      if (e.key === 'Enter') {
        const row = groupedData[focusedIndex];
        if (row) nav(`/triage/${row.id}`);
      }
      if (e.key === 'r') {
        if (selectedAlerts.size === 0 && groupedData[focusedIndex]) {
          toggleSelection(groupedData[focusedIndex].id);
        }
        setIsModalOpen(true);
      }
      if (e.key === 'e') {
         if (groupedData[focusedIndex]) {
            const row = groupedData[focusedIndex];
            row.groupedIds.forEach(dbId => updateAlertStatus(dbId, 'ESCALATED', null, null, analystName));
            setTimeout(() => refresh(), 500);
         }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [focusedIndex, groupedData, selectedAlerts, isModalOpen, nav, analystName]);

  const toggleSelection = (id) => {
    const next = new Set(selectedAlerts);
    if (next.has(id)) next.delete(id); else next.add(id);
    setSelectedAlerts(next);
  };

  const handleResolve = async (disposition, reason) => {
    try {
      const idsToResolve = [];
      groupedData.forEach(g => {
        if (selectedAlerts.has(g.id)) idsToResolve.push(...g.groupedIds);
      });
      if (idsToResolve.length === 0 && groupedData[focusedIndex]) {
        idsToResolve.push(...groupedData[focusedIndex].groupedIds);
      }
      await resolveAlerts(idsToResolve, disposition, reason, analystName);
      setSelectedAlerts(new Set());
      setIsModalOpen(false);
      await refresh();
    } catch (err) {
      console.error(err);
      alert("Failed to resolve alerts via API");
    }
  };

  return (
    <div className="app-layout">
      <TopNav />

      {/* KPI Strip */}
      <div className="kpi-strip">
        <div className="kpi-item">
          <span className="kpi-label">Open Alerts</span>
          <span className="kpi-val" style={{ color: activeCount > 0 ? 'var(--amber)' : 'inherit' }}>
            {activeCount}
          </span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Unassigned</span>
          <span className="kpi-val">{unassigned}</span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Oldest Open</span>
          <span className="kpi-val" style={{ fontSize: 13 }}>{oldestOpen}</span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Closed by Analyst</span>
          <span className="kpi-val" style={{ color: 'var(--green)' }}>{closedByAnalyst}</span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Closed by Rule / ARIA</span>
          <span className="kpi-val" style={{ color: 'var(--blue)' }}>{closedByAria}</span>
        </div>
      </div>

      <main className="dashboard-main">
        {/* Table Toolbar */}
        <div className="table-toolbar">
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <div className="tab-toggle" style={{ display: 'flex', gap: '8px' }}>
              <button
                className={`btn ${activeTab === 'ACTIVE' ? 'primary' : ''}`}
                onClick={() => setActiveTab('ACTIVE')}
              >
                Active Alerts ({alerts.filter(a => String(a.status).toUpperCase() !== 'RESOLVED').length})
              </button>
              <button
                className={`btn ${activeTab === 'RESOLVED' ? 'primary' : ''}`}
                onClick={() => setActiveTab('RESOLVED')}
              >
                Resolved History ({alerts.filter(a => String(a.status).toUpperCase() === 'RESOLVED').length})
              </button>
            </div>

            {techniqueFilter && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--elevated)', padding: '2px 8px', borderRadius: 2, fontSize: 11 }}>
                <Filter size={11} />
                <span>Filtered by Technique: <strong>{techniqueFilter}</strong></span>
                <button
                  onClick={() => setSearchParams({})}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 0, display: 'flex' }}
                >
                  <X size={12} />
                </button>
              </div>
            )}
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {selectedAlerts.size > 0 && activeTab === 'ACTIVE' && (
              <button className="btn primary" onClick={() => setIsModalOpen(true)}>
                Resolve Selected ({selectedAlerts.size})
              </button>
            )}
            <button className="btn" onClick={() => refresh()}>
              Refresh
            </button>
          </div>
        </div>

        {/* Alerts Table */}
        <div style={{ flex: 1, overflow: 'auto' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th style={{ width: '32px' }}></th>
                <th style={{ width: '4px', padding: 0 }}></th>
                <th style={{ width: '90px' }}>ID</th>
                <th>Alert Title & Telemetry Snapshot</th>
                <th style={{ width: '180px' }}>Host / Agent</th>
                <th style={{ width: '80px' }}>Risk</th>
                <th style={{ width: '100px' }}>Status</th>
                <th style={{ width: '180px' }}>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {groupedData.length === 0 && (
                <tr>
                  <td colSpan="8" style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                    No alerts found for current criteria.
                  </td>
                </tr>
              )}
              {groupedData.map((row, idx) => (
                <tr
                  key={row.id}
                  className={idx === focusedIndex ? 'focused' : ''}
                  onClick={() => setFocusedIndex(idx)}
                  onDoubleClick={() => nav(`/triage/${row.id}`)}
                >
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedAlerts.has(row.id)}
                      onChange={() => toggleSelection(row.id)}
                      onClick={e => e.stopPropagation()}
                    />
                  </td>
                  <td className="severity-cell">
                    <span className={`sev-bar ${row.severity.toLowerCase()}`} />
                  </td>
                  <td className="mono" style={{ fontWeight: 600 }}>{row.id}</td>
                  <td className="title-cell mono" style={{ fontSize: 12 }}>
                    {row.title}
                    {row.count > 1 && (
                      <span style={{ background: '#333', padding: '2px 6px', borderRadius: '2px', fontSize: '10px', marginLeft: '8px' }}>
                        ×{row.count}
                      </span>
                    )}
                  </td>
                  <td className="mono">
                    <span style={{ fontWeight: 600 }}>{row.agent}</span>
                    <br />
                    <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{row.ip}</span>
                  </td>
                  <td>
                    <span className={`risk-txt ${row.severity.toLowerCase()}`}>{row.score}</span>
                  </td>
                  <td>
                    <span style={{
                      display: 'inline-block',
                      padding: '2px 6px',
                      borderRadius: 2,
                      fontSize: 10,
                      fontWeight: 600,
                      background: row.status === 'RESOLVED' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                      color: row.status === 'RESOLVED' ? 'var(--green)' : 'var(--red)',
                    }}>
                      {row.status}
                    </span>
                  </td>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    {row.time}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>

      <ResolutionModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onResolve={handleResolve}
        selectedCount={selectedAlerts.size || 1}
      />
    </div>
  );
}
