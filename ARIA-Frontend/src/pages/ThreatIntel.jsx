import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { TopNav } from '../components/ui.jsx';
import { fetchThreatIntel } from '../api/ariaClient.js';
import { Search, ExternalLink, ShieldCheck, Crosshair, Filter } from 'lucide-react';

function cleanDescription(text = '') {
  return String(text)
    .replace(/\(Citation:[^)]*\)/g, '')
    .replace(/<\/?[a-zA-Z][^>]*>/g, '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

export default function ThreatIntel() {
  const [query, setQuery] = useState('');
  const [techniques, setTechniques] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filterObservedOnly, setFilterObservedOnly] = useState(false);
  const nav = useNavigate();

  const searchIntel = async (q = '') => {
    setLoading(true);
    try {
      const res = await fetchThreatIntel(q);
      setTechniques(res.techniques || []);
      setTotalCount(res.total || 0);
    } catch (err) {
      console.error('Failed to fetch threat intel:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      searchIntel(query);
    }, 250);
    return () => clearTimeout(timer);
  }, [query]);

  const displayedTechniques = filterObservedOnly
    ? techniques.filter(t => t.observed_count > 0)
    : techniques;

  const handleTechniqueClick = (techniqueId) => {
    // Navigate to dashboard with search/technique filter
    nav(`/dashboard?technique=${encodeURIComponent(techniqueId)}`);
  };

  return (
    <div className="app-layout">
      <TopNav />

      {/* KPI Header Strip */}
      <div className="kpi-strip">
        <div className="kpi-item">
          <span className="kpi-label">Total ATT&CK Techniques</span>
          <span className="kpi-val">{totalCount || 697}</span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Active Techniques Observed</span>
          <span className="kpi-val" style={{ color: 'var(--amber)' }}>
            {techniques.filter(t => t.observed_count > 0).length}
          </span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Total Correlated Alerts</span>
          <span className="kpi-val">
            {techniques.reduce((sum, t) => sum + (t.observed_count || 0), 0)}
          </span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Knowledge Base Status</span>
          <span className="kpi-val" style={{ color: 'var(--green)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
            <ShieldCheck size={14} /> Synchronized
          </span>
        </div>
      </div>

      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Search & Filter Toolbar */}
        <div className="table-toolbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1, maxWidth: 500 }}>
            <div style={{ position: 'relative', width: '100%' }}>
              <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Search by ID (e.g., T1499, T1059), Name, or Tactic..."
                style={{
                  width: '100%',
                  padding: '6px 12px 6px 32px',
                  background: 'var(--bg)',
                  border: '1px solid var(--border)',
                  color: 'white',
                  borderRadius: 2,
                  fontSize: 12,
                }}
              />
            </div>
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button
              className={`btn ${filterObservedOnly ? 'primary' : ''}`}
              onClick={() => setFilterObservedOnly(!filterObservedOnly)}
              style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            >
              <Filter size={12} />
              {filterObservedOnly ? 'Showing Observed Only' : 'Filter: Observed in SOC'}
            </button>
          </div>
        </div>

        {/* MITRE ATT&CK Matrix Explorer Table */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th style={{ width: '100px' }}>Technique ID</th>
                <th style={{ width: '220px' }}>Name</th>
                <th style={{ width: '180px' }}>Local Alerts</th>
                <th style={{ width: '160px' }}>Tactics</th>
                <th>Description</th>
                <th style={{ width: '70px', textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {loading && displayedTechniques.length === 0 ? (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                    Searching MITRE ATT&CK Knowledge Base...
                  </td>
                </tr>
              ) : displayedTechniques.length === 0 ? (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                    No matching MITRE techniques found for query "{query}".
                  </td>
                </tr>
              ) : (
                displayedTechniques.map(tech => {
                  const hasObserved = tech.observed_count > 0;
                  return (
                    <tr key={tech.id} style={{ background: hasObserved ? 'rgba(59, 130, 246, 0.04)' : undefined }}>
                      <td className="mono" style={{ fontWeight: 600, color: hasObserved ? 'var(--blue)' : 'inherit' }}>
                        {tech.id}
                      </td>
                      <td style={{ fontWeight: 600 }}>{tech.name}</td>
                      <td>
                        {hasObserved ? (
                          <button
                            onClick={() => handleTechniqueClick(tech.id)}
                            style={{
                              background: 'rgba(239, 68, 68, 0.15)',
                              border: '1px solid var(--red)',
                              color: 'var(--red)',
                              padding: '2px 8px',
                              borderRadius: 2,
                              fontSize: 11,
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 4,
                            }}
                            title={`Filter queue by ${tech.id}`}
                          >
                            <Crosshair size={11} />
                            Observed in {tech.observed_count} local alert{tech.observed_count === 1 ? '' : 's'}
                          </button>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>0 local alerts</span>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {(tech.tactics || []).slice(0, 2).map(tac => (
                            <span
                              key={tac}
                              style={{
                                background: 'var(--elevated)',
                                padding: '1px 6px',
                                borderRadius: 2,
                                fontSize: 10,
                                textTransform: 'uppercase',
                                color: 'var(--text-secondary)',
                              }}
                            >
                              {tac}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: 12, whiteSpace: 'normal', maxWidth: 450 }}>
                        {cleanDescription(tech.description)}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <a
                          href={`https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}`}
                          target="_blank"
                          rel="noreferrer"
                          className="btn"
                          style={{ padding: '3px 8px', fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 4 }}
                          title="Open official MITRE ATT&CK reference"
                        >
                          <ExternalLink size={11} />
                          MITRE
                        </a>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
