import React, { useEffect, useState } from 'react';
import { TopNav } from '../components/ui.jsx';
import { fetchSettings, updateSettings } from '../api/ariaClient.js';
import { Sliders, Save, RotateCcw, Check, Shield, Bell, User, Cpu } from 'lucide-react';

export default function Settings() {
  const [config, setConfig] = useState({
    escalate_threshold: 80,
    monitor_threshold: 55,
    cooldown_seconds: 120,
    analyst_name: 'Analyst',
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    fetchSettings()
      .then(res => {
        if (res) setConfig(res);
      })
      .catch(err => console.error('Failed to load settings:', err))
      .finally(() => setLoading(false));
  }, []);

  const handleChange = (field, value) => {
    setConfig(prev => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      const payload = {
        escalate_threshold: Number(config.escalate_threshold),
        monitor_threshold: Number(config.monitor_threshold),
        cooldown_seconds: Number(config.cooldown_seconds),
        analyst_name: String(config.analyst_name).trim() || 'Analyst',
      };
      const res = await updateSettings(payload);
      if (res && res.settings) {
        setConfig(res.settings);
      }
      setToast('Configuration successfully saved to aria_config.json');
      setTimeout(() => setToast(null), 4000);
    } catch (err) {
      console.error('Failed to save settings:', err);
      alert('Error updating configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleResetDefaults = () => {
    setConfig({
      escalate_threshold: 80,
      monitor_threshold: 55,
      cooldown_seconds: 120,
      analyst_name: 'Analyst',
    });
  };

  return (
    <div className="app-layout">
      <TopNav />

      {/* KPI Header Strip */}
      <div className="kpi-strip">
        <div className="kpi-item">
          <span className="kpi-label">Config File</span>
          <span className="kpi-val mono" style={{ fontSize: 13 }}>aria_config.json</span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Escalate Threshold</span>
          <span className="kpi-val mono" style={{ color: 'var(--red)' }}>≥ {config.escalate_threshold}</span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Monitor Threshold</span>
          <span className="kpi-val mono" style={{ color: 'var(--amber)' }}>≥ {config.monitor_threshold}</span>
        </div>
        <div className="kpi-item">
          <span className="kpi-label">Deduplication Cooldown</span>
          <span className="kpi-val mono">{config.cooldown_seconds}s</span>
        </div>
      </div>

      <main style={{ flex: 1, overflowY: 'auto', padding: '24px 32px', maxWidth: 800 }}>
        <div style={{ marginBottom: 24 }}>
          <h1 style={{ fontSize: 18, fontWeight: 600, margin: '0 0 6px 0' }}>SOC Pipeline Configuration</h1>
          <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
            Manage risk scoring thresholds, ingestion deduplication intervals, and analyst attribution.
          </p>
        </div>

        {loading ? (
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
            Loading configuration...
          </div>
        ) : (
          <form onSubmit={handleSave}>
            {/* Risk Scoring Section */}
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: 20, marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <Shield size={16} style={{ color: 'var(--blue)' }} />
                <h2 style={{ fontSize: 13, textTransform: 'uppercase', letterSpacing: '0.04em', margin: 0 }}>
                  Risk Scoring & Auto-Triage Thresholds
                </h2>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
                <div>
                  <label style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 6 }}>
                    Escalate Threshold (Score 0-100)
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={config.escalate_threshold}
                    onChange={e => handleChange('escalate_threshold', e.target.value)}
                    style={{ width: '100%', padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)', color: 'white', borderRadius: 2 }}
                    required
                  />
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginTop: 4 }}>
                    Alerts with risk scores at or above this threshold trigger Tier-2 escalation recommendations.
                  </span>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 6 }}>
                    Monitor Threshold (Score 0-100)
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={config.monitor_threshold}
                    onChange={e => handleChange('monitor_threshold', e.target.value)}
                    style={{ width: '100%', padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)', color: 'white', borderRadius: 2 }}
                    required
                  />
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginTop: 4 }}>
                    Alerts between Monitor and Escalate thresholds are assigned for active surveillance.
                  </span>
                </div>
              </div>
            </div>

            {/* Deduplication Cooldown Section */}
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: 20, marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <Cpu size={16} style={{ color: 'var(--amber)' }} />
                <h2 style={{ fontSize: 13, textTransform: 'uppercase', letterSpacing: '0.04em', margin: 0 }}>
                  Telemetry Deduplication & Throttling
                </h2>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 6 }}>
                  Pre-Queue Cooldown Window (Seconds)
                </label>
                <input
                  type="number"
                  min="10"
                  max="3600"
                  value={config.cooldown_seconds}
                  onChange={e => handleChange('cooldown_seconds', e.target.value)}
                  style={{ width: '100%', maxWidth: 300, padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)', color: 'white', borderRadius: 2 }}
                  required
                />
                <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginTop: 4 }}>
                  Identical host & attack class anomalies arriving within this window increment occurrence count instead of spawning duplicate LLM triage jobs.
                </span>
              </div>
            </div>

            {/* Analyst Profile Attribution */}
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: 20, marginBottom: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <User size={16} style={{ color: 'var(--green)' }} />
                <h2 style={{ fontSize: 13, textTransform: 'uppercase', letterSpacing: '0.04em', margin: 0 }}>
                  Analyst Profile & Attribution
                </h2>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 6 }}>
                  Active Analyst Handle
                </label>
                <input
                  type="text"
                  value={config.analyst_name}
                  onChange={e => handleChange('analyst_name', e.target.value)}
                  style={{ width: '100%', maxWidth: 300, padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)', color: 'white', borderRadius: 2 }}
                  required
                />
                <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginTop: 4 }}>
                  Used as the default <span className="mono">closed_by</span> signature for alert disposition and resolution audits.
                </span>
              </div>
            </div>

            {/* Action Bar */}
            <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end', alignItems: 'center' }}>
              <button
                type="button"
                className="btn"
                onClick={handleResetDefaults}
                style={{ display: 'flex', alignItems: 'center', gap: 6 }}
              >
                <RotateCcw size={13} />
                Reset Defaults
              </button>
              <button
                type="submit"
                className="btn primary"
                disabled={saving}
                style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 20px' }}
              >
                <Save size={14} />
                {saving ? 'Saving...' : 'Save Configuration'}
              </button>
            </div>
          </form>
        )}

        {/* Toast Notification */}
        {toast && (
          <div className="toast" style={{ display: 'flex', alignItems: 'center', gap: 8, borderColor: 'var(--green)' }}>
            <Check size={16} style={{ color: 'var(--green)' }} />
            <span>{toast}</span>
          </div>
        )}
      </main>
    </div>
  );
}
