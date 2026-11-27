// ARIA API client + adapter.
// Maps rows from the backend `soc_alerts` table (served by frontend_api.py) into
// the view-model shape the Dashboard / Triage components render.

const API_BASE = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  if (!res.ok) throw new Error(`API ${res.status} ${res.statusText} on ${path}`);
  return res.json();
}

export const fetchHealth = () => request('/api/health');
export const fetchRawAlerts = () => request('/api/alerts');
export const fetchRawAlert = id => request(`/api/alerts/${id}`);

export const updateAlertStatus = (id, status, disposition = null, reason = null, closedBy = 'Analyst') =>
  request(`/api/alerts/${id}/status`, {
    method: 'PUT',
    body: JSON.stringify({ status, disposition, reason, closed_by: closedBy })
  });

export const resolveAlerts = (alertIds, disposition = 'True Positive', reason = '', closedBy = 'Analyst') => {
  const ids = Array.isArray(alertIds) ? alertIds : [alertIds];
  return request('/api/alerts/resolve', {
    method: 'PATCH',
    body: JSON.stringify({
      alert_ids: ids,
      disposition,
      reason,
      closed_by: closedBy,
    }),
  });
};

export const fetchAnalytics = () => request('/api/analytics');
export const fetchThreatIntel = (q = '') => request(`/api/threat-intel${q ? `?q=${encodeURIComponent(q)}` : ''}`);
// Settings are cached (30s) and in-flight requests are shared so StrictMode / multiple
// components never spam /api/settings.
let _settingsCache = null;
let _settingsAt = 0;
let _settingsInflight = null;
export const fetchSettings = () => {
  if (_settingsCache && Date.now() - _settingsAt < 30000) return Promise.resolve(_settingsCache);
  if (_settingsInflight) return _settingsInflight;
  _settingsInflight = request('/api/settings')
    .then(s => { _settingsCache = s; _settingsAt = Date.now(); return s; })
    .finally(() => { _settingsInflight = null; });
  return _settingsInflight;
};
export const updateSettings = settings =>
  request('/api/settings', { method: 'POST', body: JSON.stringify(settings) })
    .then(r => { _settingsCache = r.settings || null; _settingsAt = Date.now(); return r; });

export const ALERT_PREFIX = 'ARIA-';
export const toUiId = dbId => `${ALERT_PREFIX}${dbId}`;
export const toDbId = uiId => Number(String(uiId).replace(ALERT_PREFIX, ''));

function parseJsonSafe(raw) {
  if (!raw) return {};
  if (typeof raw === 'object') return raw;
  try {
    return JSON.parse(String(raw).replace(/^```json\s*|```$/g, '').trim());
  } catch {
    return { _raw: String(raw) };
  }
}

function normaliseScore(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return 0;
  return Math.round(n <= 1 && n > 0 ? n * 100 : Math.min(Math.max(n, 0), 100));
}

export function severityFromScore(score) {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Medium';
  return 'Low';
}

export function verdictFromScore(score) {
  if (score >= 80) return 'escalate';
  if (score >= 55) return 'monitor';
  return 'resolve';
}

function formatTime(ts) {
  if (!ts) return '--:--:--';
  const d = new Date(String(ts).replace(/([+-]\d{2})(\d{2})$/, '$1:$2'));
  return Number.isNaN(d.getTime()) ? String(ts) : d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

export function adaptAlert(row) {
  const rag = parseJsonSafe(row.rag_analysis);
  const score = normaliseScore(rag.risk_score != null ? rag.risk_score : (row.severity === 'HIGH' ? 75 : 50));
  const summary = rag.incident_summary || {};
  const iocObj = rag.iocs_extracted || {};

  // Host Context: top_processes and external_connections
  const hostContext = row.host_context || rag.host_context || {};
  const topProcesses = hostContext.top_processes || [];
  const externalConnections = hostContext.external_connections || [];

  // Telemetry Snapshot
  const featureSnapshot = row.feature_snapshot || (iocObj.feature_snapshot) || rag.feature_snapshot || {};

  // Deterministic Alert Title Construction:
  // Resource Anomaly · [agent_name] · Top PID: [process_name] ([pid]) · TCP_APS: [val]
  const agentName = row.agent_name || 'Unknown host';

  let topPidStr = 'Process unreported';
  if (topProcesses && topProcesses.length > 0) {
    const topProc = topProcesses[0];
    const pName = topProc.name || topProc.Name || 'proc';
    const pid = topProc.pid ?? topProc.Id ?? topProc.PID ?? 'N/A';
    topPidStr = `Top PID: ${pName} (${pid})`;
  } else if (iocObj.pid || iocObj.process_id) {
    topPidStr = `Top PID: ${iocObj.process_name || 'proc'} (${iocObj.pid || iocObj.process_id})`;
  }

  // Extract TCP_APS metric
  let tcpApsVal = featureSnapshot.Network_I_ActiveNIC_TCP_APS;
  if (tcpApsVal == null) {
    const combinedObs = [
      ...(rag.evidence_assessment?.observed || []),
      ...(summary.why_flagged || [])
    ];
    for (const line of combinedObs) {
      const match = String(line).match(/(?:TCP_APS|TCP activity rate|metric recorded)[:\s]+([\d,]+)/i);
      if (match) {
        tcpApsVal = match[1].replace(/,/g, '');
        break;
      }
    }
  }
  const tcpApsFormatted = tcpApsVal != null
    ? Number(tcpApsVal).toLocaleString()
    : 'unreported';

  const title = rag.case_title || `Resource Anomaly · ${agentName} · ${topPidStr} · TCP_APS: ${tcpApsFormatted}`;

  const iocs = Object.entries(iocObj)
    .filter(([k, v]) => k !== 'feature_snapshot' && v != null && v !== '')
    .map(([, v]) => String(v));
  (summary.why_flagged || []).forEach(w => iocs.push(String(w)));

  const evidence = (rag.rag_threat_intel_context || []).map((e, i) => ({
    source: e.source || `Retrieved document ${i + 1}`,
    tier: i === 0 ? 'PRIMARY' : 'SUPPORTING',
    score: e.score != null ? Number(e.score).toFixed(2) : '—',
    body: e.description || e.content || '',
  }));

  const steps = (rag.investigation_priority || [])
    .slice()
    .sort((a, b) => (a.priority || 99) - (b.priority || 99))
    .map(p => p.action)
    .filter(Boolean);

  const rawMitre = (rag.mitre_techniques && rag.mitre_techniques.length
    ? rag.mitre_techniques
    : rag.mitre_validation?.alert_associated || []).map(String);
  // Filter out any "None mapped" or empty items
  const mitre = rawMitre.filter(m => m && !m.toLowerCase().includes('none') && !m.toLowerCase().includes('not established'));

  return {
    id: toUiId(row.id),
    dbId: row.id,
    queueId: row.alert_id,
    title,
    time: formatTime(row.timestamp),
    timestamp: row.timestamp,
    ip: row.agent_ip || iocObj.agent_ip || 'Unreported',
    agent: agentName,
    source: rag.demo ? 'Demo fixture' : 'ARIA ML',
    sourceLabel: rag.demo ? 'Demo fixture' : 'ARIA ML',
    severity: severityFromScore(score),
    verdict: verdictFromScore(score),
    score,
    status: row.status || 'NEW',
    owner: row.owner || null,
    disposition: row.disposition || '',
    reason: row.resolve_reason || row.reason || '',
    closedBy: row.closed_by || '',
    closedAt: row.closed_at ? formatTime(row.closed_at) : null,
    confidence: summary.confidence || 'Moderate',
    triageAction: rag.triage_action || 'Tier-1 Investigation / Monitor Host',
    mitre,
    iocs: [...new Set(iocs)],
    evidence,
    reasoning: summary.what_happened || rag.ai_reasoning || row.ml_reasoning || 'Awaiting automated triage synthesis…',
    mlReasoning: row.ml_reasoning,
    steps: steps.length ? steps : ['Review host telemetry and investigate active threads/processes on the flagged host'],
    cautions: rag.analyst_cautions || [],
    validationWarnings: !!row.validation_warnings,
    raw: rag,
    telemetry: featureSnapshot,
    hostContext,
    topProcesses,
    externalConnections,
    occurrenceCount: row.occurrence_count || 1,
  };
}

let _alertsInflight = null;
export function fetchAlerts() {
  if (_alertsInflight) return _alertsInflight;
  _alertsInflight = fetchRawAlerts()
    .then(rows => rows.map(adaptAlert).sort((a, b) => b.dbId - a.dbId))
    .finally(() => { _alertsInflight = null; });
  return _alertsInflight;
}
