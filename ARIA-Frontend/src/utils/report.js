// Builds a self-contained, print-ready 1-page incident report and opens it in a new window.
// Independent of the app layout, so no navbar/sidebar/scroll-container clipping is possible.

const esc = v => String(v ?? '—')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function verdictLabel(a) {
  if (a.score >= 80) return 'ESCALATE';
  if (a.score >= 55) return 'MONITOR';
  return 'LOW PRIORITY';
}

export function buildReportHtml(a) {
  const procs = (a.topProcesses || []).map(p => {
    const ws = p.working_set_mb ?? p.WorkingSet64;
    return `<tr><td>${esc(p.pid ?? p.Id ?? p.PID)}</td><td>${esc(p.name || p.Name)}</td><td>${typeof ws === 'number' ? Math.round(ws) + ' MB' : esc(ws)}</td><td>${esc(p.path || p.Path)}</td></tr>`;
  }).join('') || '<tr><td colspan="4">No process context captured</td></tr>';

  const conns = (a.externalConnections || []).map(c =>
    `<tr><td>${esc(c.local_port ?? c.LocalPort)}</td><td>${esc(c.remote_address ?? c.RemoteAddress)}</td><td>${esc(c.remote_port ?? c.RemotePort)}</td><td>${esc(c.owning_process ?? c.pid ?? c.OwningProcess)}</td></tr>`
  ).join('') || '<tr><td colspan="4">No external connections observed</td></tr>';

  const mitre = (a.mitre || []).length
    ? `<h2>Correlated MITRE ATT&amp;CK Techniques</h2><p class="mono">${a.mitre.map(esc).join(' &nbsp;|&nbsp; ')}</p>` : '';

  const steps = (a.steps || []).map((s, i) => `<li>${esc(s)}</li>`).join('');

  const audit = [
    `<tr><td>${esc(a.time)}</td><td>Alert ingested and classified by ARIA (${esc(a.severity)})</td></tr>`,
    String(a.status).toUpperCase() === 'RESOLVED'
      ? `<tr><td>${esc(a.closedAt || 'RESOLVED')}</td><td>Closed by ${esc(a.closedBy || 'Analyst')} &middot; Disposition: <b>${esc(a.disposition)}</b>${a.reason ? ` (&ldquo;${esc(a.reason)}&rdquo;)` : ''}</td></tr>`
      : `<tr><td>—</td><td>Status: ${esc(a.status)} (open)</td></tr>`,
  ].join('');

  return `<!doctype html><html><head><meta charset="utf-8"><title>ARIA Report ${esc(a.id)}</title>
<style>
  @page { size: A4; margin: 12mm; }
  * { box-sizing: border-box; }
  body { font-family: Arial, Helvetica, sans-serif; color: #111; font-size: 11px; margin: 0; }
  h1 { font-size: 16px; margin: 0 0 4px; } h2 { font-size: 12px; text-transform: uppercase; margin: 12px 0 4px; border-bottom: 1px solid #999; padding-bottom: 2px; }
  .mono { font-family: Consolas, 'Courier New', monospace; }
  .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 2px 16px; margin: 6px 0; }
  .kpi { display: flex; gap: 24px; margin: 6px 0; padding: 6px 8px; border: 1px solid #999; }
  .kpi div b { display: block; font-size: 14px; }
  table { width: 100%; border-collapse: collapse; margin-top: 2px; }
  th, td { border: 1px solid #bbb; padding: 3px 5px; text-align: left; vertical-align: top; word-break: break-all; }
  th { background: #eee; } p { margin: 3px 0; line-height: 1.4; } ol { margin: 3px 0 0 18px; padding: 0; }
  .brand { font-size: 10px; color: #555; letter-spacing: .08em; }
</style></head><body>
  <div class="brand">ARIA &mdash; AUTOMATED INCIDENT TRIAGE REPORT</div>
  <h1>${esc(a.title)}</h1>
  <div class="meta mono">
    <span>Case ID: <b>${esc(a.id)}</b></span><span>Status: ${esc(a.status)}</span>
    <span>Host / IP: ${esc(a.agent)} / ${esc(a.ip)}</span><span>Ingested: ${esc(a.time)}</span>
  </div>
  <div class="kpi">
    <div>Risk Score<b>${esc(a.score)}/100</b></div>
    <div>Severity<b>${esc(a.severity)}</b></div>
    <div>Verdict<b>${verdictLabel(a)}</b></div>
    <div>Confidence<b>${esc(a.confidence)}</b></div>
  </div>
  <h2>Automated Triage Summary</h2><p>${esc(a.reasoning)}</p>
  <h2>Top Processes</h2>
  <table><thead><tr><th>PID</th><th>Process</th><th>Working Set</th><th>Path</th></tr></thead><tbody>${procs}</tbody></table>
  <h2>Active External Connections</h2>
  <table><thead><tr><th>Local Port</th><th>Remote Address</th><th>Remote Port</th><th>Owning PID</th></tr></thead><tbody>${conns}</tbody></table>
  ${mitre}
  <h2>Investigation Steps</h2><ol>${steps}</ol>
  <h2>Activity &amp; Disposition Audit Log</h2>
  <table><tbody>${audit}</tbody></table>
  <script>window.onload = function () { setTimeout(function () { window.focus(); window.print(); }, 250); };</script>
</body></html>`;
}

export function openReport(alert) {
  const w = window.open('', '_blank', 'width=900,height=1000');
  if (!w) { window.alert('Pop-up blocked: allow pop-ups to export the report.'); return; }
  w.document.open();
  w.document.write(buildReportHtml(alert));
  w.document.close();
}
