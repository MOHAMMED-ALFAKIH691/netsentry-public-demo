let latestReportId = null;
const demoOnly = document.body.dataset.demoOnly === 'true';
const $ = (id) => document.getElementById(id);

function setStatus(message, isError=false) {
  $('scan-status').textContent = message;
  $('scan-status').className = isError ? 'status-text error' : 'muted status-text';
}
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
function showError(elementId, message) {
  $(elementId).innerHTML = `<div class="error">${esc(message)}</div>`;
}
function setMetrics(data) {
  $('metric-target').textContent = data.target || '—';
  $('metric-ports').textContent = data.open_port_count ?? '—';
  $('metric-score').textContent = data.risk_score ?? '—';
  $('metric-level').textContent = data.risk_level ? `${data.risk_level} RISK` : 'Awaiting assessment';
  $('metric-cves').textContent = data.cves ? data.cves.length : '—';
}
function renderAssessment(data) {
  latestReportId = data.report_id || null;
  $('download-btn').disabled = !latestReportId;
  setMetrics(data);
  $('ports-result').innerHTML = data.open_ports?.length ? `
    <div style="overflow-x:auto"><table class="data-table"><thead><tr><th>PORT</th><th>SERVICE</th><th>VERSION</th><th>STATE</th></tr></thead><tbody>
    ${data.open_ports.map(p => `<tr><td>${esc(p.port)}/${esc(p.protocol)}</td><td>${esc(p.service)}</td><td>${esc([p.product,p.version,p.extra].filter(Boolean).join(' ') || '—')}</td><td><span class="pill ${p.state==='open'?'open':'closed'}">${esc(p.state)}</span></td></tr>`).join('')}
    </tbody></table></div>` : '<div class="result-placeholder">No open ports were detected in the selected fast-scan range.</div>';
  $('risk-result').innerHTML = `<div class="row-top"><span>Overall score</span><span>${esc(data.risk_score)} / 10 · ${esc(data.risk_level)}</span></div>` + (data.risk_items?.length ? data.risk_items.map(r => `<div class="risk-row"><div class="row-top"><span>${esc(r.service)} · ${esc(r.port)}/tcp</span><span class="level ${esc(r.level)}">${esc(r.level)}</span></div><div class="row-detail">${esc(r.reason)}</div></div>`).join('') : '<div class="row-detail" style="padding-top:12px">No scored exposure factors detected in the scanned ports.</div>');
  $('cve-result').innerHTML = `<div class="row-detail" style="margin-bottom:10px">${esc(data.cve_status || '')}</div>` + (data.cves?.length ? data.cves.map(c => `<div class="cve-card"><div class="row-top"><span>${esc(c.id)}</span><span class="pill">${c.cvss == null ? 'CVSS N/A' : 'CVSS '+esc(c.cvss)}</span></div><div class="row-detail">${esc(c.description)}</div><div class="row-detail">${esc(c.product_query)} · ${esc(c.match_type)}</div></div>`).join('') : '<div class="row-detail">No potential CVE matches are displayed. A keyword lookup result, when present, must be validated against the exact affected product, version, and configuration.</div>');
  const sim = data.simulation || {};
  $('simulation-result').innerHTML = `<div class="pill">${esc(sim.mode || 'Simulation only')}</div>` + (sim.items?.length ? sim.items.map(i => `<div class="sim-row"><div class="row-top"><span>${esc(i.service)} · ${esc(i.port)}/tcp</span><span class="level ${esc(i.risk)}">${esc(i.risk)}</span></div><div class="row-detail">${esc(i.result)}</div></div>`).join('') : '<div class="row-detail" style="padding-top:12px">No common authentication-related services were found open. No authentication attempts were made.</div>');
  $('recommendations').innerHTML = (data.recommendations || []).map(r => `<div class="recommendation">${esc(r)}</div>`).join('') || '<div class="result-placeholder">No recommendations available.</div>';
  setStatus(data.demo ? 'Sample demonstration loaded — no network traffic sent.' : 'Assessment completed.');
  if (data.demo) $('metric-target').textContent = data.target;
}
async function postJSON(url, payload) {
  const response = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}
$('demo-btn').addEventListener('click', async () => {
  setStatus('Loading sample data…');
  try { const data = await postJSON('/api/demo', {}); renderAssessment(data); }
  catch (e) { setStatus(e.message, true); }
});
$('scan-btn').addEventListener('click', async () => {
  if (!$('authorized').checked) { setStatus('Please confirm authorization before scanning.', true); return; }
  setStatus('Running Nmap service scan…'); $('scan-btn').disabled = true;
  try {
    const data = await postJSON('/api/scan', {target:$('target').value, authorized:true, include_cve:$('include-cve').checked});
    renderAssessment(data);
  } catch (e) { showError('ports-result', e.message); setStatus(e.message, true); }
  finally { $('scan-btn').disabled = demoOnly; }
});
$('discover-btn').addEventListener('click', async () => {
  if (!$('authorized').checked) { showError('discovery-result', 'Confirm that you are authorized to assess this network.'); return; }
  $('discovery-result').textContent = 'Discovering hosts…'; $('discover-btn').disabled = true;
  try {
    const data = await postJSON('/api/discover', {network:$('network').value, authorized:true});
    $('discovery-result').innerHTML = data.hosts.length ? `<div class="host-list">${data.hosts.map(h=>`<span class="host-chip">${esc(h.ip)} · ${esc(h.status)}</span>`).join('')}</div><div class="row-detail" style="margin-top:10px">${data.count} active host(s) in ${esc(data.network)}.</div>` : 'No active hosts were detected in this network.';
  } catch (e) { showError('discovery-result', e.message); }
  finally { $('discover-btn').disabled = demoOnly; }
});
$('download-btn').addEventListener('click', () => {
  if (latestReportId) window.location.href = `/api/report/${encodeURIComponent(latestReportId)}`;
});
