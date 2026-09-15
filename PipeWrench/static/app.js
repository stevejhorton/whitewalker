const $ = (selector) => document.querySelector(selector);
const state = { devices: [], running: false, current: null, snapshotId: '', historical: false, batchTimer: null, capacityTimer: null };
const deviceSelect = $('#deviceSelect');
const runButton = $('#runButton');
const notice = $('#notice');
const resultGrid = $('#resultGrid');

async function request(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function message(text = '', isError = false) {
  notice.textContent = text;
  notice.classList.toggle('error', isError);
}

function populateDevices(devices, selected = '') {
  state.devices = devices;
  deviceSelect.replaceChildren(new Option(devices.length ? 'Choose a headend…' : 'Add a headend to begin', ''));
  devices.forEach((device) => deviceSelect.append(new Option(device, device)));
  deviceSelect.value = selected && devices.includes(selected) ? selected : '';
  const checks = $('#deviceChecks'); checks.replaceChildren();
  devices.forEach((device) => {
    const label = document.createElement('label'); const input = document.createElement('input');
    input.type = 'checkbox'; input.value = device; label.append(input, document.createTextNode(device)); checks.append(label);
  });
}

function fillSelect(select, items, placeholder, valueKey, labelFn) {
  const selected = select.value; select.replaceChildren(new Option(placeholder, ''));
  items.forEach((item) => select.append(new Option(labelFn(item), item[valueKey])));
  if ([...select.options].some((option) => option.value === selected)) select.value = selected;
}

async function refreshSaved() {
  const [snapshotData, baselineData, batchData, capacityData] = await Promise.all([
    request('/api/snapshots'), request('/api/baselines'), request('/api/batches'), request('/api/capacity-reports'),
  ]);
  fillSelect($('#snapshotSelect'), snapshotData.snapshots, 'Open a saved snapshot…', 'snapshot_id', (item) => `${item.captured_at} · ${item.device} · ${item.action}`);
  [$('#baselineSelect'), $('#batchBaseline')].forEach((select) => fillSelect(select, baselineData.baselines,
    select.id === 'batchBaseline' ? 'Compliance rules only' : 'Choose gold profile…', 'baseline_id', (item) => `${item.name} · ${item.device}`));
  fillSelect($('#batchSelect'), batchData.batches, 'Open a prior walk…', 'batch_id',
    (item) => `${item.created_at} · ${item.completed}/${item.total} · ${item.status}`);
  fillSelect($('#capacitySelect'), capacityData.reports, 'Open a prior report…', 'report_id',
    (item) => `${item.created_at} · ${item.completed}/${item.total} · ${item.status}`);
}

async function initialize() {
  try {
    const [deviceData, status] = await Promise.all([request('/api/devices'), request('/api/status')]);
    populateDevices(deviceData.devices);
    $('#credentialDot').className = status.credentials.ready ? 'ready' : 'error';
    $('#credentialState').textContent = status.credentials.ready ? 'Credentials found' : 'Credentials missing';
    if (!status.credentials.ready) message('Create ~/creds/un.txt and ~/creds/pw.txt, or update CREDENTIAL_DIR in VARS.', true);
    $('#tlsDot').className = status.tls_verify ? 'ready' : 'warning';
    $('#tlsState').textContent = status.tls_verify ? 'Certificate verified' : 'Management cert allowed';
    await refreshSaved();
  } catch (error) { message(error.message, true); }
}

$('#addToggle').addEventListener('click', () => {
  const panel = $('#addPanel'); panel.hidden = !panel.hidden; if (!panel.hidden) $('#newDevice').focus();
});
$('#saveDevice').addEventListener('click', async () => {
  const input = $('#newDevice'); const hostname = input.value.trim();
  if (!hostname) return message('Enter a headend short name.', true);
  try {
    const payload = await request('/api/devices', { method: 'POST', body: JSON.stringify({ hostname }) });
    populateDevices(payload.devices, payload.added); input.value = ''; $('#addPanel').hidden = true;
    message(`${payload.added} saved to the local headend cache.`);
  } catch (error) { message(error.message, true); }
});
$('#newDevice').addEventListener('keydown', (event) => { if (event.key === 'Enter') $('#saveDevice').click(); });

function showWorkspace(name) {
  const inspections = name === 'inspections';
  $('#inspectionPane').hidden = !inspections; $('#toolsPane').hidden = inspections;
  $('#inspectionTab').classList.toggle('active', inspections); $('#toolsTab').classList.toggle('active', !inspections);
  $('#inspectionTab').setAttribute('aria-selected', String(inspections)); $('#toolsTab').setAttribute('aria-selected', String(!inspections));
}

$('#inspectionTab').addEventListener('click', () => showWorkspace('inspections'));
$('#toolsTab').addEventListener('click', () => showWorkspace('tools'));

runButton.addEventListener('click', async () => {
  if (state.running) return;
  const device = deviceSelect.value; const action = document.querySelector('input[name="action"]:checked').value;
  if (!device) return message('Choose a headend first.', true);
  setRunning(true, device, action);
  try {
    const payload = await request('/api/run', { method: 'POST', body: JSON.stringify({ device, action }) });
    showPayload(payload, false); message(`Inspection completed for ${device}. Save it when you want it in Git history.`);
  } catch (error) {
    resultGrid.hidden = true; $('#metricGrid').hidden = true; $('#emptyState').hidden = false;
    $('#resultsTitle').textContent = 'Inspection failed'; message(error.message, true);
  } finally { setRunning(false); }
});

function setRunning(running, device = '', action = '') {
  state.running = running; runButton.disabled = running;
  runButton.querySelector('span').textContent = running ? 'Inspecting…' : 'Run inspection';
  if (!running) return;
  message(`Connecting to ${device}:2002…`); $('#resultsTitle').textContent = `Inspecting ${device}`;
  $('#emptyState').hidden = true; $('#metricGrid').hidden = true; resultGrid.hidden = false;
  resultGrid.innerHTML = loadingCards(action === 'health' ? 8 : 12); $('#summary').hidden = true;
  $('#saveResults').hidden = true; $('#historicalBanner').hidden = true; $('#comparisonPanel').hidden = true;
}

function loadingCards(count) {
  return Array.from({ length: count }, (_, index) => `<div class="result-card" style="height:58px;opacity:${1 - index * .05}"></div>`).join('');
}

function showPayload(payload, historical) {
  state.current = payload; state.snapshotId = payload.snapshot_id || ''; state.historical = historical;
  const title = payload.action === 'health' ? 'Health snapshot' : 'Standards review';
  $('#resultsTitle').textContent = `${title} · ${payload.device}`;
  $('#okCount').textContent = payload.summary.ok; $('#warnCount').textContent = payload.summary.warning;
  $('#errorCount').textContent = payload.summary.error; $('#summary').hidden = false;
  $('#emptyState').hidden = true; resultGrid.hidden = false; renderMetrics(payload.metrics || []); renderResults(payload.results || []);
  $('#saveResults').hidden = historical; $('#goldToggle').hidden = !state.snapshotId;
  $('#historicalBanner').hidden = !historical;
  $('#historicalTime').textContent = historical ? `${payload.captured_at} · PipeWrench ${payload.pipewrench_version}` : '';
  $('#comparisonPanel').hidden = true; $('#goldPanel').hidden = true;
  $('#compareButton').disabled = !state.snapshotId || !$('#baselineSelect').value;
}

function renderResults(results) {
  resultGrid.replaceChildren();
  results.forEach((result) => {
    const fragment = $('#resultTemplate').content.cloneNode(true);
    const card = fragment.querySelector('.result-card'); const heading = fragment.querySelector('.result-heading');
    const body = fragment.querySelector('.result-body'); card.dataset.status = result.status;
    fragment.querySelector('.result-name').textContent = result.label;
    fragment.querySelector('.result-command').textContent = result.command || result.status.toUpperCase();
    fragment.querySelector('pre').textContent = result.output || result.detail || 'No additional detail.';
    heading.addEventListener('click', () => {
      const expanded = heading.getAttribute('aria-expanded') === 'true'; heading.setAttribute('aria-expanded', String(!expanded)); body.hidden = expanded;
    });
    resultGrid.append(fragment);
  });
}

function renderMetrics(metrics) {
  const grid = $('#metricGrid'); grid.replaceChildren(); grid.hidden = !metrics.length;
  metrics.forEach((metric) => {
    const card = document.createElement('article'); card.className = 'metric-card';
    const label = document.createElement('span'); label.textContent = metric.label;
    const value = document.createElement('strong'); value.textContent = metric.value;
    const detail = document.createElement('small'); detail.textContent = metric.detail;
    card.append(label, value, detail); grid.append(card);
  });
}

$('#saveResults').addEventListener('click', async () => {
  if (!state.current) return;
  try {
    const saved = await request('/api/snapshots', { method: 'POST', body: JSON.stringify(state.current) });
    state.snapshotId = saved.snapshot_id; $('#saveResults').hidden = true; $('#goldToggle').hidden = false;
    await refreshSaved(); message(`Snapshot ${saved.snapshot_id} saved for Git archival.`);
  } catch (error) { message(error.message, true); }
});

$('#snapshotSelect').addEventListener('change', async (event) => {
  if (!event.target.value) return;
  try { showPayload(await request(`/api/snapshots/${event.target.value}`), true); message('Viewing saved historical data.'); }
  catch (error) { message(error.message, true); }
});
$('#baselineSelect').addEventListener('change', () => { $('#compareButton').disabled = !state.snapshotId || !$('#baselineSelect').value; });
$('#compareButton').addEventListener('click', async () => {
  try {
    const comparison = await request('/api/compare', { method: 'POST', body: JSON.stringify({ snapshot_id: state.snapshotId, baseline_id: $('#baselineSelect').value }) });
    const panel = $('#comparisonPanel'); panel.hidden = false;
    panel.innerHTML = comparison.matched ? `<strong>✓ Matches ${escapeHtml(comparison.baseline_name)}</strong>` : `<strong>${comparison.findings.length} gold-standard differences</strong><ul>${comparison.findings.map((item) => `<li>${escapeHtml(item.label)} — ${escapeHtml(item.output)}</li>`).join('')}</ul>`;
  } catch (error) { message(error.message, true); }
});

$('#goldToggle').addEventListener('click', () => {
  $('#goldPanel').hidden = !$('#goldPanel').hidden;
  if (!$('#goldPanel').hidden) $('#goldPlatform').value = state.current.platform || '';
});
$('#saveGold').addEventListener('click', async () => {
  try {
    const baseline = await request('/api/baselines', { method: 'POST', body: JSON.stringify({ snapshot_id: state.snapshotId, platform: $('#goldPlatform').value, location: $('#goldLocation').value }) });
    $('#goldPanel').hidden = true; await refreshSaved(); message(`${baseline.name} is now the gold profile.`);
  } catch (error) { message(error.message, true); }
});

$('#selectAll').addEventListener('click', () => document.querySelectorAll('#deviceChecks input').forEach((input) => { input.checked = true; }));
$('#clearAll').addEventListener('click', () => document.querySelectorAll('#deviceChecks input').forEach((input) => { input.checked = false; }));
$('#batchButton').addEventListener('click', async () => {
  const devices = [...document.querySelectorAll('#deviceChecks input:checked')].map((input) => input.value);
  if (!devices.length) return message('Select at least one headend for the walk.', true);
  try {
    const job = await request('/api/batches', { method: 'POST', body: JSON.stringify({ devices, action: 'standards', baseline_id: $('#batchBaseline').value }) });
    $('#batchButton').disabled = true; pollBatch(job.batch_id);
  } catch (error) { message(error.message, true); }
});

async function pollBatch(batchId) {
  clearTimeout(state.batchTimer);
  try {
    const job = await request(`/api/batches/${batchId}`);
    const errors = job.results.filter((item) => item.error).length;
    const reviews = job.results.reduce((count, item) => count + (item.summary?.warning || 0), 0);
    const anomalies = job.results.reduce((count, item) => count + (item.comparison?.findings?.length || 0), 0);
    $('#batchStatus').textContent = `${job.status === 'completed' ? 'Completed' : 'Running'}: ${job.completed}/${job.total} headends · ${reviews} compliance reviews · ${anomalies} gold differences · ${errors} connection errors`;
    renderBatch(job);
    if (job.status === 'completed') { $('#batchButton').disabled = false; await refreshSaved(); return; }
    state.batchTimer = setTimeout(() => pollBatch(batchId), 3000);
  } catch (error) { $('#batchStatus').textContent = error.message; $('#batchButton').disabled = false; }
}

$('#batchSelect').addEventListener('change', async (event) => {
  if (!event.target.value) return;
  try { renderBatch(await request(`/api/batches/${event.target.value}`)); }
  catch (error) { message(error.message, true); }
});

function renderBatch(job) {
  const report = $('#batchReport'); report.hidden = false; report.replaceChildren();
  job.results.forEach((item) => {
    const row = document.createElement('div'); row.className = 'batch-result';
    const target = document.createElement(item.snapshot_id ? 'button' : 'strong'); target.textContent = item.device;
    if (item.snapshot_id) target.addEventListener('click', async () => {
      try { showPayload(await request(`/api/snapshots/${item.snapshot_id}`), true); window.scrollTo({ top: $('.results').offsetTop, behavior: 'smooth' }); }
      catch (error) { message(error.message, true); }
    });
    const summary = document.createElement('span');
    summary.textContent = item.error ? 'ERROR' : `${item.summary.warning} review · ${item.summary.error} errors`;
    const detail = document.createElement('span');
    const labels = item.comparison?.findings?.map((finding) => finding.label) || [];
    detail.textContent = item.error || (labels.length ? `Gold differences: ${labels.join(', ')}` : (item.comparison ? 'Matches gold' : 'Compliance only'));
    row.append(target, summary, detail); report.append(row);
  });
}

function formatCount(value) {
  return Number.isInteger(value) ? value.toLocaleString() : '—';
}

function capacityMetric(label, value, detail) {
  const card = document.createElement('article'); card.className = 'metric-card';
  const name = document.createElement('span'); name.textContent = label;
  const count = document.createElement('strong'); count.textContent = formatCount(value);
  const note = document.createElement('small'); note.textContent = detail;
  card.append(name, count, note); return card;
}

function renderCapacity(report) {
  const totals = report.totals || {}; const total = report.total || 0;
  const metrics = $('#capacityMetrics'); metrics.replaceChildren(); metrics.hidden = false;
  const coverage = (key) => `${totals[`${key}_devices`] || 0}/${total} headends reported`;
  metrics.append(
    capacityMetric('Known local capacity', totals.pool_addresses, coverage('pool_addresses')),
    capacityMetric('Provisioned capacity', totals.provisioned_capacity, coverage('provisioned_capacity')),
    capacityMetric('Configured limit', totals.configured_limit, coverage('configured_limit')),
    capacityMetric('Effective ceiling', totals.effective_capacity, coverage('effective_capacity')),
    capacityMetric('Active sessions', totals.active_sessions, coverage('active_sessions')),
  );

  const container = $('#capacityReport'); container.hidden = false; container.replaceChildren();
  const note = document.createElement('p'); note.className = 'capacity-note';
  note.textContent = `${report.status === 'completed' ? 'Completed' : 'Running'} report ${report.report_id} · ${report.completed}/${total} headends · ${totals.local_devices || 0} local · ${totals.dhcp_devices || 0} DHCP · ${totals.mixed_devices || 0} mixed`;
  const wrap = document.createElement('div'); wrap.className = 'capacity-table-wrap';
  const table = document.createElement('table'); table.className = 'capacity-table';
  const head = document.createElement('thead');
  head.innerHTML = '<tr><th>Headend</th><th>Address source</th><th>Known local addresses</th><th>Provisioned</th><th>Configured</th><th>Effective</th><th>Active</th><th>Limiting factor / status</th></tr>';
  const body = document.createElement('tbody');
  (report.results || []).forEach((item) => {
    const row = document.createElement('tr');
    const device = document.createElement('td'); device.className = 'device-name'; device.textContent = item.device;
    const poolDetail = document.createElement('small');
    const poolBreakdown = (item.pools || []).map((pool) => `${pool.name} ${formatCount(pool.addresses)}`).join(' · ');
    poolDetail.textContent = poolBreakdown || `${item.pool_count || 0} pool(s)`; device.append(poolDetail);
    const source = document.createElement('td'); source.textContent = (item.address_source || 'unknown').replace(/^./, (letter) => letter.toUpperCase());
    const dhcpDetail = document.createElement('small');
    const dhcpParts = [];
    if (item.dhcp_servers?.length) dhcpParts.push(`servers ${item.dhcp_servers.join(', ')}`);
    if (item.dhcp_scopes?.length) dhcpParts.push(`scopes ${item.dhcp_scopes.join(', ')}`);
    dhcpDetail.textContent = dhcpParts.join(' · '); if (dhcpParts.length) source.append(dhcpDetail);
    [item.pool_addresses, item.provisioned_capacity, item.configured_limit, item.effective_capacity, item.active_sessions].forEach((value) => {
      const cell = document.createElement('td'); cell.textContent = formatCount(value); row.append(cell);
    });
    const status = document.createElement('td'); const statusText = document.createElement('span');
    statusText.className = `capacity-status ${item.status || 'warning'}`;
    const overlap = item.overlapping_addresses ? ` · ${formatCount(item.overlapping_addresses)} overlapping excluded` : '';
    const completeness = item.external_dhcp_capacity_unknown ? 'External DHCP capacity unknown' : (item.limiting_factor || (item.missing?.length ? `Missing ${item.missing.join(', ')}` : 'Complete'));
    statusText.textContent = item.status === 'error' ? 'Collection failed' : `${completeness}${overlap}`;
    if (item.errors?.length) statusText.title = item.errors.join('\n');
    status.append(statusText); row.prepend(device, source); row.append(status); body.append(row);
  });
  table.append(head, body); wrap.append(table); container.append(note, wrap);
}

async function pollCapacity(reportId) {
  clearTimeout(state.capacityTimer);
  try {
    const report = await request(`/api/capacity-reports/${reportId}`);
    const errors = report.totals?.error_devices || 0; const warnings = report.totals?.warning_devices || 0;
    const phase = report.status === 'completed' ? 'Completed' : report.status === 'retrying' ? `Retrying incomplete headends (pass ${report.retry_pass}/2)` : 'Collecting';
    $('#capacityStatus').textContent = `${phase}: ${report.completed}/${report.total} headends · ${warnings} partial · ${errors} failed`;
    renderCapacity(report);
    if (report.status === 'completed') { $('#capacityButton').disabled = false; $('#capacityButton span').textContent = 'Inventory all headends'; await refreshSaved(); return; }
    state.capacityTimer = setTimeout(() => pollCapacity(reportId), 3000);
  } catch (error) { $('#capacityStatus').textContent = error.message; $('#capacityStatus').classList.add('error'); $('#capacityButton').disabled = false; $('#capacityButton span').textContent = 'Inventory all headends'; }
}

$('#capacityButton').addEventListener('click', async () => {
  try {
    $('#capacityButton').disabled = true; $('#capacityButton span').textContent = 'Collecting…';
    $('#capacityStatus').classList.remove('error'); $('#capacityStatus').textContent = 'Starting service-wide capacity inventory…';
    const report = await request('/api/capacity-reports', { method: 'POST', body: '{}' });
    pollCapacity(report.report_id);
  } catch (error) {
    $('#capacityStatus').textContent = error.message; $('#capacityStatus').classList.add('error'); $('#capacityButton').disabled = false;
  } finally {
    if (!$('#capacityButton').disabled) $('#capacityButton span').textContent = 'Inventory all headends';
  }
});

$('#capacitySelect').addEventListener('change', async (event) => {
  if (!event.target.value) return;
  try { renderCapacity(await request(`/api/capacity-reports/${event.target.value}`)); }
  catch (error) { $('#capacityStatus').textContent = error.message; $('#capacityStatus').classList.add('error'); }
});

function escapeHtml(value) {
  const node = document.createElement('span'); node.textContent = value == null ? '' : String(value); return node.innerHTML;
}

initialize();
