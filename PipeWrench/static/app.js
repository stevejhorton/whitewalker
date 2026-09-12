const $ = (selector) => document.querySelector(selector);

const state = { devices: [], running: false };
const deviceSelect = $('#deviceSelect');
const runButton = $('#runButton');
const notice = $('#notice');
const resultGrid = $('#resultGrid');

async function request(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
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
  deviceSelect.replaceChildren();
  if (!devices.length) {
    deviceSelect.append(new Option('Add a headend to begin', ''));
    return;
  }
  deviceSelect.append(new Option('Choose a headend…', ''));
  devices.forEach((device) => deviceSelect.append(new Option(device, device)));
  deviceSelect.value = selected && devices.includes(selected) ? selected : '';
}

async function initialize() {
  try {
    const [deviceData, status] = await Promise.all([request('/api/devices'), request('/api/status')]);
    populateDevices(deviceData.devices);
    const dot = $('#credentialDot');
    if (status.credentials.ready) {
      dot.className = 'ready';
      $('#credentialState').textContent = 'Credentials found';
    } else {
      dot.className = 'error';
      $('#credentialState').textContent = 'Credentials missing';
      message('Create un.txt and pw.txt in the PipeWrench folder before running an inspection.', true);
    }
    const tlsDot = $('#tlsDot');
    if (status.tls_verify) {
      tlsDot.className = 'ready';
      $('#tlsState').textContent = 'Certificate verified';
    } else {
      tlsDot.className = 'warning';
      $('#tlsState').textContent = 'Management cert allowed';
    }
  } catch (error) {
    message(error.message, true);
  }
}

$('#addToggle').addEventListener('click', () => {
  const panel = $('#addPanel');
  panel.hidden = !panel.hidden;
  if (!panel.hidden) $('#newDevice').focus();
});

$('#saveDevice').addEventListener('click', async () => {
  const input = $('#newDevice');
  const hostname = input.value.trim();
  if (!hostname) return message('Enter a headend short name.', true);
  try {
    const payload = await request('/api/devices', { method: 'POST', body: JSON.stringify({ hostname }) });
    populateDevices(payload.devices, payload.added);
    input.value = '';
    $('#addPanel').hidden = true;
    message(`${payload.added} saved to the local headend cache.`);
  } catch (error) {
    message(error.message, true);
  }
});

$('#newDevice').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') $('#saveDevice').click();
});

runButton.addEventListener('click', async () => {
  if (state.running) return;
  const device = deviceSelect.value;
  const action = document.querySelector('input[name="action"]:checked').value;
  if (!device) return message('Choose a headend first.', true);

  state.running = true;
  runButton.disabled = true;
  runButton.querySelector('span').textContent = 'Inspecting…';
  message(`Connecting to ${device}:2002…`);
  $('#resultsTitle').textContent = `Inspecting ${device}`;
  $('#emptyState').hidden = true;
  $('#metricGrid').hidden = true;
  resultGrid.hidden = false;
  resultGrid.innerHTML = loadingCards(action === 'health' ? 8 : 10);
  $('#summary').hidden = true;

  try {
    const payload = await request('/api/run', {
      method: 'POST',
      body: JSON.stringify({ device, action }),
    });
    renderResults(payload);
    message(`Inspection completed for ${device}.`);
  } catch (error) {
    resultGrid.hidden = true;
    $('#metricGrid').hidden = true;
    $('#emptyState').hidden = false;
    $('#resultsTitle').textContent = 'Inspection failed';
    message(error.message, true);
  } finally {
    state.running = false;
    runButton.disabled = false;
    runButton.querySelector('span').textContent = 'Run inspection';
  }
});

function loadingCards(count) {
  return Array.from({ length: count }, (_, index) =>
    `<div class="result-card" style="height:58px;opacity:${1 - index * .07}"></div>`
  ).join('');
}

function renderResults(payload) {
  $('#resultsTitle').textContent = `${payload.action === 'health' ? 'Health snapshot' : 'Standards review'} · ${payload.device}`;
  $('#okCount').textContent = payload.summary.ok;
  $('#warnCount').textContent = payload.summary.warning;
  $('#errorCount').textContent = payload.summary.error;
  $('#summary').hidden = false;
  renderMetrics(payload.metrics || []);
  resultGrid.replaceChildren();

  payload.results.forEach((result) => {
    const fragment = $('#resultTemplate').content.cloneNode(true);
    const card = fragment.querySelector('.result-card');
    const heading = fragment.querySelector('.result-heading');
    const body = fragment.querySelector('.result-body');
    card.dataset.status = result.status;
    fragment.querySelector('.result-name').textContent = result.label;
    fragment.querySelector('.result-command').textContent = result.command || result.status.toUpperCase();
    fragment.querySelector('pre').textContent = result.output || result.detail || 'No additional detail.';
    heading.addEventListener('click', () => {
      const expanded = heading.getAttribute('aria-expanded') === 'true';
      heading.setAttribute('aria-expanded', String(!expanded));
      body.hidden = expanded;
    });
    resultGrid.append(fragment);
  });
}

function renderMetrics(metrics) {
  const metricGrid = $('#metricGrid');
  metricGrid.replaceChildren();
  metricGrid.hidden = !metrics.length;
  metrics.forEach((metric) => {
    const card = document.createElement('article');
    card.className = 'metric-card';
    const label = document.createElement('span');
    label.textContent = metric.label;
    const value = document.createElement('strong');
    value.textContent = metric.value;
    const detail = document.createElement('small');
    detail.textContent = metric.detail;
    card.append(label, value, detail);
    metricGrid.append(card);
  });
}

initialize();
