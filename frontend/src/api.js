/** ThreatTriage API client with JWT auth */

const API_BASE = 'http://localhost:8000';
const API_KEY = 'threat-triage-dev-key';

function getHeaders() {
  const h = { 'Content-Type': 'application/json' };
  const token = localStorage.getItem('tt_token');
  if (token) {
    h['Authorization'] = `Bearer ${token}`;
  } else {
    h['X-API-Key'] = API_KEY;
  }
  return h;
}

function getAuthHeaders() {
  const token = localStorage.getItem('tt_token');
  if (token) return { 'Authorization': `Bearer ${token}` };
  return { 'X-API-Key': API_KEY };
}

async function handleResponse(res) {
  if (res.status === 401) {
    localStorage.removeItem('tt_token');
    localStorage.removeItem('tt_user');
    window.dispatchEvent(new Event('auth:logout'));
  }
  return res.json();
}

// ── Auth ─────────────────────────────────────────────────────────────────

export async function login(username, password) {
  const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  if (data.access_token) {
    localStorage.setItem('tt_token', data.access_token);
    localStorage.setItem('tt_user', JSON.stringify(data.user));
  }
  return data;
}

export async function register(username, email, password, full_name) {
  const res = await fetch(`${API_BASE}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password, full_name }),
  });
  const data = await res.json();
  if (data.access_token) {
    localStorage.setItem('tt_token', data.access_token);
    localStorage.setItem('tt_user', JSON.stringify(data.user));
  }
  return data;
}

export function logout() {
  localStorage.removeItem('tt_token');
  localStorage.removeItem('tt_user');
}

export function getStoredUser() {
  try {
    const u = localStorage.getItem('tt_user');
    return u ? JSON.parse(u) : null;
  } catch { return null; }
}

export function getStoredToken() {
  return localStorage.getItem('tt_token');
}

// ── Log Ingestion ────────────────────────────────────────────────────────

export async function ingestLogs(rawLogs, logType = null) {
  const body = { raw_logs: rawLogs };
  if (logType) body.log_type = logType;
  const res = await fetch(`${API_BASE}/api/v1/logs/ingest`, {
    method: 'POST', headers: getHeaders(), body: JSON.stringify(body),
  });
  return handleResponse(res);
}

export async function uploadLogFile(file, logType = null) {
  const formData = new FormData();
  formData.append('file', file);
  if (logType) formData.append('log_type', logType);
  const res = await fetch(`${API_BASE}/api/v1/logs/upload`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: formData,
  });
  return handleResponse(res);
}

export async function fetchLogs(limit = 50, offset = 0, suspiciousOnly = false) {
  const params = new URLSearchParams({ limit, offset, suspicious_only: suspiciousOnly });
  const res = await fetch(`${API_BASE}/api/v1/logs?${params}`, { headers: getHeaders() });
  return handleResponse(res);
}

// ── Alerts ───────────────────────────────────────────────────────────────

export async function getAlerts(severity = null, status = null, limit = 50) {
  const params = new URLSearchParams({ limit });
  if (severity) params.set('severity', severity);
  if (status) params.set('status', status);
  const res = await fetch(`${API_BASE}/api/v1/alerts?${params}`, { headers: getHeaders() });
  return handleResponse(res);
}

export const fetchAlerts = getAlerts;

export async function updateAlertStatus(alertId, newStatus) {
  const res = await fetch(`${API_BASE}/api/v1/alerts/${alertId}/status`, {
    method: 'PATCH',
    headers: getHeaders(),
    body: JSON.stringify({ status: newStatus }),
  });
  return handleResponse(res);
}

// ── Incidents ────────────────────────────────────────────────────────────

export async function getIncidents() {
  const res = await fetch(`${API_BASE}/api/v1/incidents`, { headers: getHeaders() });
  return handleResponse(res);
}

export const fetchIncidents = getIncidents;

export async function getIncidentReport(idx) {
  const res = await fetch(`${API_BASE}/api/v1/incidents/${idx}/report`, { headers: getHeaders() });
  return handleResponse(res);
}

export const fetchIncidentReport = getIncidentReport;

// ── Dashboard ────────────────────────────────────────────────────────────

export async function getDashboardMetrics() {
  const res = await fetch(`${API_BASE}/api/v1/dashboard/metrics`, { headers: getHeaders() });
  return handleResponse(res);
}

export const fetchDashboardMetrics = getDashboardMetrics;

// ── MITRE ────────────────────────────────────────────────────────────────

export async function getMitreHeatmap() {
  const res = await fetch(`${API_BASE}/api/v1/dashboard/mitre`, { headers: getHeaders() });
  return handleResponse(res);
}

export const fetchMitreHeatmap = getMitreHeatmap;

// ── Threat Intel ─────────────────────────────────────────────────────────

export async function lookupIOC(iocType, value) {
  const res = await fetch(`${API_BASE}/api/v1/intel/lookup`, {
    method: 'POST', headers: getHeaders(),
    body: JSON.stringify({ ioc_type: iocType, value }),
  });
  return handleResponse(res);
}

// ── Health ───────────────────────────────────────────────────────────────

export async function healthCheck() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}
