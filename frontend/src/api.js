/** ThreatTriage API client */

const API_BASE = 'http://localhost:8000';
const API_KEY = 'threat-triage-dev-key';

const headers = {
  'Content-Type': 'application/json',
  'X-API-Key': API_KEY,
};

export async function ingestLogs(rawLogs, logType = null) {
  const body = { raw_logs: rawLogs };
  if (logType) body.log_type = logType;
  const res = await fetch(`${API_BASE}/api/v1/logs/ingest`, {
    method: 'POST', headers, body: JSON.stringify(body),
  });
  return res.json();
}

export async function uploadLogFile(file, logType = null) {
  const formData = new FormData();
  formData.append('file', file);
  if (logType) formData.append('log_type', logType);
  const res = await fetch(`${API_BASE}/api/v1/logs/upload`, {
    method: 'POST',
    headers: { 'X-API-Key': API_KEY },
    body: formData,
  });
  return res.json();
}

export async function fetchLogs(limit = 50, offset = 0, suspiciousOnly = false) {
  const params = new URLSearchParams({ limit, offset, suspicious_only: suspiciousOnly });
  const res = await fetch(`${API_BASE}/api/v1/logs?${params}`, { headers });
  return res.json();
}

export async function getAlerts(severity = null, status = null, limit = 50) {
  const params = new URLSearchParams({ limit });
  if (severity) params.set('severity', severity);
  if (status) params.set('status', status);
  const res = await fetch(`${API_BASE}/api/v1/alerts?${params}`, { headers });
  return res.json();
}

// Alias for backward compatibility
export const fetchAlerts = getAlerts;

export async function updateAlertStatus(alertId, newStatus) {
  const res = await fetch(`${API_BASE}/api/v1/alerts/${alertId}/status`, {
    method: 'PATCH',
    headers,
    body: JSON.stringify({ status: newStatus }),
  });
  return res.json();
}

export async function getIncidents() {
  const res = await fetch(`${API_BASE}/api/v1/incidents`, { headers });
  return res.json();
}

// Alias
export const fetchIncidents = getIncidents;

export async function getIncidentReport(idx) {
  const res = await fetch(`${API_BASE}/api/v1/incidents/${idx}/report`, { headers });
  return res.json();
}

export const fetchIncidentReport = getIncidentReport;

export async function getDashboardMetrics() {
  const res = await fetch(`${API_BASE}/api/v1/dashboard/metrics`, { headers });
  return res.json();
}

// Alias
export const fetchDashboardMetrics = getDashboardMetrics;

export async function getMitreHeatmap() {
  const res = await fetch(`${API_BASE}/api/v1/dashboard/mitre`, { headers });
  return res.json();
}

export const fetchMitreHeatmap = getMitreHeatmap;

export async function lookupIOC(iocType, value) {
  const res = await fetch(`${API_BASE}/api/v1/intel/lookup`, {
    method: 'POST', headers,
    body: JSON.stringify({ ioc_type: iocType, value }),
  });
  return res.json();
}

export async function healthCheck() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}
