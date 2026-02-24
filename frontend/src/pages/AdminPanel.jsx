import { useState, useEffect, useCallback } from 'react';
import {
  Settings, Users, ScrollText, HardDrive, RefreshCw, Shield, Clock,
  Archive, Trash2, UserCheck, ChevronDown, Activity, Database,
} from 'lucide-react';
import {
  fetchAuditLogs, fetchUsers, updateUserRole,
  fetchStorageStats, rotateStorage, fetchArchives,
  fetchMLStatus, runMLDetection,
} from '../api';

export default function AdminPanel() {
  const [tab, setTab] = useState('audit');
  const [auditLogs, setAuditLogs] = useState([]);
  const [users, setUsers] = useState([]);
  const [storageStats, setStorageStats] = useState(null);
  const [archives, setArchives] = useState([]);
  const [mlStatus, setMlStatus] = useState(null);
  const [mlResults, setMlResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionMsg, setActionMsg] = useState(null);

  const loadTabData = useCallback(async () => {
    setLoading(true);
    try {
      if (tab === 'audit') {
        const data = await fetchAuditLogs(200);
        setAuditLogs(data.items || []);
      } else if (tab === 'users') {
        const data = await fetchUsers();
        setUsers(data.users || []);
      } else if (tab === 'storage') {
        const [stats, arch] = await Promise.all([fetchStorageStats(), fetchArchives()]);
        setStorageStats(stats);
        setArchives(arch.archives || []);
      } else if (tab === 'ml') {
        const st = await fetchMLStatus();
        setMlStatus(st);
      }
    } catch { /* ignore */ }
    setLoading(false);
  }, [tab]);

  useEffect(() => { loadTabData(); }, [loadTabData]);

  async function handleRoleChange(userId, newRole) {
    try {
      await updateUserRole(userId, newRole);
      setActionMsg({ type: 'success', text: `Role updated to ${newRole}` });
      loadTabData();
    } catch (e) {
      setActionMsg({ type: 'error', text: `Failed: ${e.message}` });
    }
  }

  async function handleRotate() {
    setLoading(true);
    try {
      const result = await rotateStorage(7);
      setActionMsg({ type: 'success', text: `Archived ${result.archived_count || 0} logs` });
      loadTabData();
    } catch (e) {
      setActionMsg({ type: 'error', text: `Rotation failed: ${e.message}` });
    }
    setLoading(false);
  }

  async function handleMLDetect() {
    setLoading(true);
    try {
      const result = await runMLDetection();
      setMlResults(result);
      setActionMsg({ type: 'success', text: `Analyzed ${result.total_analyzed || 0} logs, found ${result.total_anomalies || 0} anomalies` });
    } catch (e) {
      setActionMsg({ type: 'error', text: `ML detection failed: ${e.message}` });
    }
    setLoading(false);
  }

  const tabs = [
    { id: 'audit', icon: ScrollText, label: 'Audit Logs' },
    { id: 'users', icon: Users, label: 'User Management' },
    { id: 'storage', icon: HardDrive, label: 'Cold Storage' },
    { id: 'ml', icon: Activity, label: 'ML Anomaly' },
  ];

  const severityColors = {
    critical: '#ff0040', high: '#ff6b00', medium: '#ffb800', low: '#00d4ff', info: '#888',
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div className="page-header-left">
          <Settings size={20} className="page-icon" />
          <div>
            <h1>ADMIN_PANEL</h1>
            <p className="page-subtitle">System Administration & Analytics</p>
          </div>
        </div>
        <button className="cyber-btn" onClick={loadTabData} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {actionMsg && (
        <div className={`status-banner ${actionMsg.type === 'success' ? 'status-success' : 'status-error'}`}>
          <span>{actionMsg.text}</span>
          <button className="banner-dismiss" onClick={() => setActionMsg(null)}>&times;</button>
        </div>
      )}

      {/* Tabs */}
      <div className="tab-bar">
        {tabs.map(t => (
          <button
            key={t.id}
            className={`tab-item ${tab === t.id ? 'active' : ''}`}
            onClick={() => setTab(t.id)}
          >
            <t.icon size={14} />
            <span>{t.label}</span>
          </button>
        ))}
      </div>

      {/* Audit Logs Tab */}
      {tab === 'audit' && (
        <div className="cyber-table-wrapper">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>User</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.map((log, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.8em', whiteSpace: 'nowrap', color: '#8b949e' }}>
                    {log.created_at ? new Date(log.created_at).toLocaleString() : '—'}
                  </td>
                  <td>
                    <span style={{ color: '#00d4ff' }}>{log.username}</span>
                  </td>
                  <td>
                    <span className="tag-pill">{log.action}</span>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.85em' }}>
                    {log.resource_type}{log.resource_id ? `:${log.resource_id.slice(0, 8)}` : ''}
                  </td>
                  <td style={{ fontSize: '0.8em', color: '#8b949e', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {log.details ? JSON.stringify(log.details) : '—'}
                  </td>
                </tr>
              ))}
              {!loading && auditLogs.length === 0 && (
                <tr><td colSpan={5} className="empty-state">No audit logs recorded yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Users Tab */}
      {tab === 'users' && (
        <div className="cyber-table-wrapper">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u, i) => (
                <tr key={i}>
                  <td style={{ color: '#e6edf3', fontWeight: 600 }}>{u.username}</td>
                  <td style={{ color: '#8b949e' }}>{u.email}</td>
                  <td>
                    <select
                      value={u.role}
                      onChange={(e) => handleRoleChange(u.id, e.target.value)}
                      className="cyber-select"
                    >
                      <option value="admin">Admin</option>
                      <option value="analyst">Analyst</option>
                      <option value="readonly">Read-Only</option>
                    </select>
                  </td>
                  <td>
                    <span className={`status-pill ${u.is_active ? 'status-active' : 'status-inactive'}`}>
                      {u.is_active ? 'ACTIVE' : 'DISABLED'}
                    </span>
                  </td>
                  <td>
                    <UserCheck size={14} style={{ color: '#00ff41' }} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Storage Tab */}
      {tab === 'storage' && (
        <div>
          {storageStats && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '16px', marginBottom: '24px' }}>
              <div className="metric-card">
                <div className="metric-value">{storageStats.active_log_count?.toLocaleString() || 0}</div>
                <div className="metric-label">Active Logs</div>
              </div>
              <div className="metric-card">
                <div className="metric-value">{storageStats.archive_count || 0}</div>
                <div className="metric-label">Archives</div>
              </div>
              <div className="metric-card">
                <div className="metric-value">
                  {storageStats.total_archive_size_mb
                    ? `${storageStats.total_archive_size_mb.toFixed(2)} MB`
                    : '0 MB'}
                </div>
                <div className="metric-label">Archive Size</div>
              </div>
            </div>
          )}

          <button className="cyber-btn" onClick={handleRotate} disabled={loading} style={{ marginBottom: '24px' }}>
            <Archive size={14} /> Rotate Logs (7-day retention)
          </button>

          {archives.length > 0 && (
            <>
              <div className="section-label">// Archives</div>
              <div className="cyber-table-wrapper">
                <table className="cyber-table">
                  <thead>
                    <tr><th>Filename</th><th>Size</th><th>Created</th></tr>
                  </thead>
                  <tbody>
                    {archives.map((a, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'monospace', color: '#00ff41', fontSize: '0.85em' }}>{a.filename}</td>
                        <td>{a.size_mb ? `${a.size_mb.toFixed(2)} MB` : a.size_bytes + ' B'}</td>
                        <td style={{ color: '#8b949e', fontSize: '0.85em' }}>
                          {a.created_at ? new Date(a.created_at).toLocaleString() : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}

      {/* ML Anomaly Tab */}
      {tab === 'ml' && (
        <div>
          {mlStatus && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '16px', marginBottom: '24px' }}>
              <div className="metric-card">
                <div className="metric-value" style={{ color: mlStatus.trained ? '#00ff41' : '#ff6b00' }}>
                  {mlStatus.trained ? 'TRAINED' : 'UNTRAINED'}
                </div>
                <div className="metric-label">Model Status</div>
              </div>
              <div className="metric-card">
                <div className="metric-value">{mlStatus.training_samples || 0}</div>
                <div className="metric-label">Training Samples</div>
              </div>
              <div className="metric-card">
                <div className="metric-value">{(mlStatus.contamination * 100).toFixed(0)}%</div>
                <div className="metric-label">Contamination</div>
              </div>
            </div>
          )}

          <button className="cyber-btn" onClick={handleMLDetect} disabled={loading} style={{ marginBottom: '24px' }}>
            <Activity size={14} /> Run Anomaly Detection
          </button>

          {mlResults && (
            <>
              <div className="section-label">// Detection Results — {mlResults.total_anomalies || 0} anomalies in {mlResults.total_analyzed || 0} logs</div>
              <div className="cyber-table-wrapper">
                <table className="cyber-table">
                  <thead>
                    <tr><th>Source IP</th><th>Anomaly Score</th><th>Severity</th><th>Features</th></tr>
                  </thead>
                  <tbody>
                    {(mlResults.anomalies || []).map((a, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'monospace', color: '#00ff41' }}>{a.source_ip}</td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <div style={{
                              width: '60px', height: '6px', background: '#21262d', borderRadius: '3px', overflow: 'hidden'
                            }}>
                              <div style={{
                                width: `${a.normalized_score}%`, height: '100%',
                                background: severityColors[a.severity] || '#888',
                              }} />
                            </div>
                            <span style={{ fontSize: '0.85em' }}>{a.normalized_score}</span>
                          </div>
                        </td>
                        <td>
                          <span style={{ color: severityColors[a.severity] || '#888', fontWeight: 700, textTransform: 'uppercase', fontSize: '0.8em' }}>
                            {a.severity}
                          </span>
                        </td>
                        <td style={{ fontSize: '0.75em', fontFamily: 'monospace', color: '#8b949e' }}>
                          {a.features ? Object.entries(a.features).map(([k, v]) => `${k}=${typeof v === 'number' ? v.toFixed(1) : v}`).join(' | ') : '—'}
                        </td>
                      </tr>
                    ))}
                    {(mlResults.anomalies || []).length === 0 && (
                      <tr><td colSpan={4} className="empty-state">No anomalies detected — system nominal</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
