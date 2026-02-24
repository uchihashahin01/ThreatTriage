import { useState, useEffect, useCallback } from 'react';
import { Zap, Play, Clock, CheckCircle, XCircle, AlertTriangle, RefreshCw, Shield, ChevronDown, ChevronUp, Activity, Cpu } from 'lucide-react';
import { fetchPlaybooks, fetchSOARHistory, executePlaybook } from '../api';

export default function SOARDashboard() {
  const [playbooks, setPlaybooks] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [executing, setExecuting] = useState(false);
  const [expandedExec, setExpandedExec] = useState(null);
  const [testResult, setTestResult] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [pb, hist] = await Promise.all([fetchPlaybooks(), fetchSOARHistory()]);
      setPlaybooks(pb.playbooks || []);
      setHistory((hist.items || []).reverse());
    } catch { /* ignore */ }
    setLoading(false);
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  async function handleTestExecute(pb) {
    setExecuting(true);
    setTestResult(null);
    try {
      const alertData = {
        title: `Test: ${pb.name}`,
        severity: 'critical',
        source_ip: '198.51.100.42',
        mitre_tactic: pb.triggers?.[0]?.mitre_tactics?.[0] || 'initial-access',
        mitre_technique_ids: ['T1078'],
      };
      const result = await executePlaybook(pb.id, alertData);
      setTestResult({ success: true, data: result });
      loadData();
    } catch (e) {
      setTestResult({ success: false, error: e.message });
    }
    setExecuting(false);
  }

  const activeCount = playbooks.filter(p => p.enabled).length;
  const totalExecutions = history.length;
  const successExecs = history.filter(h => h.actions_failed === 0).length;

  return (
    <div className="page-container">
      <div className="page-header">
        <div className="page-header-left">
          <Zap size={20} className="page-icon" />
          <div>
            <h1>SOAR_PLAYBOOKS</h1>
            <p className="page-subtitle">Security Orchestration, Automation & Response</p>
          </div>
        </div>
        <button className="cyber-btn" onClick={loadData} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Stats bar */}
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', marginBottom: '1.5rem' }}>
        <div className="stat-card">
          <div className="stat-icon"><Shield size={16} /></div>
          <div className="stat-value">{playbooks.length}</div>
          <div className="stat-label">Playbooks</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(0, 212, 255, 0.12)', color: 'var(--cyber-blue)' }}><Cpu size={16} /></div>
          <div className="stat-value">{activeCount}</div>
          <div className="stat-label">Active</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(168, 85, 247, 0.12)', color: 'var(--cyber-purple)' }}><Activity size={16} /></div>
          <div className="stat-value">{totalExecutions}</div>
          <div className="stat-label">Executions</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(0, 255, 65, 0.12)', color: 'var(--cyber-green)' }}><CheckCircle size={16} /></div>
          <div className="stat-value">{successExecs}</div>
          <div className="stat-label">Successful</div>
        </div>
      </div>

      {testResult && (
        <div className={`status-banner ${testResult.success ? 'status-success' : 'status-error'}`}>
          {testResult.success ? <CheckCircle size={16} /> : <XCircle size={16} />}
          <span>{testResult.success
            ? `Executed ${testResult.data?.executed || 0} playbook(s) successfully`
            : `Execution failed: ${testResult.error}`}
          </span>
          <button className="banner-dismiss" onClick={() => setTestResult(null)}>&times;</button>
        </div>
      )}

      {/* Playbooks grid */}
      <div className="section-label">// Available Playbooks</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '16px', marginBottom: '32px' }}>
        {playbooks.map(pb => (
          <div key={pb.id} className="cyber-card" style={{ borderLeftColor: pb.enabled ? 'var(--cyber-green)' : 'var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
              <div>
                <div className="mono" style={{ color: 'var(--cyber-green)', fontSize: '0.75em', opacity: 0.7, marginBottom: '4px' }}>{pb.id}</div>
                <h3 style={{ color: 'var(--text-bright)', fontSize: '1em', margin: 0, fontWeight: 700 }}>{pb.name}</h3>
              </div>
              <span className={`status-pill ${pb.enabled ? 'status-active' : 'status-inactive'}`}>
                {pb.enabled ? 'ACTIVE' : 'DISABLED'}
              </span>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85em', margin: '8px 0', lineHeight: 1.5 }}>{pb.description}</p>

            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '12px' }}>
              {(pb.triggers || []).map((t, i) => (
                <span key={i} className="tag tag-green" style={{ fontSize: '0.72em' }}>
                  ≥{t.min_severity} {t.mitre_tactics?.length ? `| ${t.mitre_tactics.join(', ')}` : ''}
                </span>
              ))}
            </div>

            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '16px' }}>
              {(pb.action_types || []).map((a, i) => (
                <span key={i} className="tag-pill">{a}</span>
              ))}
            </div>

            <button
              className="cyber-btn cyber-btn-sm"
              onClick={() => handleTestExecute(pb)}
              disabled={executing}
            >
              <Play size={12} /> Test Execute
            </button>
          </div>
        ))}
        {!loading && playbooks.length === 0 && (
          <div className="empty-state">No playbooks configured</div>
        )}
      </div>

      {/* Execution History */}
      <div className="section-label">// Execution History</div>
      <div className="cyber-table-wrapper">
        <table className="cyber-table">
          <thead>
            <tr>
              <th>Playbook</th>
              <th>Triggered</th>
              <th>Actions</th>
              <th>Status</th>
              <th>Executed At</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {history.map((exec, i) => (
              <tbody key={i}>
                <tr className="clickable-row" onClick={() => setExpandedExec(expandedExec === i ? null : i)}>
                  <td>
                    <span className="mono" style={{ color: 'var(--cyber-green)', fontSize: '0.85em' }}>{exec.playbook_id}</span>
                    <div style={{ color: 'var(--text-secondary)', fontSize: '0.8em' }}>{exec.playbook_name}</div>
                  </td>
                  <td>
                    {exec.triggered
                      ? <span className="tag tag-green">YES</span>
                      : <span className="tag" style={{ opacity: 0.4 }}>NO</span>}
                  </td>
                  <td>
                    <span style={{ color: 'var(--cyber-green)', fontWeight: 700 }}>{exec.actions_succeeded}</span>
                    <span style={{ color: 'var(--text-dim)' }}>/</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{exec.actions_total}</span>
                    {exec.actions_failed > 0 && <span style={{ color: 'var(--cyber-red)', marginLeft: '6px', fontSize: '0.85em' }}>({exec.actions_failed} failed)</span>}
                  </td>
                  <td>
                    {exec.actions_failed === 0
                      ? <span className="status-pill status-active">OK</span>
                      : <span className="status-pill status-error">PARTIAL</span>}
                  </td>
                  <td className="mono" style={{ fontSize: '0.8em', color: 'var(--text-secondary)' }}>
                    {exec.executed_at ? new Date(exec.executed_at).toLocaleString() : '—'}
                  </td>
                  <td style={{ color: 'var(--text-dim)' }}>
                    {expandedExec === i ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  </td>
                </tr>
                {expandedExec === i && exec.results && (
                  <tr>
                    <td colSpan={6} style={{ background: 'rgba(0,0,0,0.3)', padding: '16px', borderLeft: '2px solid var(--cyber-green)' }}>
                      <div className="mono" style={{ fontSize: '0.8em' }}>
                        {exec.results.map((r, j) => (
                          <div key={j} style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '6px' }}>
                            {r.success
                              ? <CheckCircle size={12} style={{ color: 'var(--cyber-green)' }} />
                              : <XCircle size={12} style={{ color: 'var(--cyber-red)' }} />}
                            <span style={{ color: 'var(--cyber-blue)' }}>{r.action_type}</span>
                            <span style={{ color: 'var(--text-secondary)' }}>{r.message}</span>
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            ))}
            {!loading && history.length === 0 && (
              <tbody><tr><td colSpan={6} className="empty-state">No executions yet</td></tr></tbody>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
