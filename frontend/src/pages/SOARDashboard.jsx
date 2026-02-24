import { useState, useEffect, useCallback } from 'react';
import { Zap, Play, Clock, CheckCircle, XCircle, AlertTriangle, RefreshCw, Shield, ChevronDown, ChevronUp } from 'lucide-react';
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
          <div key={pb.id} className="cyber-card" style={{ borderLeftColor: pb.enabled ? '#00ff41' : '#484f58' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
              <div>
                <div style={{ fontFamily: 'monospace', color: '#00ff41', fontSize: '0.8em', marginBottom: '4px' }}>{pb.id}</div>
                <h3 style={{ color: '#e6edf3', fontSize: '1em', margin: 0 }}>{pb.name}</h3>
              </div>
              <span className={`status-pill ${pb.enabled ? 'status-active' : 'status-inactive'}`}>
                {pb.enabled ? 'ACTIVE' : 'DISABLED'}
              </span>
            </div>
            <p style={{ color: '#8b949e', fontSize: '0.85em', margin: '8px 0' }}>{pb.description}</p>

            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '12px' }}>
              {(pb.triggers || []).map((t, i) => (
                <span key={i} style={{
                  background: 'rgba(0,255,65,0.08)', border: '1px solid rgba(0,255,65,0.2)',
                  padding: '2px 8px', borderRadius: '3px', fontSize: '0.75em', color: '#00ff41', fontFamily: 'monospace',
                }}>
                  ≥{t.min_severity} {t.mitre_tactics?.length ? `| ${t.mitre_tactics.join(', ')}` : ''}
                </span>
              ))}
            </div>

            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '12px' }}>
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
              <>
                <tr key={i} className="clickable-row" onClick={() => setExpandedExec(expandedExec === i ? null : i)}>
                  <td>
                    <span style={{ fontFamily: 'monospace', color: '#00ff41', fontSize: '0.85em' }}>{exec.playbook_id}</span>
                    <div style={{ color: '#8b949e', fontSize: '0.8em' }}>{exec.playbook_name}</div>
                  </td>
                  <td>
                    {exec.triggered
                      ? <span style={{ color: '#00ff41' }}>YES</span>
                      : <span style={{ color: '#484f58' }}>NO</span>}
                  </td>
                  <td>
                    <span style={{ color: '#00ff41' }}>{exec.actions_succeeded}</span>
                    /<span>{exec.actions_total}</span>
                    {exec.actions_failed > 0 && <span style={{ color: '#ff0040', marginLeft: '4px' }}>({exec.actions_failed} failed)</span>}
                  </td>
                  <td>
                    {exec.actions_failed === 0
                      ? <span className="status-pill status-active">OK</span>
                      : <span className="status-pill status-error">PARTIAL</span>}
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.8em', color: '#8b949e' }}>
                    {exec.executed_at ? new Date(exec.executed_at).toLocaleString() : '—'}
                  </td>
                  <td>
                    {expandedExec === i ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  </td>
                </tr>
                {expandedExec === i && exec.results && (
                  <tr key={`${i}-detail`}>
                    <td colSpan={6} style={{ background: 'rgba(0,0,0,0.3)', padding: '16px' }}>
                      <div style={{ fontFamily: 'monospace', fontSize: '0.8em' }}>
                        {exec.results.map((r, j) => (
                          <div key={j} style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '6px' }}>
                            {r.success
                              ? <CheckCircle size={12} style={{ color: '#00ff41' }} />
                              : <XCircle size={12} style={{ color: '#ff0040' }} />}
                            <span style={{ color: '#00d4ff' }}>{r.action_type}</span>
                            <span style={{ color: '#8b949e' }}>{r.message}</span>
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {!loading && history.length === 0 && (
              <tr><td colSpan={6} className="empty-state">No executions yet</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
