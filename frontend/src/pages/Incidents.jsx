import { useState, useEffect } from 'react';
import { ShieldAlert, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react';
import { fetchIncidents, fetchIncidentReport } from '../api';

export default function Incidents() {
    const [incidents, setIncidents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [expanded, setExpanded] = useState(null);
    const [report, setReport] = useState(null);

    useEffect(() => {
        fetchIncidents()
            .then(data => { setIncidents(data.items || []); setLoading(false); })
            .catch(() => setLoading(false));
    }, []);

    const toggleExpand = async (idx) => {
        if (expanded === idx) {
            setExpanded(null);
            setReport(null);
            return;
        }
        setExpanded(idx);
        const data = await fetchIncidentReport(idx);
        setReport(data);
    };

    return (
        <div>
            <div className="page-header">
                <h2>🛡️ Incidents</h2>
                <p>Correlated security incidents from grouped alerts</p>
            </div>

            {loading ? (
                <div className="loading-state"><div className="loading-spinner" /></div>
            ) : incidents.length === 0 ? (
                <div className="empty-state" style={{ marginTop: '3rem' }}>
                    <ShieldAlert size={48} style={{ marginBottom: '1rem', opacity: 0.3 }} />
                    <h3 style={{ marginBottom: '0.5rem', color: 'var(--text-primary)' }}>No Incidents</h3>
                    <p>Ingest logs to trigger alert correlation and incident creation.</p>
                </div>
            ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {incidents.map((inc, idx) => (
                        <div key={idx} className="card animate-in" style={{ animationDelay: `${idx * 0.05}s`, cursor: 'pointer' }}
                            onClick={() => toggleExpand(idx)}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                {expanded === idx ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
                                <span className={`severity-badge severity-${inc.severity}`}>{inc.severity}</span>
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>{inc.title}</div>
                                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'flex', gap: '1rem', marginTop: '0.2rem' }}>
                                        <span>🔔 {inc.total_alerts} alerts</span>
                                        <span>🎯 {inc.total_iocs} IOCs</span>
                                        <span>🗺️ {inc.mitre_technique_count} techniques</span>
                                    </div>
                                </div>
                                <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                                    {(inc.mitre_tactics || []).map((t, i) => (
                                        <span key={i} className="tag">{t}</span>
                                    ))}
                                </div>
                            </div>

                            {/* Expanded Report */}
                            {expanded === idx && report && (
                                <div style={{ marginTop: '1.25rem', borderTop: '1px solid var(--border-color)', paddingTop: '1rem' }}
                                    onClick={e => e.stopPropagation()}>

                                    {/* Summary */}
                                    <div style={{ whiteSpace: 'pre-line', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem', lineHeight: 1.7 }}>
                                        {report.executive_summary?.summary}
                                    </div>

                                    {/* MITRE Techniques */}
                                    {report.mitre_attack?.techniques?.length > 0 && (
                                        <div style={{ marginBottom: '1rem' }}>
                                            <h4 style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-accent)', marginBottom: '0.5rem' }}>
                                                🎯 MITRE ATT&CK Techniques
                                            </h4>
                                            <table className="data-table" style={{ fontSize: '0.8rem' }}>
                                                <thead>
                                                    <tr>
                                                        <th>ID</th>
                                                        <th>Technique</th>
                                                        <th>Tactic</th>
                                                        <th>Count</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {report.mitre_attack.techniques.map((tech, i) => (
                                                        <tr key={i}>
                                                            <td>
                                                                <a href={tech.url} target="_blank" rel="noopener noreferrer"
                                                                    style={{ color: 'var(--accent-primary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                                                                    {tech.id} <ExternalLink size={10} />
                                                                </a>
                                                            </td>
                                                            <td>{tech.name}</td>
                                                            <td><span className="tag">{tech.tactic}</span></td>
                                                            <td className="mono">{tech.detection_count}</td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    )}

                                    {/* Recommendations */}
                                    {report.recommendations?.length > 0 && (
                                        <div>
                                            <h4 style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-accent)', marginBottom: '0.5rem' }}>
                                                ✅ Remediation Recommendations
                                            </h4>
                                            {report.recommendations.map((rec, i) => (
                                                <div key={i} style={{
                                                    background: 'var(--bg-elevated)', borderRadius: 'var(--radius-sm)',
                                                    padding: '0.6rem 0.85rem', marginBottom: '0.4rem',
                                                    borderLeft: `3px solid ${rec.priority === 'high' ? 'var(--critical)' : 'var(--accent-primary)'}`,
                                                }}>
                                                    <div style={{ fontWeight: 600, fontSize: '0.82rem' }}>{rec.mitigation}</div>
                                                    <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                                                        Addresses: {rec.addresses_techniques.join(', ')} · Priority: {rec.priority}
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
