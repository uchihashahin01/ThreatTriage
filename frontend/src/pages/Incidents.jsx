import { useState, useEffect } from 'react';
import { ShieldAlert, ChevronDown, ChevronRight, ExternalLink, Terminal, FileText } from 'lucide-react';
import { fetchIncidents, fetchIncidentReport } from '../api';

export default function Incidents() {
    const [incidents, setIncidents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [expanded, setExpanded] = useState(null);
    const [report, setReport] = useState(null);
    const [reportLoading, setReportLoading] = useState(false);

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
        setReportLoading(true);
        try {
            const data = await fetchIncidentReport(idx);
            setReport(data);
        } catch (e) {
            setReport(null);
        }
        setReportLoading(false);
    };

    return (
        <div>
            <div className="page-header">
                <h2>
                    <ShieldAlert className="page-icon" size={20} />
                    Incidents
                </h2>
                <p>{'>'} correlated security incidents from grouped alerts</p>
            </div>

            {loading ? (
                <div className="loading-state">
                    <div className="loading-spinner" />
                    <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.8rem' }}>Loading incidents...</p>
                </div>
            ) : incidents.length === 0 ? (
                <div className="empty-state" style={{ marginTop: '3rem' }}>
                    <Terminal size={48} style={{ marginBottom: '1rem', opacity: 0.3, color: 'var(--cyber-green)' }} />
                    <h3 style={{ color: 'var(--text-primary)', marginBottom: '0.5rem', fontSize: '1rem' }}>No Incidents</h3>
                    <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem' }}>
                        {'>'} Ingest logs to trigger alert correlation
                    </p>
                </div>
            ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {incidents.map((inc, idx) => (
                        <div key={idx} className="card animate-in"
                            style={{
                                animationDelay: `${idx * 0.04}s`, cursor: 'pointer',
                                borderLeft: `2px solid ${
                                    inc.severity === 'critical' ? 'var(--critical)' :
                                    inc.severity === 'high' ? 'var(--high)' :
                                    'var(--border-color)'
                                }`,
                            }}
                            onClick={() => toggleExpand(idx)}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                {expanded === idx ? <ChevronDown size={16} color="var(--cyber-green)" /> : <ChevronRight size={16} />}
                                <span className={`severity-badge severity-${inc.severity}`}>{inc.severity}</span>
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontWeight: 700, fontSize: '0.88rem', color: 'var(--text-bright)' }}>
                                        {inc.title}
                                    </div>
                                    <div style={{
                                        fontSize: '0.68rem', color: 'var(--text-dim)',
                                        display: 'flex', gap: '0.75rem', marginTop: '0.15rem',
                                        fontFamily: 'JetBrains Mono',
                                    }}>
                                        <span>{inc.total_alerts} alerts</span>
                                        <span>{inc.total_iocs} IOCs</span>
                                        <span>{inc.mitre_technique_count} techniques</span>
                                    </div>
                                </div>
                                <div style={{ display: 'flex', gap: '0.2rem', flexWrap: 'wrap' }}>
                                    {(inc.mitre_tactics || []).slice(0, 3).map((t, i) => (
                                        <span key={i} className="tag">{t}</span>
                                    ))}
                                </div>
                            </div>

                            {/* Expanded Report */}
                            {expanded === idx && (
                                <div style={{ marginTop: '1rem', borderTop: '1px solid var(--border-color)', paddingTop: '1rem' }}
                                    onClick={e => e.stopPropagation()}>

                                    {reportLoading ? (
                                        <div className="loading-state" style={{ padding: '1.5rem' }}>
                                            <div className="loading-spinner" />
                                        </div>
                                    ) : report ? (
                                        <>
                                            {/* Summary */}
                                            <div className="terminal-box" style={{ marginBottom: '1rem' }}>
                                                <div className="terminal-output">
                                                    {report.executive_summary?.summary || 'No summary available.'}
                                                </div>
                                            </div>

                                            {/* MITRE Techniques */}
                                            {report.mitre_attack?.techniques?.length > 0 && (
                                                <div style={{ marginBottom: '1rem' }}>
                                                    <h4 style={{
                                                        fontSize: '0.72rem', fontWeight: 600, color: 'var(--cyber-green)',
                                                        fontFamily: 'JetBrains Mono', marginBottom: '0.5rem',
                                                        letterSpacing: '0.05em',
                                                    }}>
                                                        {'>'} MITRE ATT&CK TECHNIQUES
                                                    </h4>
                                                    <table className="data-table" style={{ fontSize: '0.75rem' }}>
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
                                                                            style={{ color: 'var(--cyber-green)', display: 'flex', alignItems: 'center', gap: '0.2rem', fontFamily: 'JetBrains Mono' }}>
                                                                            {tech.id} <ExternalLink size={9} />
                                                                        </a>
                                                                    </td>
                                                                    <td style={{ color: 'var(--text-primary)' }}>{tech.name}</td>
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
                                                    <h4 style={{
                                                        fontSize: '0.72rem', fontWeight: 600, color: 'var(--cyber-green)',
                                                        fontFamily: 'JetBrains Mono', marginBottom: '0.5rem',
                                                        letterSpacing: '0.05em',
                                                    }}>
                                                        {'>'} REMEDIATION
                                                    </h4>
                                                    {report.recommendations.map((rec, i) => (
                                                        <div key={i} style={{
                                                            background: 'var(--bg-elevated)', borderRadius: 'var(--radius-sm)',
                                                            padding: '0.5rem 0.75rem', marginBottom: '0.35rem',
                                                            borderLeft: `2px solid ${rec.priority === 'high' ? 'var(--critical)' : 'var(--cyber-green)'}`,
                                                        }}>
                                                            <div style={{ fontWeight: 600, fontSize: '0.78rem', color: 'var(--text-bright)' }}>
                                                                {rec.mitigation}
                                                            </div>
                                                            <div style={{ fontSize: '0.65rem', color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                                                                Addresses: {rec.addresses_techniques?.join(', ')} | Priority: {rec.priority}
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </>
                                    ) : (
                                        <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                                            Failed to load report
                                        </p>
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
