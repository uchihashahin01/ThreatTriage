import { useState, useEffect } from 'react';
import { Target, ExternalLink } from 'lucide-react';
import { fetchMitreHeatmap } from '../api';

const HEAT_COLORS = [
    { min: 0, color: 'var(--border-color)', text: 'var(--text-dim)' },
    { min: 1, color: 'rgba(79, 107, 255, 0.15)', text: '#7c8aff' },
    { min: 3, color: 'rgba(255, 190, 11, 0.15)', text: '#ffbe0b' },
    { min: 5, color: 'rgba(255, 140, 66, 0.2)', text: '#ff8c42' },
    { min: 10, color: 'rgba(255, 71, 87, 0.25)', text: '#ff4757' },
];

function getHeatStyle(count) {
    let style = HEAT_COLORS[0];
    for (const level of HEAT_COLORS) {
        if (count >= level.min) style = level;
    }
    return { background: style.color, borderColor: `${style.text}33` };
}

function getHeatTextColor(count) {
    let style = HEAT_COLORS[0];
    for (const level of HEAT_COLORS) {
        if (count >= level.min) style = level;
    }
    return style.text;
}

export default function MitreView() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchMitreHeatmap()
            .then(d => { setData(d); setLoading(false); })
            .catch(() => setLoading(false));
    }, []);

    if (loading) return <div className="loading-state"><div className="loading-spinner" /></div>;

    const techniques = data?.techniques || [];

    // Group by tactic
    const tacticGroups = {};
    for (const tech of techniques) {
        const tactic = tech.tactic || 'Unknown';
        if (!tacticGroups[tactic]) tacticGroups[tactic] = [];
        tacticGroups[tactic].push(tech);
    }

    return (
        <div>
            <div className="page-header">
                <h2>🎯 MITRE ATT&CK Coverage</h2>
                <p>Techniques detected across ingested logs mapped to the MITRE ATT&CK framework</p>
            </div>

            {/* Summary Stats */}
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', marginBottom: '1.5rem' }}>
                <div className="stat-card animate-in animate-in-delay-1">
                    <div className="stat-value">{techniques.length}</div>
                    <div className="stat-label">Techniques Detected</div>
                </div>
                <div className="stat-card animate-in animate-in-delay-2">
                    <div className="stat-value">{Object.keys(tacticGroups).length}</div>
                    <div className="stat-label">Tactics Covered</div>
                </div>
                <div className="stat-card animate-in animate-in-delay-3">
                    <div className="stat-value">{data?.total_detections || 0}</div>
                    <div className="stat-label">Total Detections</div>
                </div>
            </div>

            {techniques.length === 0 ? (
                <div className="empty-state" style={{ marginTop: '3rem' }}>
                    <Target size={48} style={{ marginBottom: '1rem', opacity: 0.3 }} />
                    <h3 style={{ color: 'var(--text-primary)', marginBottom: '0.5rem' }}>No MITRE Data</h3>
                    <p>Analyze some logs to see MITRE ATT&CK technique coverage.</p>
                </div>
            ) : (
                <>
                    {/* Heatmap Grid */}
                    <div className="card animate-in" style={{ marginBottom: '1.5rem' }}>
                        <div className="card-header">
                            <span className="card-title">Technique Detection Heatmap</span>
                            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                                <span>Intensity:</span>
                                {HEAT_COLORS.slice(1).map((level, i) => (
                                    <span key={i} style={{
                                        display: 'inline-flex', alignItems: 'center', gap: '0.25rem'
                                    }}>
                                        <span style={{ width: 12, height: 12, borderRadius: 3, background: level.color, display: 'inline-block' }} />
                                        {level.min}+
                                    </span>
                                ))}
                            </div>
                        </div>
                        <div className="mitre-grid">
                            {techniques.map((tech, idx) => {
                                const heatStyle = getHeatStyle(tech.count);
                                const textColor = getHeatTextColor(tech.count);
                                return (
                                    <a
                                        key={idx}
                                        href={tech.url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="mitre-cell animate-in"
                                        style={{
                                            ...heatStyle,
                                            textDecoration: 'none',
                                            animationDelay: `${idx * 0.03}s`,
                                            animationFillMode: 'both',
                                        }}
                                    >
                                        <div className="technique-id" style={{ color: textColor }}>{tech.technique_id}</div>
                                        <div className="technique-name">{tech.name}</div>
                                        <div className="technique-count" style={{ color: textColor }}>{tech.count}</div>
                                    </a>
                                );
                            })}
                        </div>
                    </div>

                    {/* Tactic Breakdown */}
                    <div className="card animate-in">
                        <div className="card-header">
                            <span className="card-title">Tactic Breakdown</span>
                        </div>
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Tactic</th>
                                    <th>Techniques</th>
                                    <th>Total Detections</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {Object.entries(tacticGroups).map(([tactic, techs], idx) => {
                                    const totalCount = techs.reduce((s, t) => s + t.count, 0);
                                    return (
                                        <tr key={idx}>
                                            <td><span className="tag">{tactic}</span></td>
                                            <td className="mono">{techs.length}</td>
                                            <td className="mono" style={{ fontWeight: 700 }}>{totalCount}</td>
                                            <td>
                                                <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                                                    {techs.map((t, i) => (
                                                        <a key={i} href={t.url} target="_blank" rel="noopener noreferrer"
                                                            style={{ color: 'var(--accent-primary)', fontSize: '0.75rem', fontFamily: 'JetBrains Mono' }}>
                                                            {t.technique_id}
                                                        </a>
                                                    ))}
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </>
            )}
        </div>
    );
}
