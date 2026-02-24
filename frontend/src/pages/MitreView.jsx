import { useState, useEffect } from 'react';
import { Crosshair, ExternalLink, Terminal } from 'lucide-react';
import { fetchMitreHeatmap } from '../api';

const HEAT_COLORS = [
    { min: 0, color: 'rgba(255,255,255,0.03)', text: 'var(--text-dim)' },
    { min: 1, color: 'rgba(0,212,255,0.12)', text: '#00d4ff' },
    { min: 3, color: 'rgba(255,184,0,0.14)', text: '#ffb800' },
    { min: 5, color: 'rgba(255,107,0,0.18)', text: '#ff6b00' },
    { min: 10, color: 'rgba(255,0,64,0.22)', text: '#ff0040' },
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

    if (loading) return (
        <div className="loading-state">
            <div className="loading-spinner" />
            <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.8rem' }}>Loading MITRE data...</p>
        </div>
    );

    const techniques = data?.techniques || [];

    const tacticGroups = {};
    for (const tech of techniques) {
        const tactic = tech.tactic || 'Unknown';
        if (!tacticGroups[tactic]) tacticGroups[tactic] = [];
        tacticGroups[tactic].push(tech);
    }

    return (
        <div>
            <div className="page-header">
                <h2>
                    <Crosshair className="page-icon" size={20} />
                    MITRE ATT&CK Coverage
                </h2>
                <p>{'>'} technique heatmap from detected threats mapped to ATT&CK framework</p>
            </div>

            {/* Summary Stats */}
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', marginBottom: '1.25rem' }}>
                <div className="stat-card animate-in animate-in-delay-1">
                    <div className="stat-value" style={{ color: 'var(--cyber-green)' }}>{techniques.length}</div>
                    <div className="stat-label">Techniques</div>
                </div>
                <div className="stat-card animate-in animate-in-delay-2">
                    <div className="stat-value" style={{ color: 'var(--cyber-blue)' }}>{Object.keys(tacticGroups).length}</div>
                    <div className="stat-label">Tactics</div>
                </div>
                <div className="stat-card animate-in animate-in-delay-3">
                    <div className="stat-value" style={{ color: 'var(--critical)' }}>{data?.total_detections || 0}</div>
                    <div className="stat-label">Total Hits</div>
                </div>
            </div>

            {techniques.length === 0 ? (
                <div className="empty-state" style={{ marginTop: '3rem' }}>
                    <Terminal size={48} style={{ marginBottom: '1rem', opacity: 0.3, color: 'var(--cyber-green)' }} />
                    <h3 style={{ color: 'var(--text-primary)', marginBottom: '0.5rem', fontSize: '1rem' }}>No MITRE Data</h3>
                    <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem' }}>
                        {'>'} Ingest and analyze logs to populate technique coverage
                    </p>
                </div>
            ) : (
                <>
                    {/* Heatmap Grid */}
                    <div className="card animate-in" style={{ marginBottom: '1.25rem' }}>
                        <div className="card-header">
                            <span className="card-title">Detection Heatmap</span>
                            <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', fontSize: '0.65rem', color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                                {HEAT_COLORS.slice(1).map((level, i) => (
                                    <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.2rem' }}>
                                        <span style={{ width: 10, height: 10, borderRadius: 2, background: level.text, display: 'inline-block', opacity: 0.7 }} />
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
                                    <th>Detections</th>
                                    <th>IDs</th>
                                </tr>
                            </thead>
                            <tbody>
                                {Object.entries(tacticGroups).map(([tactic, techs], idx) => {
                                    const totalCount = techs.reduce((s, t) => s + t.count, 0);
                                    return (
                                        <tr key={idx}>
                                            <td><span className="tag">{tactic}</span></td>
                                            <td className="mono">{techs.length}</td>
                                            <td className="mono" style={{ fontWeight: 700, color: totalCount >= 5 ? 'var(--critical)' : 'var(--text-primary)' }}>{totalCount}</td>
                                            <td>
                                                <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                                                    {techs.map((t, i) => (
                                                        <a key={i} href={t.url} target="_blank" rel="noopener noreferrer"
                                                            style={{ color: 'var(--cyber-green)', fontSize: '0.72rem', fontFamily: 'JetBrains Mono' }}>
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
