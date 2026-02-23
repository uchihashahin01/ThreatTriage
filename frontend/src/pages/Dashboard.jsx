import { useState, useEffect } from 'react';
import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    PieChart, Pie, Cell, AreaChart, Area,
} from 'recharts';
import {
    AlertTriangle, ShieldCheck, Bug, Globe, Activity,
    TrendingUp, Clock,
} from 'lucide-react';
import { fetchDashboardMetrics } from '../api';

const SEVERITY_COLORS = {
    critical: '#ff4757',
    high: '#ff8c42',
    medium: '#ffbe0b',
    low: '#4cc9f0',
    info: '#6b7280',
};

const PIE_COLORS = ['#ff4757', '#ff8c42', '#ffbe0b', '#4cc9f0', '#6b7280'];

export default function Dashboard() {
    const [metrics, setMetrics] = useState(null);
    const [loading, setLoading] = useState(true);

    const load = () => {
        fetchDashboardMetrics()
            .then(data => { setMetrics(data); setLoading(false); })
            .catch(() => setLoading(false));
    };

    useEffect(() => {
        load();
        const interval = setInterval(load, 10000);
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <div className="loading-state">
                <div className="loading-spinner" />
                <p>Loading dashboard...</p>
            </div>
        );
    }

    if (!metrics || metrics.total_logs === 0) {
        return (
            <div>
                <div className="page-header">
                    <h2>📊 SOC Dashboard</h2>
                    <p>Real-time security operations overview</p>
                </div>
                <div className="empty-state" style={{ marginTop: '4rem' }}>
                    <Activity size={48} style={{ marginBottom: '1rem', opacity: 0.3 }} />
                    <h3 style={{ marginBottom: '0.5rem', color: 'var(--text-primary)' }}>No Data Yet</h3>
                    <p style={{ maxWidth: 400, textAlign: 'center' }}>
                        Ingest some logs via the <strong>Log Ingestion</strong> page or the API to see your SOC dashboard come alive.
                    </p>
                </div>
            </div>
        );
    }

    const severityData = Object.entries(metrics.alerts_by_severity || {}).map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
        fill: SEVERITY_COLORS[name] || '#6b7280',
    }));

    const topIPs = (metrics.top_source_ips || []).map(item => ({
        ip: item.ip.length > 16 ? item.ip.slice(0, 16) + '…' : item.ip,
        count: item.count,
    }));

    const topTechniques = (metrics.top_mitre_techniques || []).map(item => ({
        id: item.technique_id,
        count: item.count,
    }));

    return (
        <div>
            <div className="page-header">
                <h2>📊 SOC Dashboard</h2>
                <p>Real-time security operations overview</p>
            </div>

            {/* Stat Cards */}
            <div className="stats-grid">
                <div className="stat-card animate-in animate-in-delay-1">
                    <div className="stat-icon" style={{ background: 'var(--accent-glow)', color: 'var(--accent-primary)' }}>
                        <FileTextIcon />
                    </div>
                    <div className="stat-value">{metrics.total_logs?.toLocaleString()}</div>
                    <div className="stat-label">Logs Processed</div>
                </div>

                <div className="stat-card animate-in animate-in-delay-2">
                    <div className="stat-icon" style={{ background: 'var(--critical-bg)', color: 'var(--critical)' }}>
                        <AlertTriangle size={18} />
                    </div>
                    <div className="stat-value" style={{ color: metrics.total_alerts > 0 ? 'var(--critical)' : undefined }}>
                        {metrics.total_alerts}
                    </div>
                    <div className="stat-label">Active Alerts</div>
                </div>

                <div className="stat-card animate-in animate-in-delay-3">
                    <div className="stat-icon" style={{ background: 'var(--high-bg)', color: 'var(--high)' }}>
                        <ShieldCheck size={18} />
                    </div>
                    <div className="stat-value">{metrics.total_incidents}</div>
                    <div className="stat-label">Incidents</div>
                </div>

                <div className="stat-card animate-in animate-in-delay-4">
                    <div className="stat-icon" style={{ background: 'var(--success-bg)', color: 'var(--success)' }}>
                        <Bug size={18} />
                    </div>
                    <div className="stat-value">{metrics.total_iocs}</div>
                    <div className="stat-label">IOCs</div>
                </div>
            </div>

            {/* Charts Row */}
            <div className="grid-2" style={{ marginBottom: '1.5rem' }}>
                {/* Severity Distribution */}
                <div className="card animate-in">
                    <div className="card-header">
                        <span className="card-title">Alert Severity Distribution</span>
                    </div>
                    <div style={{ height: 260 }}>
                        {severityData.length > 0 ? (
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={severityData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={95}
                                        paddingAngle={4}
                                        dataKey="value"
                                        strokeWidth={0}
                                    >
                                        {severityData.map((entry, idx) => (
                                            <Cell key={idx} fill={entry.fill} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{
                                            background: 'var(--bg-elevated)',
                                            border: '1px solid var(--border-color)',
                                            borderRadius: '8px',
                                            color: 'var(--text-primary)',
                                            fontSize: '0.8rem',
                                        }}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="empty-state"><p>No alerts</p></div>
                        )}
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                        {severityData.map((entry, idx) => (
                            <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem' }}>
                                <span style={{ width: 8, height: 8, borderRadius: '50%', background: entry.fill, display: 'inline-block' }} />
                                <span style={{ color: 'var(--text-secondary)' }}>{entry.name}</span>
                                <span style={{ fontWeight: 700, fontFamily: 'JetBrains Mono' }}>{entry.value}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Top Source IPs */}
                <div className="card animate-in">
                    <div className="card-header">
                        <span className="card-title">Top Threat Source IPs</span>
                    </div>
                    <div style={{ height: 280 }}>
                        {topIPs.length > 0 ? (
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={topIPs} layout="vertical" margin={{ left: 10, right: 20 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                                    <XAxis type="number" stroke="var(--text-dim)" tick={{ fontSize: 11 }} />
                                    <YAxis
                                        type="category"
                                        dataKey="ip"
                                        width={120}
                                        stroke="var(--text-dim)"
                                        tick={{ fontSize: 11, fontFamily: 'JetBrains Mono' }}
                                    />
                                    <Tooltip
                                        contentStyle={{
                                            background: 'var(--bg-elevated)',
                                            border: '1px solid var(--border-color)',
                                            borderRadius: '8px',
                                            color: 'var(--text-primary)',
                                            fontSize: '0.8rem',
                                        }}
                                    />
                                    <Bar dataKey="count" fill="#ff4757" radius={[0, 4, 4, 0]} barSize={18} />
                                </BarChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="empty-state"><p>No IP data</p></div>
                        )}
                    </div>
                </div>
            </div>

            {/* MITRE + Recent Alerts */}
            <div className="grid-2">
                {/* Top MITRE Techniques */}
                <div className="card animate-in">
                    <div className="card-header">
                        <span className="card-title">Top MITRE ATT&CK Techniques</span>
                    </div>
                    <div style={{ height: 260 }}>
                        {topTechniques.length > 0 ? (
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={topTechniques} margin={{ left: 0, right: 20 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                                    <XAxis
                                        dataKey="id"
                                        stroke="var(--text-dim)"
                                        tick={{ fontSize: 10, fontFamily: 'JetBrains Mono' }}
                                        angle={-35}
                                        textAnchor="end"
                                        height={50}
                                    />
                                    <YAxis stroke="var(--text-dim)" tick={{ fontSize: 11 }} />
                                    <Tooltip
                                        contentStyle={{
                                            background: 'var(--bg-elevated)',
                                            border: '1px solid var(--border-color)',
                                            borderRadius: '8px',
                                            color: 'var(--text-primary)',
                                        }}
                                    />
                                    <Bar dataKey="count" fill="var(--accent-primary)" radius={[4, 4, 0, 0]} barSize={24} />
                                </BarChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="empty-state"><p>No techniques</p></div>
                        )}
                    </div>
                </div>

                {/* Recent Alerts */}
                <div className="card animate-in">
                    <div className="card-header">
                        <span className="card-title">Recent Alerts</span>
                        <Clock size={14} style={{ color: 'var(--text-dim)' }} />
                    </div>
                    <div style={{ maxHeight: 290, overflowY: 'auto' }}>
                        {(metrics.recent_alerts || []).map((alert, idx) => (
                            <div key={idx} style={{
                                display: 'flex', alignItems: 'center', gap: '0.75rem',
                                padding: '0.6rem 0', borderBottom: '1px solid var(--border-color)',
                            }}>
                                <span className={`severity-badge severity-${alert.severity}`}>
                                    {alert.severity}
                                </span>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ fontSize: '0.82rem', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                        {alert.title}
                                    </div>
                                    <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                                        {alert.source_ip || 'no source IP'} • {alert.detection_type}
                                    </div>
                                </div>
                                {alert.mitre_technique_ids?.slice(0, 2).map((t, i) => (
                                    <span key={i} className="tag">{t}</span>
                                ))}
                            </div>
                        ))}
                        {!metrics.recent_alerts?.length && (
                            <div className="empty-state"><p>No recent alerts</p></div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}

function FileTextIcon() {
    return <Activity size={18} />;
}
