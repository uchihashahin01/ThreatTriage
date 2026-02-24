import { useState, useEffect, useCallback } from 'react';
import {
    BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
    PieChart, Pie, Cell, Legend,
} from 'recharts';
import {
    Activity, AlertTriangle, Shield, Crosshair,
    Wifi, WifiOff, Terminal, Zap,
} from 'lucide-react';
import { getDashboardMetrics } from '../api';
import useWebSocket from '../hooks/useWebSocket';

const SEV_COLORS = {
    critical: '#ff0040',
    high: '#ff6b00',
    medium: '#ffb800',
    low: '#00d4ff',
    info: '#5a6b80',
};

export default function Dashboard() {
    const [metrics, setMetrics] = useState(null);
    const [loading, setLoading] = useState(true);
    const [newAlertFlash, setNewAlertFlash] = useState(null);
    const [uptimeSeconds, setUptimeSeconds] = useState(0);

    const fetchMetrics = useCallback(async () => {
        try {
            const data = await getDashboardMetrics();
            setMetrics(data);
        } catch (e) { /* ignore */ }
        setLoading(false);
    }, []);

    useEffect(() => { fetchMetrics(); }, [fetchMetrics]);

    // Uptime counter
    useEffect(() => {
        const t = setInterval(() => setUptimeSeconds(s => s + 1), 1000);
        return () => clearInterval(t);
    }, []);

    // ── WebSocket for live updates ───────────────────────────────────────
    const handleWsMessage = useCallback((msg) => {
        if (msg.type === 'new_alert') {
            const alert = msg.data;
            setMetrics(prev => {
                if (!prev) return prev;
                const updated = {
                    ...prev,
                    total_alerts: prev.total_alerts + 1,
                    recent_alerts: [alert, ...(prev.recent_alerts || [])].slice(0, 8),
                };
                const bySev = { ...(prev.alerts_by_severity || {}) };
                bySev[alert.severity] = (bySev[alert.severity] || 0) + 1;
                updated.alerts_by_severity = bySev;
                return updated;
            });
            if (alert.severity === 'critical' || alert.severity === 'high') {
                setNewAlertFlash(alert);
                setTimeout(() => setNewAlertFlash(null), 5000);
            }
        } else if (msg.type === 'stats_update') {
            fetchMetrics();
        }
    }, [fetchMetrics]);

    const { isConnected } = useWebSocket('ws://localhost:8000/ws/alerts', {
        onMessage: handleWsMessage,
    });

    const formatUptime = (s) => {
        const h = Math.floor(s / 3600);
        const m = Math.floor((s % 3600) / 60);
        const sec = s % 60;
        return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
    };

    if (loading) return (
        <div className="loading-state">
            <div className="loading-spinner" />
            <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.8rem' }}>Initializing dashboard...</p>
        </div>
    );

    if (!metrics) return (
        <div className="empty-state">
            <Terminal size={48} style={{ marginBottom: '1rem', opacity: 0.3, color: 'var(--cyber-green)' }} />
            <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.8rem' }}>
                {'>'} No data — ingest logs to populate
            </p>
        </div>
    );

    const sevData = Object.entries(metrics.alerts_by_severity || {}).map(([key, val]) => ({
        name: key.charAt(0).toUpperCase() + key.slice(1), value: val, fill: SEV_COLORS[key] || '#5a6b80',
    }));

    const recentAlerts = metrics.recent_alerts || [];

    return (
        <div>
            <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h2>
                        <Activity className="page-icon" size={20} />
                        SOC Dashboard
                    </h2>
                    <p>{'>'} real-time security operations overview</p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className={`live-indicator ${isConnected ? 'connected' : 'disconnected'}`}>
                        <div className="live-dot" />
                        {isConnected ? 'LIVE' : 'OFFLINE'}
                    </div>
                    <div style={{
                        fontFamily: 'Share Tech Mono, monospace', fontSize: '0.75rem',
                        color: 'var(--cyber-green)', letterSpacing: '0.1em',
                    }}>
                        {formatUptime(uptimeSeconds)}
                    </div>
                </div>
            </div>

            {/* Alert toast */}
            {newAlertFlash && (
                <div className={`alert-toast ${newAlertFlash.severity}`}>
                    <Zap size={16} style={{ color: 'var(--critical)', flexShrink: 0 }} />
                    <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: 700, fontSize: '0.78rem', fontFamily: 'JetBrains Mono' }}>
                            [ALERT] {newAlertFlash.severity.toUpperCase()}
                        </div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                            {newAlertFlash.title}
                        </div>
                    </div>
                </div>
            )}

            {/* Stat Cards */}
            <div className="grid-4">
                <div className="stat-card animate-in animate-in-delay-1">
                    <div className="stat-icon"><Activity size={16} /></div>
                    <div className="stat-value">{metrics.total_logs?.toLocaleString()}</div>
                    <div className="stat-label">Logs Processed</div>
                </div>
                <div className="stat-card animate-in animate-in-delay-2">
                    <div className="stat-icon" style={{ background: 'rgba(255,0,64,0.08)', color: 'var(--critical)' }}>
                        <AlertTriangle size={16} />
                    </div>
                    <div className="stat-value" style={{ color: metrics.total_alerts > 0 ? 'var(--critical)' : undefined }}>
                        {metrics.total_alerts}
                    </div>
                    <div className="stat-label">Active Alerts</div>
                </div>
                <div className="stat-card animate-in animate-in-delay-3">
                    <div className="stat-icon" style={{ background: 'rgba(0,212,255,0.08)', color: 'var(--cyber-blue)' }}>
                        <Shield size={16} />
                    </div>
                    <div className="stat-value">{metrics.total_incidents}</div>
                    <div className="stat-label">Incidents</div>
                </div>
                <div className="stat-card animate-in animate-in-delay-4">
                    <div className="stat-icon" style={{ background: 'rgba(168,85,247,0.08)', color: 'var(--cyber-purple)' }}>
                        <Crosshair size={16} />
                    </div>
                    <div className="stat-value">{metrics.total_iocs}</div>
                    <div className="stat-label">IOCs Tracked</div>
                </div>
            </div>

            {/* Charts Row */}
            <div className="grid-2" style={{ marginBottom: '0.75rem' }}>
                <div className="card animate-in">
                    <div className="card-header">
                        <span className="card-title">Alert Severity Distribution</span>
                    </div>
                    {sevData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={240}>
                            <PieChart>
                                <Pie data={sevData} cx="50%" cy="50%" innerRadius={55} outerRadius={90}
                                    dataKey="value" nameKey="name" paddingAngle={3} stroke="none">
                                    {sevData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                                </Pie>
                                <Legend iconType="circle" iconSize={6}
                                    wrapperStyle={{ fontSize: '0.7rem', fontFamily: 'JetBrains Mono' }}
                                    formatter={(val) => <span style={{ color: 'var(--text-secondary)' }}>{val}</span>} />
                                <Tooltip contentStyle={{
                                    background: 'var(--bg-card)', border: '1px solid var(--border-color)',
                                    borderRadius: 4, fontSize: '0.75rem', fontFamily: 'JetBrains Mono',
                                }} />
                            </PieChart>
                        </ResponsiveContainer>
                    ) : (
                        <div className="empty-state" style={{ padding: '2rem' }}>
                            <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem' }}>No alerts detected</p>
                        </div>
                    )}
                </div>

                <div className="card animate-in">
                    <div className="card-header">
                        <span className="card-title">Top Threat Source IPs</span>
                    </div>
                    {metrics.top_source_ips?.length > 0 ? (
                        <ResponsiveContainer width="100%" height={240}>
                            <BarChart data={metrics.top_source_ips} layout="vertical" margin={{ left: 10, right: 20 }}>
                                <XAxis type="number" stroke="var(--text-dim)" tick={{ fontSize: 10, fontFamily: 'JetBrains Mono' }} />
                                <YAxis type="category" dataKey="ip" width={110}
                                    stroke="var(--text-dim)"
                                    tick={{ fontSize: 10, fill: '#00ff41', fontFamily: 'JetBrains Mono' }} />
                                <Tooltip contentStyle={{
                                    background: 'var(--bg-card)', border: '1px solid var(--border-color)',
                                    borderRadius: 4, fontSize: '0.75rem', fontFamily: 'JetBrains Mono',
                                }} />
                                <Bar dataKey="count" fill="#ff0040" radius={[0, 3, 3, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    ) : (
                        <div className="empty-state" style={{ padding: '2rem' }}>
                            <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem' }}>No threat IPs</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Recent Alerts Feed */}
            <div className="card animate-in">
                <div className="card-header">
                    <span className="card-title">Live Alert Feed</span>
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                        {recentAlerts.length} recent
                    </span>
                </div>
                {recentAlerts.length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                        {recentAlerts.map((alert, i) => (
                            <div key={alert.id || i} className="animate-in" style={{
                                display: 'flex', alignItems: 'center', gap: '0.75rem',
                                padding: '0.5rem 0.6rem', borderRadius: 'var(--radius-sm)',
                                background: i === 0 ? 'rgba(0,255,65,0.02)' : 'transparent',
                                borderLeft: `2px solid ${SEV_COLORS[alert.severity] || 'var(--border-color)'}`,
                            }}>
                                <span className={`severity-badge severity-${alert.severity}`} style={{ minWidth: 65 }}>
                                    {alert.severity}
                                </span>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{
                                        fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)',
                                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                    }}>
                                        {alert.title}
                                    </div>
                                </div>
                                {alert.source_ip && (
                                    <span className="mono" style={{ fontSize: '0.7rem', color: '#00ff41' }}>
                                        {alert.source_ip}
                                    </span>
                                )}
                                <div style={{ display: 'flex', gap: '0.2rem' }}>
                                    {(alert.mitre_technique_ids || []).slice(0, 2).map(t => (
                                        <span key={t} className="tag" style={{ fontSize: '0.6rem' }}>{t}</span>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div className="empty-state" style={{ padding: '1.5rem' }}>
                        <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem' }}>
                            {'>'} Awaiting incoming alerts...
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
}
