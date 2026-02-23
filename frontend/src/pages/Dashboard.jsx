import { useState, useEffect, useCallback } from 'react';
import {
    BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
    PieChart, Pie, Cell, Legend,
} from 'recharts';
import { Activity, AlertTriangle, Shield, Crosshair, Wifi, WifiOff } from 'lucide-react';
import { getDashboardMetrics } from '../api';
import useWebSocket from '../hooks/useWebSocket';

const SEV_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' };

export default function Dashboard() {
    const [metrics, setMetrics] = useState(null);
    const [loading, setLoading] = useState(true);
    const [newAlertFlash, setNewAlertFlash] = useState(null);

    const fetchMetrics = useCallback(async () => {
        try {
            const data = await getDashboardMetrics();
            setMetrics(data);
        } catch (e) { /* ignore */ }
        setLoading(false);
    }, []);

    useEffect(() => { fetchMetrics(); }, [fetchMetrics]);

    // ── WebSocket for live updates ───────────────────────────────────────
    const handleWsMessage = useCallback((msg) => {
        if (msg.type === 'new_alert') {
            const alert = msg.data;
            setMetrics(prev => {
                if (!prev) return prev;
                // Update counts
                const updated = {
                    ...prev,
                    total_alerts: prev.total_alerts + 1,
                    recent_alerts: [alert, ...(prev.recent_alerts || [])].slice(0, 5),
                };
                // Update severity counts
                const bySev = { ...(prev.alerts_by_severity || {}) };
                bySev[alert.severity] = (bySev[alert.severity] || 0) + 1;
                updated.alerts_by_severity = bySev;
                return updated;
            });
            // Flash notification for high/critical
            if (alert.severity === 'critical' || alert.severity === 'high') {
                setNewAlertFlash(alert);
                setTimeout(() => setNewAlertFlash(null), 4000);
            }
        } else if (msg.type === 'stats_update') {
            // Full stats refresh
            fetchMetrics();
        }
    }, [fetchMetrics]);

    const { isConnected } = useWebSocket('ws://localhost:8000/ws/alerts', {
        onMessage: handleWsMessage,
    });

    if (loading) return (
        <div className="loading-state">
            <div className="loading-spinner" />
            <p>Loading dashboard...</p>
        </div>
    );

    if (!metrics) return (
        <div className="empty-state">
            <Shield size={48} style={{ marginBottom: '1rem', opacity: 0.3 }} />
            <p>No data available — ingest logs to populate the dashboard</p>
        </div>
    );

    const sevData = Object.entries(metrics.alerts_by_severity || {}).map(([key, val]) => ({
        name: key.charAt(0).toUpperCase() + key.slice(1), value: val, fill: SEV_COLORS[key] || '#6b7280',
    }));

    return (
        <div>
            <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                    <h2>📊 SOC Dashboard</h2>
                    <p>Real-time security operations overview</p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
                    {isConnected ? (
                        <><Wifi size={14} style={{ color: 'var(--success)' }} /><span style={{ color: 'var(--success)' }}>Live</span></>
                    ) : (
                        <><WifiOff size={14} style={{ color: 'var(--text-dim)' }} /><span style={{ color: 'var(--text-dim)' }}>Offline</span></>
                    )}
                </div>
            </div>

            {/* Alert toast */}
            {newAlertFlash && (
                <div className="animate-in" style={{
                    padding: '0.75rem 1rem', marginBottom: '1rem',
                    borderRadius: 'var(--radius-md)',
                    background: newAlertFlash.severity === 'critical' ? 'var(--critical-bg)' : 'var(--warning-bg, rgba(249,115,22,0.1))',
                    border: `1px solid ${newAlertFlash.severity === 'critical' ? 'var(--critical-border)' : 'rgba(249,115,22,0.3)'}`,
                    display: 'flex', alignItems: 'center', gap: '0.75rem',
                }}>
                    <AlertTriangle size={18} style={{ color: 'var(--critical)', flexShrink: 0 }} />
                    <div>
                        <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>🔴 New {newAlertFlash.severity.toUpperCase()} Alert</div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{newAlertFlash.title}</div>
                    </div>
                </div>
            )}

            {/* Stat Cards */}
            <div className="grid-4">
                <div className="stat-card">
                    <div className="stat-icon"><Activity size={20} /></div>
                    <div className="stat-value">{metrics.total_logs}</div>
                    <div className="stat-label">LOGS PROCESSED</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon" style={{ background: 'rgba(249,115,22,0.1)', color: '#f97316' }}><AlertTriangle size={20} /></div>
                    <div className="stat-value">{metrics.total_alerts}</div>
                    <div className="stat-label">ACTIVE ALERTS</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon" style={{ background: 'rgba(16,185,129,0.1)', color: '#10b981' }}><Shield size={20} /></div>
                    <div className="stat-value">{metrics.total_incidents}</div>
                    <div className="stat-label">INCIDENTS</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon" style={{ background: 'rgba(6,182,212,0.1)', color: '#06b6d4' }}><Crosshair size={20} /></div>
                    <div className="stat-value">{metrics.total_iocs}</div>
                    <div className="stat-label">IOCS</div>
                </div>
            </div>

            {/* Charts Row */}
            <div className="grid-2" style={{ marginTop: '1.5rem' }}>
                <div className="card">
                    <div className="card-header"><span className="card-title">ALERT SEVERITY DISTRIBUTION</span></div>
                    {sevData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={260}>
                            <PieChart>
                                <Pie data={sevData} cx="50%" cy="50%" innerRadius={60} outerRadius={100}
                                    dataKey="value" nameKey="name" paddingAngle={3} stroke="none">
                                    {sevData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                                </Pie>
                                <Legend iconType="circle" wrapperStyle={{ fontSize: '0.8rem' }}
                                    formatter={(val) => <span style={{ color: 'var(--text-primary)' }}>{val}</span>} />
                                <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, fontSize: '0.8rem' }} />
                            </PieChart>
                        </ResponsiveContainer>
                    ) : <div className="empty-state"><p>No alerts yet</p></div>}
                </div>

                <div className="card">
                    <div className="card-header"><span className="card-title">TOP THREAT SOURCE IPS</span></div>
                    {metrics.top_source_ips?.length > 0 ? (
                        <ResponsiveContainer width="100%" height={260}>
                            <BarChart data={metrics.top_source_ips} layout="vertical" margin={{ left: 10, right: 20 }}>
                                <XAxis type="number" stroke="var(--text-dim)" tick={{ fontSize: 11 }} />
                                <YAxis type="category" dataKey="ip" width={120}
                                    stroke="var(--text-dim)" tick={{ fontSize: 11, fill: 'var(--text-secondary)' }} />
                                <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, fontSize: '0.8rem' }} />
                                <Bar dataKey="count" fill="#f472b6" radius={[0, 4, 4, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    ) : <div className="empty-state"><p>No IP data</p></div>}
                </div>
            </div>

            {/* Bottom Row */}
            <div className="grid-2" style={{ marginTop: '1.5rem' }}>
                <div className="card">
                    <div className="card-header"><span className="card-title">TOP MITRE ATT&CK TECHNIQUES</span></div>
                    {metrics.top_mitre_techniques?.length > 0 ? (
                        <ResponsiveContainer width="100%" height={200}>
                            <BarChart data={metrics.top_mitre_techniques.slice(0, 5)}>
                                <XAxis dataKey="technique_id" stroke="var(--text-dim)" tick={{ fontSize: 10 }} />
                                <YAxis stroke="var(--text-dim)" tick={{ fontSize: 10 }} />
                                <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, fontSize: '0.8rem' }} />
                                <Bar dataKey="count" fill="#818cf8" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    ) : <div className="empty-state"><p>No MITRE data</p></div>}
                </div>

                <div className="card">
                    <div className="card-header">
                        <span className="card-title">RECENT ALERTS</span>
                        {isConnected && <Wifi size={14} style={{ color: 'var(--success)' }} />}
                    </div>
                    {metrics.recent_alerts?.length > 0 ? (
                        <div>
                            {metrics.recent_alerts.map((alert, idx) => (
                                <div key={alert.id || idx} className="animate-in" style={{
                                    display: 'flex', alignItems: 'center', gap: '0.75rem',
                                    padding: '0.6rem 0', borderBottom: '1px solid var(--border-color)',
                                }}>
                                    <span className={`severity-badge severity-${alert.severity}`}>{alert.severity.toUpperCase()}</span>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{ fontSize: '0.82rem', fontWeight: 600 }}>{alert.title}</div>
                                    </div>
                                    <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                                        {(alert.mitre_technique_ids || []).map(t => (
                                            <span key={t} className="tag">{t}</span>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : <div className="empty-state"><p>No alerts yet</p></div>}
                </div>
            </div>
        </div>
    );
}
