import { useState, useEffect, useCallback } from 'react';
import {
    Bell, Filter, RefreshCw, CheckCircle, XCircle,
    Search as SearchIcon, Zap, Eye, Archive,
} from 'lucide-react';
import { getAlerts, updateAlertStatus } from '../api';
import useWebSocket from '../hooks/useWebSocket';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function Alerts() {
    const [alerts, setAlerts] = useState([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(true);
    const [sevFilter, setSevFilter] = useState('');
    const [statusFilter, setStatusFilter] = useState('');
    const [searchText, setSearchText] = useState('');
    const [newAlertIds, setNewAlertIds] = useState(new Set());

    const fetchAlerts = useCallback(async () => {
        try {
            const data = await getAlerts(sevFilter || undefined, statusFilter || undefined, 100);
            setAlerts(data.items || []);
            setTotal(data.total || 0);
        } catch (e) { /* ignore */ }
        setLoading(false);
    }, [sevFilter, statusFilter]);

    useEffect(() => { fetchAlerts(); }, [fetchAlerts]);

    // ── WebSocket for live updates ───────────────────────────────────────
    const handleWsMessage = useCallback((msg) => {
        if (msg.type === 'new_alert') {
            const alert = msg.data;
            setAlerts(prev => [alert, ...prev]);
            setTotal(prev => prev + 1);
            setNewAlertIds(prev => new Set(prev).add(alert.id));
            setTimeout(() => {
                setNewAlertIds(prev => {
                    const next = new Set(prev);
                    next.delete(alert.id);
                    return next;
                });
            }, 4000);
        }
    }, []);

    const { isConnected } = useWebSocket('ws://localhost:8000/ws/alerts', {
        onMessage: handleWsMessage,
    });

    const handleStatusChange = async (alertId, newStatus) => {
        try {
            await updateAlertStatus(alertId, newStatus);
            setAlerts(prev =>
                prev.map(a => a.id === alertId ? { ...a, status: newStatus } : a)
            );
        } catch (e) {
            console.error('Failed to update status:', e);
        }
    };

    // Filter + search
    let filtered = [...alerts].sort((a, b) =>
        (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5)
    );
    if (searchText.trim()) {
        const q = searchText.toLowerCase();
        filtered = filtered.filter(a =>
            (a.title || '').toLowerCase().includes(q) ||
            (a.source_ip || '').includes(q) ||
            (a.description || '').toLowerCase().includes(q) ||
            (a.mitre_technique_ids || []).some(t => t.toLowerCase().includes(q))
        );
    }

    const critCount = alerts.filter(a => a.severity === 'critical').length;
    const highCount = alerts.filter(a => a.severity === 'high').length;
    const newCount = alerts.filter(a => a.status === 'new').length;

    return (
        <div>
            <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h2>
                        <Bell className="page-icon" size={20} />
                        Security Alerts
                    </h2>
                    <p>{'>'} detection engine output — {total} total</p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <div className={`live-indicator ${isConnected ? 'connected' : 'disconnected'}`}>
                        <div className="live-dot" />
                        {isConnected ? 'LIVE' : 'OFFLINE'}
                    </div>
                </div>
            </div>

            {/* Quick Stats */}
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
                {critCount > 0 && (
                    <span className="severity-badge severity-critical" style={{ fontSize: '0.65rem' }}>
                        <Zap size={10} /> {critCount} CRITICAL
                    </span>
                )}
                {highCount > 0 && (
                    <span className="severity-badge severity-high" style={{ fontSize: '0.65rem' }}>
                        {highCount} HIGH
                    </span>
                )}
                {newCount > 0 && (
                    <span className="tag tag-green" style={{ fontSize: '0.65rem' }}>
                        {newCount} NEW
                    </span>
                )}
            </div>

            {/* Filters */}
            <div className="card" style={{ marginBottom: '0.75rem', padding: '0.75rem 1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                    <Filter size={14} style={{ color: 'var(--text-dim)' }} />
                    <select className="form-select" style={{ width: 'auto', minWidth: 130, fontSize: '0.75rem', padding: '0.35rem 1.8rem 0.35rem 0.6rem' }}
                        value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
                        <option value="">All Severity</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                    <select className="form-select" style={{ width: 'auto', minWidth: 130, fontSize: '0.75rem', padding: '0.35rem 1.8rem 0.35rem 0.6rem' }}
                        value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
                        <option value="">All Status</option>
                        <option value="new">New</option>
                        <option value="investigating">Investigating</option>
                        <option value="resolved">Resolved</option>
                        <option value="false_positive">False Positive</option>
                    </select>
                    <div style={{ position: 'relative', flex: 1, minWidth: 180 }}>
                        <SearchIcon size={12} style={{
                            position: 'absolute', left: '0.6rem', top: '50%',
                            transform: 'translateY(-50%)', color: 'var(--text-dim)',
                        }} />
                        <input
                            className="form-input"
                            placeholder="Search alerts..."
                            value={searchText}
                            onChange={e => setSearchText(e.target.value)}
                            style={{ paddingLeft: '2rem', fontSize: '0.75rem', padding: '0.35rem 0.6rem 0.35rem 2rem' }}
                        />
                    </div>
                    <button className="btn btn-secondary btn-sm" onClick={fetchAlerts}>
                        <RefreshCw size={12} /> Refresh
                    </button>
                </div>
            </div>

            {/* Table */}
            {loading ? (
                <div className="loading-state"><div className="loading-spinner" /><p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.8rem' }}>Loading alerts...</p></div>
            ) : filtered.length === 0 ? (
                <div className="card empty-state">
                    <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.8rem' }}>{'>'} No alerts matching criteria</p>
                </div>
            ) : (
                <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                    <div style={{ overflowX: 'auto' }}>
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th style={{ width: 85 }}>SEVERITY</th>
                                    <th>ALERT</th>
                                    <th style={{ width: 100 }}>TYPE</th>
                                    <th style={{ width: 120 }}>SOURCE IP</th>
                                    <th style={{ width: 140 }}>MITRE</th>
                                    <th style={{ width: 100 }}>STATUS</th>
                                    <th style={{ width: 130 }}>ACTIONS</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.map(alert => (
                                    <tr key={alert.id}
                                        className={newAlertIds.has(alert.id) ? 'new-alert-flash' : ''}
                                        style={{ animation: newAlertIds.has(alert.id) ? 'fadeInUp 0.3s ease-out' : undefined }}>
                                        <td>
                                            <span className={`severity-badge severity-${alert.severity}`}>
                                                {alert.severity}
                                            </span>
                                        </td>
                                        <td>
                                            <div style={{ fontWeight: 600, fontSize: '0.78rem', color: 'var(--text-bright)' }}>
                                                {alert.title}
                                            </div>
                                            <div style={{
                                                fontSize: '0.68rem', color: 'var(--text-dim)',
                                                maxWidth: 300, overflow: 'hidden',
                                                textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                            }}>
                                                {alert.description}
                                            </div>
                                        </td>
                                        <td><span className="tag">{alert.detection_type}</span></td>
                                        <td>
                                            <span className="mono" style={{ fontSize: '0.75rem', color: '#00ff41' }}>
                                                {alert.source_ip || '—'}
                                            </span>
                                        </td>
                                        <td>
                                            <div style={{ display: 'flex', gap: '0.2rem', flexWrap: 'wrap' }}>
                                                {(alert.mitre_technique_ids || []).slice(0, 3).map(t => (
                                                    <span key={t} className="tag" style={{ fontSize: '0.6rem' }}>{t}</span>
                                                ))}
                                            </div>
                                        </td>
                                        <td>
                                            <span className={`status-${alert.status}`} style={{
                                                fontSize: '0.68rem', fontWeight: 700,
                                                textTransform: 'uppercase',
                                                fontFamily: 'JetBrains Mono',
                                            }}>
                                                {alert.status?.replace('_', ' ')}
                                            </span>
                                        </td>
                                        <td>
                                            <div style={{ display: 'flex', gap: '0.3rem' }}>
                                                {alert.status === 'new' && (
                                                    <button className="btn btn-sm btn-secondary"
                                                        style={{ fontSize: '0.65rem', padding: '0.15rem 0.4rem' }}
                                                        onClick={() => handleStatusChange(alert.id, 'investigating')}
                                                        title="Investigate">
                                                        <Eye size={10} /> Investigate
                                                    </button>
                                                )}
                                                {alert.status === 'investigating' && (
                                                    <>
                                                        <button className="btn btn-sm btn-primary"
                                                            style={{ fontSize: '0.65rem', padding: '0.15rem 0.4rem' }}
                                                            onClick={() => handleStatusChange(alert.id, 'resolved')}
                                                            title="Resolve">
                                                            <CheckCircle size={10} /> Resolve
                                                        </button>
                                                        <button className="btn btn-sm btn-ghost"
                                                            style={{ fontSize: '0.65rem', padding: '0.15rem 0.4rem', color: 'var(--text-dim)' }}
                                                            onClick={() => handleStatusChange(alert.id, 'false_positive')}
                                                            title="False Positive">
                                                            <XCircle size={10} />
                                                        </button>
                                                    </>
                                                )}
                                                {(alert.status === 'resolved' || alert.status === 'false_positive') && (
                                                    <span style={{ fontSize: '0.65rem', color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                                                        —
                                                    </span>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
}
