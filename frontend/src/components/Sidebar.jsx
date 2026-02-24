import { NavLink, useLocation } from 'react-router-dom';
import {
    LayoutDashboard,
    Bell,
    ShieldAlert,
    FileText,
    Target,
    Search,
    Shield,
    LogOut,
    Terminal,
    Activity,
    Zap,
    Settings,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import { fetchDashboardMetrics } from '../api';

export default function Sidebar({ user, onLogout }) {
    const location = useLocation();
    const [alertCount, setAlertCount] = useState(0);

    useEffect(() => {
        fetchDashboardMetrics()
            .then(data => setAlertCount(data.total_alerts || 0))
            .catch(() => { });
    }, [location.pathname]);

    const navItems = [
        { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
        { path: '/alerts', icon: Bell, label: 'Alerts', badge: alertCount },
        { path: '/incidents', icon: ShieldAlert, label: 'Incidents' },
        { path: '/logs', icon: Terminal, label: 'Log Ingestion' },
        { path: '/mitre', icon: Target, label: 'MITRE ATT&CK' },
        { path: '/intel', icon: Search, label: 'Threat Intel' },
        { path: '/soar', icon: Zap, label: 'SOAR Playbooks' },
        { path: '/admin', icon: Settings, label: 'Admin Panel' },
    ];

    const initials = user?.username
        ? user.username.slice(0, 2).toUpperCase()
        : '??';

    return (
        <aside className="sidebar">
            <div className="sidebar-brand">
                <div className="brand-icon">
                    <Shield size={20} color="#000" />
                </div>
                <div>
                    <h1>THREAT_TRIAGE</h1>
                    <div className="brand-version">SOC Engine v1.0</div>
                </div>
            </div>

            <nav className="sidebar-nav">
                <div className="nav-section-label">// Operations</div>
                {navItems.slice(0, 4).map(item => (
                    <NavLink
                        key={item.path}
                        to={item.path}
                        end={item.path === '/'}
                        className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                    >
                        <item.icon className="nav-icon" size={16} />
                        <span>{item.label}</span>
                        {item.badge > 0 && <span className="nav-badge">{item.badge}</span>}
                    </NavLink>
                ))}

                <div className="nav-section-label">// Intelligence</div>
                {navItems.slice(4, 6).map(item => (
                    <NavLink
                        key={item.path}
                        to={item.path}
                        className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                    >
                        <item.icon className="nav-icon" size={16} />
                        <span>{item.label}</span>
                    </NavLink>
                ))}

                <div className="nav-section-label">// Automation</div>
                {navItems.slice(6).map(item => (
                    <NavLink
                        key={item.path}
                        to={item.path}
                        className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                    >
                        <item.icon className="nav-icon" size={16} />
                        <span>{item.label}</span>
                    </NavLink>
                ))}
            </nav>

            {user && (
                <div className="sidebar-user">
                    <div className="sidebar-user-avatar">{initials}</div>
                    <div className="sidebar-user-info">
                        <div className="sidebar-user-name">{user.username}</div>
                        <div className="sidebar-user-role">{user.role || 'analyst'}</div>
                    </div>
                    <button className="sidebar-logout" onClick={onLogout} title="Logout">
                        <LogOut size={14} />
                    </button>
                </div>
            )}

            <div className="sidebar-footer">
                <div className="status-dot" />
                <span>SYSTEM ACTIVE</span>
            </div>
        </aside>
    );
}
