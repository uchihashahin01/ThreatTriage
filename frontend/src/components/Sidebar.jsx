import { NavLink, useLocation } from 'react-router-dom';
import {
    LayoutDashboard,
    Bell,
    ShieldAlert,
    FileText,
    Target,
    Search,
    Shield,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import { fetchDashboardMetrics } from '../api';

export default function Sidebar() {
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
        { path: '/logs', icon: FileText, label: 'Log Ingestion' },
        { path: '/mitre', icon: Target, label: 'MITRE ATT&CK' },
        { path: '/intel', icon: Search, label: 'Threat Intel' },
    ];

    return (
        <aside className="sidebar">
            <div className="sidebar-brand">
                <div className="brand-icon">
                    <Shield size={22} color="#fff" />
                </div>
                <div>
                    <h1>ThreatTriage</h1>
                    <div className="brand-version">SOC Automation v1.0</div>
                </div>
            </div>

            <nav className="sidebar-nav">
                <div className="nav-section-label">Operations</div>
                {navItems.slice(0, 3).map(item => (
                    <NavLink
                        key={item.path}
                        to={item.path}
                        end={item.path === '/'}
                        className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                    >
                        <item.icon className="nav-icon" size={18} />
                        <span>{item.label}</span>
                        {item.badge > 0 && <span className="nav-badge">{item.badge}</span>}
                    </NavLink>
                ))}

                <div className="nav-section-label">Analysis</div>
                {navItems.slice(3).map(item => (
                    <NavLink
                        key={item.path}
                        to={item.path}
                        className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                    >
                        <item.icon className="nav-icon" size={18} />
                        <span>{item.label}</span>
                    </NavLink>
                ))}
            </nav>

            <div className="sidebar-footer">
                <div className="status-dot" />
                <span>Engine Active</span>
            </div>
        </aside>
    );
}
