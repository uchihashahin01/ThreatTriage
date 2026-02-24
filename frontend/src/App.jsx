import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import LogIngestion from './pages/LogIngestion';
import MitreView from './pages/MitreView';
import ThreatIntel from './pages/ThreatIntel';
import SOARDashboard from './pages/SOARDashboard';
import AdminPanel from './pages/AdminPanel';
import Login from './pages/Login';
import { getStoredUser, logout } from './api';
import './index.css';

export default function App() {
  const [user, setUser] = useState(() => getStoredUser());

  useEffect(() => {
    const handleLogout = () => setUser(null);
    window.addEventListener('auth:logout', handleLogout);
    return () => window.removeEventListener('auth:logout', handleLogout);
  }, []);

  const handleLogin = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
    logout();
    setUser(null);
  };

  if (!user) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar user={user} onLogout={handleLogout} />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/logs" element={<LogIngestion />} />
            <Route path="/mitre" element={<MitreView />} />
            <Route path="/intel" element={<ThreatIntel />} />
            <Route path="/soar" element={<SOARDashboard />} />
            <Route path="/admin" element={<AdminPanel />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
