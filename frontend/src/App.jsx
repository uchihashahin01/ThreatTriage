import { useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import LogIngestion from './pages/LogIngestion';
import MitreView from './pages/MitreView';
import ThreatIntel from './pages/ThreatIntel';
import './index.css';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/logs" element={<LogIngestion />} />
            <Route path="/mitre" element={<MitreView />} />
            <Route path="/intel" element={<ThreatIntel />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
