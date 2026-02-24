import { useState } from 'react';
import {
    Search, Globe, Hash, Link2, Shield,
    CheckCircle, XCircle, Loader, Radar,
} from 'lucide-react';
import { lookupIOC } from '../api';

const IOC_TYPES = [
    { value: 'ip', label: 'IP Address', icon: Globe, placeholder: '185.220.101.1' },
    { value: 'domain', label: 'Domain', icon: Link2, placeholder: 'malicious-domain.com' },
    { value: 'hash', label: 'File Hash', icon: Hash, placeholder: 'SHA256 / MD5 hash' },
    { value: 'url', label: 'URL', icon: Link2, placeholder: 'https://suspicious-site.com/payload' },
];

export default function ThreatIntel() {
    const [iocType, setIocType] = useState('ip');
    const [value, setValue] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [history, setHistory] = useState([]);

    const handleLookup = async () => {
        if (!value.trim()) return;
        setLoading(true);
        setResult(null);
        try {
            const data = await lookupIOC(iocType, value.trim());
            setResult(data);
            setHistory(prev => [{ type: iocType, value: value.trim(), score: data.aggregated_score, time: new Date() }, ...prev.slice(0, 9)]);
        } catch (err) {
            setResult({ error: err.message });
        }
        setLoading(false);
    };

    const selectedType = IOC_TYPES.find(t => t.value === iocType);

    const scoreColor = (s) => s > 70 ? 'var(--critical)' : s > 30 ? 'var(--medium)' : 'var(--cyber-green)';

    return (
        <div>
            <div className="page-header">
                <h2>
                    <Radar className="page-icon" size={20} />
                    Threat Intelligence
                </h2>
                <p>{'>'} IOC lookup against VirusTotal, AlienVault OTX, AbuseIPDB</p>
            </div>

            {/* Input */}
            <div className="card" style={{ marginBottom: '0.75rem' }}>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
                    <div>
                        <label className="form-label" style={{ fontFamily: 'JetBrains Mono', fontSize: '0.65rem', letterSpacing: '0.05em' }}>IOC TYPE</label>
                        <select className="form-select" style={{ minWidth: 130 }}
                            value={iocType} onChange={e => setIocType(e.target.value)}>
                            {IOC_TYPES.map(t => (
                                <option key={t.value} value={t.value}>{t.label}</option>
                            ))}
                        </select>
                    </div>
                    <div style={{ flex: 1 }}>
                        <label className="form-label" style={{ fontFamily: 'JetBrains Mono', fontSize: '0.65rem', letterSpacing: '0.05em' }}>VALUE</label>
                        <input
                            className="form-input"
                            placeholder={selectedType?.placeholder}
                            value={value}
                            onChange={e => setValue(e.target.value)}
                            onKeyDown={e => e.key === 'Enter' && handleLookup()}
                            style={{ fontFamily: 'JetBrains Mono', fontSize: '0.82rem', color: 'var(--cyber-green)' }}
                        />
                    </div>
                    <button className="btn btn-primary" onClick={handleLookup} disabled={loading || !value.trim()}>
                        {loading ? <Loader size={14} className="loading-spinner" style={{ width: 14, height: 14, margin: 0, borderWidth: 2 }} /> : <Search size={14} />}
                        Lookup
                    </button>
                </div>
            </div>

            <div className="grid-2">
                {/* Results */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Lookup Result</span>
                    </div>

                    {!result && !loading && (
                        <div className="empty-state">
                            <Shield size={40} style={{ marginBottom: '1rem', opacity: 0.3, color: 'var(--cyber-green)' }} />
                            <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem' }}>
                                {'>'} enter an IOC to query threat intel
                            </p>
                        </div>
                    )}

                    {loading && (
                        <div className="loading-state">
                            <div className="loading-spinner" />
                            <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem' }}>Querying providers...</p>
                        </div>
                    )}

                    {result && !result.error && (
                        <div className="animate-in">
                            {/* Score Gauge */}
                            <div style={{
                                textAlign: 'center', padding: '1.25rem', marginBottom: '1rem',
                                borderRadius: 'var(--radius-md)',
                                background: 'var(--bg-primary)',
                                border: `1px solid ${scoreColor(result.aggregated_score)}33`,
                            }}>
                                <div style={{
                                    fontSize: '2.8rem', fontWeight: 900, fontFamily: 'JetBrains Mono',
                                    color: scoreColor(result.aggregated_score),
                                    textShadow: `0 0 20px ${scoreColor(result.aggregated_score)}44`,
                                }}>
                                    {Math.round(result.aggregated_score || 0)}
                                </div>
                                <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.2rem', fontFamily: 'JetBrains Mono', letterSpacing: '0.08em' }}>
                                    THREAT SCORE
                                </div>
                                <div style={{
                                    marginTop: '0.5rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem',
                                }}>
                                    {result.is_malicious ? (
                                        <>
                                            <XCircle size={14} style={{ color: 'var(--critical)' }} />
                                            <span style={{ fontWeight: 800, color: 'var(--critical)', fontFamily: 'JetBrains Mono', fontSize: '0.75rem', letterSpacing: '0.1em' }}>MALICIOUS</span>
                                        </>
                                    ) : (
                                        <>
                                            <CheckCircle size={14} style={{ color: 'var(--cyber-green)' }} />
                                            <span style={{ fontWeight: 800, color: 'var(--cyber-green)', fontFamily: 'JetBrains Mono', fontSize: '0.75rem', letterSpacing: '0.1em' }}>CLEAN</span>
                                        </>
                                    )}
                                </div>
                            </div>

                            {/* Details */}
                            <div style={{ fontSize: '0.82rem' }}>
                                {result.tags?.length > 0 && (
                                    <div className="detail-row">
                                        <span className="detail-label">Tags</span>
                                        <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                                            {result.tags.map((t, i) => (
                                                <span key={i} className={`tag ${t.toLowerCase().includes('malicious') || t.toLowerCase().includes('malware') ? 'tag-red' : ''}`}>{t}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                {result.country && (
                                    <div className="detail-row">
                                        <span className="detail-label">Country</span>
                                        <span className="detail-value">{result.country}</span>
                                    </div>
                                )}
                                {result.asn && (
                                    <div className="detail-row">
                                        <span className="detail-label">ASN</span>
                                        <span className="detail-value mono" style={{ color: 'var(--cyber-green)' }}>{result.asn}</span>
                                    </div>
                                )}
                                {result.org && (
                                    <div className="detail-row">
                                        <span className="detail-label">Org</span>
                                        <span className="detail-value">{result.org}</span>
                                    </div>
                                )}
                                <div className="detail-row">
                                    <span className="detail-label">Providers</span>
                                    <span className="detail-value mono">{result.providers_queried || 0} queried</span>
                                </div>
                            </div>

                            {/* Per-provider results */}
                            {result.provider_results && Object.entries(result.provider_results).map(([name, prov], idx) => (
                                <div key={idx} style={{
                                    marginTop: '0.6rem', padding: '0.6rem 0.75rem',
                                    background: 'var(--bg-elevated)', borderRadius: 'var(--radius-sm)',
                                    borderLeft: `2px solid ${prov.is_malicious ? 'var(--critical)' : 'var(--cyber-green)'}`,
                                }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                                        <span style={{ fontWeight: 700, fontSize: '0.78rem', textTransform: 'uppercase', fontFamily: 'JetBrains Mono', letterSpacing: '0.05em' }}>{name}</span>
                                        <span className={`severity-badge ${prov.is_malicious ? 'severity-critical' : 'severity-low'}`} style={{ fontSize: '0.6rem' }}>
                                            {prov.is_malicious ? 'MALICIOUS' : 'CLEAN'}
                                        </span>
                                    </div>
                                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                                        Score: <span style={{ fontWeight: 700, color: scoreColor(prov.reputation_score || 0) }}>{Math.round(prov.reputation_score || 0)}</span>
                                        {prov.confidence > 0 && <> | Conf: <span className="mono">{Math.round(prov.confidence)}%</span></>}
                                    </div>
                                    {prov.description && (
                                        <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>{prov.description}</div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}

                    {result?.error && (
                        <div className="terminal-box" style={{ borderColor: 'var(--critical)' }}>
                            <div className="terminal-output" style={{ color: 'var(--critical)' }}>
                                [ERR] {result.error}
                            </div>
                        </div>
                    )}
                </div>

                {/* History */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Lookup History</span>
                    </div>
                    {history.length === 0 ? (
                        <div className="empty-state">
                            <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem' }}>{'>'} recent lookups will appear here</p>
                        </div>
                    ) : (
                        <div>
                            {history.map((h, idx) => (
                                <div key={idx} className="animate-in"
                                    style={{
                                        display: 'flex', alignItems: 'center', gap: '0.6rem',
                                        padding: '0.5rem 0', borderBottom: '1px solid var(--border-color)',
                                        cursor: 'pointer',
                                    }}
                                    onClick={() => { setIocType(h.type); setValue(h.value); }}
                                >
                                    <span className="tag" style={{ minWidth: 36, justifyContent: 'center', fontFamily: 'JetBrains Mono', fontSize: '0.6rem' }}>{h.type.toUpperCase()}</span>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div className="mono" style={{ fontSize: '0.78rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--cyber-green)' }}>
                                            {h.value}
                                        </div>
                                        <div style={{ fontSize: '0.62rem', color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                                            {h.time.toLocaleTimeString()}
                                        </div>
                                    </div>
                                    <div style={{
                                        fontFamily: 'JetBrains Mono', fontWeight: 800, fontSize: '0.85rem',
                                        color: scoreColor(h.score),
                                    }}>
                                        {Math.round(h.score || 0)}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
