import { useState } from 'react';
import {
    Search, Globe, Hash, Link2, Shield, AlertTriangle,
    CheckCircle, XCircle, Loader,
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

    return (
        <div>
            <div className="page-header">
                <h2>🔍 Threat Intelligence</h2>
                <p>Look up IOCs against VirusTotal, AlienVault OTX, and AbuseIPDB</p>
            </div>

            {/* Input */}
            <div className="card" style={{ marginBottom: '1rem' }}>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
                    <div>
                        <label className="form-label">IOC Type</label>
                        <select className="form-select" style={{ minWidth: 140 }}
                            value={iocType} onChange={e => setIocType(e.target.value)}>
                            {IOC_TYPES.map(t => (
                                <option key={t.value} value={t.value}>{t.label}</option>
                            ))}
                        </select>
                    </div>
                    <div style={{ flex: 1 }}>
                        <label className="form-label">Value</label>
                        <input
                            className="form-input"
                            placeholder={selectedType?.placeholder}
                            value={value}
                            onChange={e => setValue(e.target.value)}
                            onKeyDown={e => e.key === 'Enter' && handleLookup()}
                            style={{ fontFamily: 'JetBrains Mono', fontSize: '0.85rem' }}
                        />
                    </div>
                    <button className="btn btn-primary" onClick={handleLookup} disabled={loading || !value.trim()}>
                        {loading ? <Loader size={16} className="loading-spinner" style={{ width: 16, height: 16, margin: 0, borderWidth: 2 }} /> : <Search size={16} />}
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
                            <Shield size={40} style={{ marginBottom: '1rem', opacity: 0.3 }} />
                            <p>Enter an IOC to search threat intelligence</p>
                        </div>
                    )}

                    {loading && (
                        <div className="loading-state">
                            <div className="loading-spinner" />
                            <p>Querying providers...</p>
                        </div>
                    )}

                    {result && !result.error && (
                        <div className="animate-in">
                            {/* Score Gauge */}
                            <div style={{
                                textAlign: 'center',
                                padding: '1.5rem',
                                marginBottom: '1rem',
                                borderRadius: 'var(--radius-md)',
                                background: result.aggregated_score > 70
                                    ? 'var(--critical-bg)'
                                    : result.aggregated_score > 30
                                        ? 'var(--medium-bg)'
                                        : 'var(--success-bg)',
                                border: `1px solid ${result.aggregated_score > 70
                                    ? 'var(--critical-border)'
                                    : result.aggregated_score > 30
                                        ? 'var(--medium-border)'
                                        : 'rgba(16,185,129,0.25)'}`,
                            }}>
                                <div style={{
                                    fontSize: '3rem', fontWeight: 900, fontFamily: 'JetBrains Mono',
                                    color: result.aggregated_score > 70 ? 'var(--critical)' : result.aggregated_score > 30 ? 'var(--medium)' : 'var(--success)',
                                }}>
                                    {Math.round(result.aggregated_score || 0)}
                                </div>
                                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                                    Aggregated Threat Score
                                </div>
                                <div style={{
                                    marginTop: '0.5rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem',
                                }}>
                                    {result.is_malicious ? (
                                        <>
                                            <XCircle size={16} style={{ color: 'var(--critical)' }} />
                                            <span style={{ fontWeight: 700, color: 'var(--critical)' }}>MALICIOUS</span>
                                        </>
                                    ) : (
                                        <>
                                            <CheckCircle size={16} style={{ color: 'var(--success)' }} />
                                            <span style={{ fontWeight: 700, color: 'var(--success)' }}>CLEAN</span>
                                        </>
                                    )}
                                </div>
                            </div>

                            {/* Details */}
                            <div style={{ fontSize: '0.85rem' }}>
                                {result.tags?.length > 0 && (
                                    <div className="detail-row">
                                        <span className="detail-label">Tags</span>
                                        <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                                            {result.tags.map((t, i) => <span key={i} className="tag">{t}</span>)}
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
                                        <span className="detail-value mono">{result.asn}</span>
                                    </div>
                                )}
                                {result.org && (
                                    <div className="detail-row">
                                        <span className="detail-label">Organization</span>
                                        <span className="detail-value">{result.org}</span>
                                    </div>
                                )}
                                <div className="detail-row">
                                    <span className="detail-label">Providers</span>
                                    <span className="detail-value">{result.providers_queried || 0} queried</span>
                                </div>
                            </div>

                            {/* Per-provider results */}
                            {result.provider_results && Object.entries(result.provider_results).map(([name, prov], idx) => (
                                <div key={idx} style={{
                                    marginTop: '0.75rem', padding: '0.75rem',
                                    background: 'var(--bg-elevated)', borderRadius: 'var(--radius-sm)',
                                    border: `1px solid ${prov.is_malicious ? 'var(--critical-border)' : 'var(--border-color)'}`,
                                }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                                        <span style={{ fontWeight: 700, fontSize: '0.8rem', textTransform: 'capitalize' }}>{name}</span>
                                        <span className={`severity-badge ${prov.is_malicious ? 'severity-critical' : 'severity-low'}`}>
                                            {prov.is_malicious ? 'MALICIOUS' : 'CLEAN'}
                                        </span>
                                    </div>
                                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                                        Score: <span className="mono" style={{ fontWeight: 700 }}>{Math.round(prov.reputation_score || 0)}</span>
                                        {prov.confidence > 0 && <> · Confidence: <span className="mono">{Math.round(prov.confidence)}%</span></>}
                                    </div>
                                    {prov.description && (
                                        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>{prov.description}</div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}

                    {result?.error && (
                        <div style={{ padding: '1rem', background: 'var(--critical-bg)', borderRadius: 'var(--radius-sm)', color: 'var(--critical)' }}>
                            Error: {result.error}
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
                            <p style={{ fontSize: '0.85rem' }}>Recent lookups appear here</p>
                        </div>
                    ) : (
                        <div>
                            {history.map((h, idx) => (
                                <div key={idx} className="animate-in"
                                    style={{
                                        display: 'flex', alignItems: 'center', gap: '0.75rem',
                                        padding: '0.6rem 0', borderBottom: '1px solid var(--border-color)',
                                        cursor: 'pointer',
                                    }}
                                    onClick={() => { setIocType(h.type); setValue(h.value); }}
                                >
                                    <span className="tag" style={{ minWidth: 40, justifyContent: 'center' }}>{h.type}</span>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div className="mono" style={{ fontSize: '0.82rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                            {h.value}
                                        </div>
                                        <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                                            {h.time.toLocaleTimeString()}
                                        </div>
                                    </div>
                                    <div style={{
                                        fontFamily: 'JetBrains Mono', fontWeight: 800, fontSize: '0.9rem',
                                        color: h.score > 70 ? 'var(--critical)' : h.score > 30 ? 'var(--medium)' : 'var(--success)',
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
