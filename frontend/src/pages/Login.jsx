import { useState } from 'react';
import { Shield, Terminal, Eye, EyeOff } from 'lucide-react';
import { login, register } from '../api';

export default function Login({ onLogin }) {
    const [mode, setMode] = useState('login');
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [fullName, setFullName] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [showPw, setShowPw] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            let data;
            if (mode === 'login') {
                data = await login(username, password);
            } else {
                data = await register(username, email, password, fullName);
            }
            if (data.access_token) {
                onLogin(data.user);
            } else {
                setError(data.detail || 'Authentication failed');
            }
        } catch (err) {
            setError('Connection failed — is the server running?');
        }
        setLoading(false);
    };

    // Allow skipping auth in demo mode
    const handleDemoLogin = () => {
        const demoUser = { username: 'analyst', role: 'analyst' };
        localStorage.setItem('tt_user', JSON.stringify(demoUser));
        onLogin(demoUser);
    };

    return (
        <div className="login-container">
            <div className="login-card animate-in">
                <div className="login-brand">
                    <div className="brand-icon">
                        <Shield size={26} color="#000" />
                    </div>
                    <h1>THREAT_TRIAGE</h1>
                    <p>{'>'} SOC Analysis Engine</p>
                </div>

                <div className="login-tabs">
                    <button
                        className={`login-tab ${mode === 'login' ? 'active' : ''}`}
                        onClick={() => { setMode('login'); setError(''); }}
                    >
                        LOGIN
                    </button>
                    <button
                        className={`login-tab ${mode === 'register' ? 'active' : ''}`}
                        onClick={() => { setMode('register'); setError(''); }}
                    >
                        REGISTER
                    </button>
                </div>

                {error && <div className="login-error">[ERR] {error}</div>}

                <form className="login-form" onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label className="form-label">Username</label>
                        <input
                            className="form-input"
                            type="text"
                            value={username}
                            onChange={e => setUsername(e.target.value)}
                            placeholder="operator"
                            autoComplete="username"
                            required
                        />
                    </div>

                    {mode === 'register' && (
                        <>
                            <div className="form-group">
                                <label className="form-label">Email</label>
                                <input
                                    className="form-input"
                                    type="email"
                                    value={email}
                                    onChange={e => setEmail(e.target.value)}
                                    placeholder="operator@soc.local"
                                    autoComplete="email"
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Full Name</label>
                                <input
                                    className="form-input"
                                    type="text"
                                    value={fullName}
                                    onChange={e => setFullName(e.target.value)}
                                    placeholder="SOC Analyst"
                                />
                            </div>
                        </>
                    )}

                    <div className="form-group">
                        <label className="form-label">Password</label>
                        <div style={{ position: 'relative' }}>
                            <input
                                className="form-input"
                                type={showPw ? 'text' : 'password'}
                                value={password}
                                onChange={e => setPassword(e.target.value)}
                                placeholder="••••••••"
                                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                                required
                                style={{ paddingRight: '2.5rem' }}
                            />
                            <button
                                type="button"
                                onClick={() => setShowPw(!showPw)}
                                style={{
                                    position: 'absolute', right: '0.5rem', top: '50%',
                                    transform: 'translateY(-50%)', background: 'none',
                                    border: 'none', color: 'var(--text-dim)', cursor: 'pointer',
                                }}
                            >
                                {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
                            </button>
                        </div>
                    </div>

                    <button className="btn btn-primary" type="submit" disabled={loading}
                        style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}>
                        {loading ? (
                            <div className="loading-spinner" style={{ width: 16, height: 16, margin: 0, borderWidth: 2 }} />
                        ) : (
                            <Terminal size={14} />
                        )}
                        {mode === 'login' ? 'AUTHENTICATE' : 'CREATE ACCOUNT'}
                    </button>
                </form>

                <div style={{ textAlign: 'center', marginTop: '1.25rem' }}>
                    <button
                        className="btn btn-ghost"
                        onClick={handleDemoLogin}
                        style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}
                    >
                        Skip — Enter Demo Mode
                    </button>
                </div>
            </div>
        </div>
    );
}
