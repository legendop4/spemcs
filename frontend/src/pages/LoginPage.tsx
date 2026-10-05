import { useState, type FormEvent, type ChangeEvent } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useApp } from '@/context/AppContext';
import { Shield, ArrowRight, Lock, Key, AlertCircle, ArrowLeft } from 'lucide-react';
import '@/landing.css';

export function LoginPage() {
  const { login } = useApp();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');

    if (!username.trim() || !password.trim()) {
      setError('Operator username and password are required.');
      return;
    }

    setLoading(true);
    try {
      const success = await login(username.trim(), password);
      if (success) {
        // Redirect to intended destination or default to security console
        const from = location.state?.from?.pathname || '/console/overview';
        navigate(from, { replace: true });
      } else {
        setError('Authentication rejected. Invalid credentials or expired session.');
      }
    } catch (err: any) {
      setError(err.message || 'Authentication error. Unable to establish secure session.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="sp-auth-canvas">
      {/* Background Architectural Canvas */}
      <div className="sp-grid-canvas" />
      <div className="sp-ambient-top" />

      {/* Top Header Strip */}
      <header style={{ padding: '1.5rem', position: 'relative', zIndex: 10 }}>
        <div className="sp-container sp-flex-between">
          <Link to="/" className="sp-flex-items-center sp-gap-3" style={{ textDecoration: 'none' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '4px',
                backgroundColor: '#0D121B',
                border: '1px solid #1E293B',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Shield style={{ width: '16px', height: '16px', color: '#00E5FF' }} />
            </div>
            <div className="sp-flex-items-center sp-gap-2">
              <span className="sp-mono" style={{ fontWeight: 800, fontSize: '1.15rem', color: '#FFFFFF', letterSpacing: '-0.02em' }}>
                SPEMCS
              </span>
              <span className="sp-badge sp-badge-cyan" style={{ fontSize: '0.62rem' }}>
                CONTROL PLANE
              </span>
            </div>
          </Link>

          <Link
            to="/"
            className="sp-mono sp-flex-items-center sp-gap-2"
            style={{ fontSize: '0.75rem', color: '#94A3B8', textDecoration: 'none' }}
          >
            <ArrowLeft style={{ width: '14px', height: '14px' }} /> Return to Overview
          </Link>
        </div>
      </header>

      {/* Center Auth Card */}
      <main className="sp-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="sp-auth-box">
          
          {/* Card Header */}
          <div style={{ marginBottom: '2rem', textAlign: 'center' }}>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '6px',
                background: 'rgba(0, 229, 255, 0.08)',
                border: '1px solid rgba(0, 229, 255, 0.25)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 1rem auto',
              }}
            >
              <Lock style={{ width: '20px', height: '20px', color: '#00E5FF' }} />
            </div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#FFFFFF', letterSpacing: '-0.025em', margin: 0 }}>
              Operator Authentication
            </h1>
            <p style={{ fontSize: '0.85rem', color: '#94A3B8', marginTop: '0.35rem' }}>
              Sign in to access the SPEMCS Security Console.
            </p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            
            <div>
              <label
                htmlFor="username"
                className="sp-mono"
                style={{ display: 'block', fontSize: '0.72rem', color: '#CBD5E1', marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}
              >
                Operator Identity / Username
              </label>
              <input
                id="username"
                type="text"
                className="sp-auth-input sp-auth-input-mono"
                placeholder="admin"
                value={username}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setUsername(e.target.value)}
                autoComplete="username"
                required
              />
            </div>

            <div>
              <div className="sp-flex-between" style={{ marginBottom: '0.4rem' }}>
                <label
                  htmlFor="password"
                  className="sp-mono"
                  style={{ fontSize: '0.72rem', color: '#CBD5E1', textTransform: 'uppercase', letterSpacing: '0.05em' }}
                >
                  Credential / Password
                </label>
              </div>
              <input
                id="password"
                type="password"
                className="sp-auth-input"
                placeholder="••••••••••••"
                value={password}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </div>

            {error && (
              <div
                className="sp-flex-items-center sp-gap-2 sp-mono"
                style={{
                  padding: '0.75rem',
                  borderRadius: '4px',
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  color: '#EF4444',
                  fontSize: '0.75rem',
                }}
              >
                <AlertCircle style={{ width: '16px', height: '16px', flexShrink: 0 }} />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              className="sp-btn-primary"
              disabled={loading}
              style={{ width: '100%', padding: '0.75rem', fontSize: '0.875rem', marginTop: '0.5rem' }}
            >
              {loading ? (
                <span className="sp-flex-items-center sp-gap-2">
                  <span className="sp-pulse-dot" style={{ width: '6px', height: '6px', background: '#06090E' }} />
                  Verifying Session...
                </span>
              ) : (
                <span className="sp-flex-items-center sp-gap-2">
                  Sign In to Console <ArrowRight style={{ width: '15px', height: '15px' }} />
                </span>
              )}
            </button>
          </form>

          {/* Restrained Security / Trust Metadata */}
          <div
            className="sp-mono"
            style={{
              marginTop: '2rem',
              paddingTop: '1.25rem',
              borderTop: '1px solid #1E293B',
              fontSize: '0.68rem',
              color: '#64748B',
              textAlign: 'center',
              lineHeight: 1.6,
            }}
          >
            <div>TLS 1.3 STRICT ENFORCED // MUTUAL TOKEN AUTH</div>
            <div style={{ color: '#475569', marginTop: '4px' }}>
              All access attempts generate immutable audit trail entries in PostgreSQL.
            </div>
          </div>

        </div>
      </main>

      {/* Footer Strip */}
      <footer style={{ padding: '1.5rem', textAlign: 'center', position: 'relative', zIndex: 10 }}>
        <div className="sp-mono" style={{ fontSize: '0.7rem', color: '#475569' }}>
          SPEMCS Enterprise Endpoint Security & Policy Enforcement • Reference AWS Production Topology
        </div>
      </footer>
    </div>
  );
}

export default LoginPage;
