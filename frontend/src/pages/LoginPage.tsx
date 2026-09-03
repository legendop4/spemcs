import { useState, type FormEvent, type ChangeEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '@/context/AppContext';
import { Button } from '@/components/ui/Button';

export function LoginPage() {
  const { login } = useApp();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');

    if (!username.trim() || !password.trim()) {
      setError('Please enter both username and password.');
      return;
    }

    setLoading(true);
    try {
      const success = await login(username.trim(), password);
      if (success) {
        navigate('/dashboard');
      } else {
        setError('Invalid credentials. Please try again.');
      }
    } catch (err: any) {
      setError(err.message || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const fillDemo = () => {
    setUsername('admin');
    setPassword('Admin@0123');
  };

  return (
    <div className="login-page">
      <div className="bg-blob bg-blob-1" />
      <div className="bg-blob bg-blob-2" />
      <div className="bg-blob bg-blob-3" />
      <div className="login-grid-bg" />
      <div className="login-tri login-tri-1" />
      <div className="login-tri login-tri-2" />
      <div className="login-tri login-tri-3" />

      <div className="login-container">
        <div className="login-left">
          <div className="login-brand">
            <img src="/logo.jpg" alt="CampusShield Logo" width="40" height="40" style={{ borderRadius: '8px', objectFit: 'cover' }} />
            <span>CAMPUS<span style={{ fontWeight: 700 }}>SHIELD</span></span>
          </div>

          <div className="login-hero">
            <h1 className="login-hero-title">SECURE</h1>
            <h1 className="login-hero-title">YOUR CAMPUS.</h1>
            <p className="login-hero-subtitle">
              Protect infrastructure.<br />
              Protect examinations.<br />
              Protect integrity.
            </p>
          </div>

          <div className="login-footer">
            <span>College Infrastructure & Exam Security Management Portal</span>
          </div>
        </div>

        <div className="login-right">
          <div className="login-card glass">
            <h2 className="login-card-title">Sign In</h2>
            <p className="login-card-subtitle">Enter your credentials to access the portal.</p>

            <form onSubmit={handleSubmit} className="login-form">
              <div className="form-field">
                <label className="form-label" htmlFor="username">Username</label>
                <input
                  id="username"
                  type="text"
                  className="form-input"
                  placeholder="admin"
                  value={username}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => setUsername(e.target.value)}
                  autoComplete="username"
                />
              </div>

              <div className="form-field">
                <label className="form-label" htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  className="form-input"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)}
                  autoComplete="current-password"
                />
              </div>

              {error && <div className="login-error">{error}</div>}

              <Button type="submit" size="lg" className="login-submit" disabled={loading}>
                {loading ? 'Signing in...' : 'Sign In'}
              </Button>
            </form>

            <div className="login-demo">
              <button className="login-demo-btn" onClick={fillDemo}>
                Use demo credentials
              </button>
              <div className="login-demo-info">
                <span>admin / Admin@0123</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
