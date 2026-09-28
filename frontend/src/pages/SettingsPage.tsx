import React, { useState, useEffect } from 'react';
import { useApp } from '@/context/AppContext';
import { LogOut, UserPlus, Key, RefreshCw, ShieldAlert, CheckCircle2, Copy } from 'lucide-react';
import { Modal } from '@/components/ui/Modal';
import { Button } from '@/components/ui/Button';
import * as api from '@/services/api';

export function SettingsPage() {
  const { currentUser, logout, wsConnected, showToast } = useApp();

  // Create User Modal
  const [createUserOpen, setCreateUserOpen] = useState(false);
  const [userForm, setUserForm] = useState({
    username: '',
    email: '',
    password: '',
    role: 'proctor' as 'proctor' | 'admin',
  });
  const [creatingUser, setCreatingUser] = useState(false);

  // Signing Key State
  const [signingKey, setSigningKey] = useState<any>(null);
  const [loadingKey, setLoadingKey] = useState(false);
  const [rotatingKey, setRotatingKey] = useState(false);

  const fetchSigningKey = async () => {
    setLoadingKey(true);
    try {
      const res = await api.getSigningKey();
      setSigningKey(res);
    } catch (err: any) {
      // Non-critical if key inspection fails
    } finally {
      setLoadingKey(false);
    }
  };

  useEffect(() => {
    fetchSigningKey();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userForm.username || !userForm.password || !userForm.email) {
      showToast('Please fill all required user fields', 'error');
      return;
    }
    setCreatingUser(true);
    try {
      await api.register(userForm.username, userForm.email, userForm.password, userForm.role);
      showToast(`User '${userForm.username}' created successfully as ${userForm.role}`, 'success');
      setCreateUserOpen(false);
      setUserForm({ username: '', email: '', password: '', role: 'proctor' });
    } catch (err: any) {
      showToast(err.message || 'Failed to register account', 'error');
    } finally {
      setCreatingUser(false);
    }
  };

  const handleRotateKey = async () => {
    if (!window.confirm('Warning: Rotating the signing key will require active exam policies to be re-compiled and re-distributed. Do you want to continue?')) {
      return;
    }
    setRotatingKey(true);
    try {
      await api.rotateSigningKey('Operator manual rotation from Settings UI');
      showToast('Cryptographic signing key rotated successfully', 'success');
      await fetchSigningKey();
    } catch (err: any) {
      showToast(err.message || 'Failed to rotate signing key', 'error');
    } finally {
      setRotatingKey(false);
    }
  };

  return (
    <div className="page-container ds-flex-col" style={{ gap: '24px', maxWidth: '1000px', margin: '0 auto' }}>
      
      {/* Account Card */}
      <div 
        className="ds-flex-col" 
        style={{ 
          backgroundColor: '#ffffff', 
          border: '1px solid rgba(0,0,0,0.06)', 
          borderRadius: '12px', 
          padding: '24px', 
          boxShadow: '0 1px 2px rgba(0,0,0,0.02)' 
        }}
      >
        <div style={{ fontSize: '12px', fontWeight: '500', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '24px' }}>
          CURRENT OPERATOR SESSION
        </div>
        <div className="ds-flex-row ds-items-center ds-justify-between" style={{ marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
          <div className="ds-flex-row ds-items-center" style={{ gap: '16px' }}>
            <div 
              style={{ 
                width: '48px', 
                height: '48px', 
                borderRadius: '50%', 
                backgroundColor: 'var(--color-text-primary)', 
                color: 'var(--color-warning)', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                fontSize: '18px', 
                fontWeight: '500' 
              }}
            >
              {currentUser?.username?.charAt(0).toUpperCase() || 'A'}
            </div>
            <div className="ds-flex-col">
              <div style={{ fontSize: '15px', color: 'var(--color-text-primary)', fontWeight: '500' }}>
                {currentUser?.username || 'admin'}
              </div>
              <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>
                {currentUser?.email || 'admin@campusshield.edu'}
              </div>
            </div>
          </div>
          <div style={{ 
            backgroundColor: 'var(--color-warning-bg)', 
            color: 'var(--color-warning-fg)', 
            padding: '4px 12px', 
            borderRadius: '6px', 
            fontSize: '12px', 
            fontWeight: '500' 
          }}>
            {currentUser?.role === 'admin' ? 'Administrator' : (currentUser?.role || 'Proctor')}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button 
            onClick={logout} 
            className="ds-flex-row ds-items-center" 
            style={{ 
              gap: '8px', 
              backgroundColor: '#ffffff', 
              border: '1px solid rgba(0,0,0,0.08)', 
              borderRadius: '8px', 
              padding: '10px 16px', 
              fontSize: '13px', 
              fontWeight: '500', 
              color: 'var(--color-text-primary)', 
              cursor: 'pointer' 
            }}
          >
            <LogOut size={16} style={{ color: 'var(--color-text-muted)' }} />
            Sign out
          </button>

          {currentUser?.role === 'admin' && (
            <button
              onClick={() => setCreateUserOpen(true)}
              className="ds-flex-row ds-items-center"
              style={{
                gap: '8px',
                backgroundColor: 'var(--color-primary)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '8px',
                padding: '10px 16px',
                fontSize: '13px',
                fontWeight: '500',
                cursor: 'pointer',
              }}
            >
              <UserPlus size={16} />
              Register New Operator / Proctor
            </button>
          )}
        </div>
      </div>

      {/* Cryptographic Keyring Card */}
      <div 
        className="ds-flex-col" 
        style={{ 
          backgroundColor: '#ffffff', 
          border: '1px solid rgba(0,0,0,0.06)', 
          borderRadius: '12px', 
          padding: '24px', 
          boxShadow: '0 1px 2px rgba(0,0,0,0.02)' 
        }}
      >
        <div className="ds-flex-row ds-justify-between ds-items-center" style={{ marginBottom: '16px' }}>
          <div style={{ fontSize: '12px', fontWeight: '500', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            CRYPTOGRAPHIC POLICY SIGNING
          </div>
          {currentUser?.role === 'admin' && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleRotateKey}
              disabled={rotatingKey}
            >
              <RefreshCw size={14} className={rotatingKey ? 'animate-spin' : ''} />
              Rotate Signing Key
            </Button>
          )}
        </div>

        <p style={{ fontSize: '13px', color: 'var(--color-text-muted)', marginBottom: '16px' }}>
          All workstation firewall policies are digitally compiled and signed with RSA-PSS SHA256 before distribution.
          Workstation endpoint agents verify the signature against the server's public key prior to arming Windows Filtering Platform rules.
        </p>

        {loadingKey ? (
          <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>Loading key information...</div>
        ) : signingKey ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
              <div style={{ padding: '12px', background: '#FBF9F5', borderRadius: '8px', border: '1px solid rgba(0,0,0,0.04)' }}>
                <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginBottom: '4px' }}>KEY ID</div>
                <div style={{ fontSize: '13px', fontFamily: 'monospace', fontWeight: 600 }}>{signingKey.key_id}</div>
              </div>
              <div style={{ padding: '12px', background: '#FBF9F5', borderRadius: '8px', border: '1px solid rgba(0,0,0,0.04)' }}>
                <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginBottom: '4px' }}>ALGORITHM</div>
                <div style={{ fontSize: '13px', fontFamily: 'monospace', fontWeight: 600 }}>{signingKey.algorithm || 'RSA-PSS-SHA256'}</div>
              </div>
              <div style={{ padding: '12px', background: '#FBF9F5', borderRadius: '8px', border: '1px solid rgba(0,0,0,0.04)' }}>
                <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginBottom: '4px' }}>CREATED AT</div>
                <div style={{ fontSize: '13px', fontWeight: 500 }}>
                  {signingKey.created_at ? new Date(signingKey.created_at).toLocaleString() : 'Active'}
                </div>
              </div>
            </div>

            <div>
              <div style={{ fontSize: '11px', fontWeight: 700, color: '#A89F91', letterSpacing: '0.5px', marginBottom: '6px' }}>
                PUBLIC KEY PEM (ENDPOINT TRUST ROOT)
              </div>
              <pre
                style={{
                  background: '#1F1E1B',
                  color: '#4ADE80',
                  padding: '12px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                  overflowX: 'auto',
                  maxHeight: '140px',
                }}
              >
                {signingKey.public_key_pem || signingKey.public_key || 'PEM Key Loaded'}
              </pre>
            </div>
          </div>
        ) : (
          <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>Signing key status not available.</div>
        )}
      </div>

      {/* System Status Card */}
      <div 
        className="ds-flex-col" 
        style={{ 
          backgroundColor: '#ffffff', 
          border: '1px solid rgba(0,0,0,0.06)', 
          borderRadius: '12px', 
          padding: '24px', 
          boxShadow: '0 1px 2px rgba(0,0,0,0.02)' 
        }}
      >
        <div style={{ fontSize: '12px', fontWeight: '500', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '16px' }}>
          SYSTEM POSTURE & HEALTH
        </div>
        <div className="ds-flex-col">
          <div className="ds-flex-row ds-items-center ds-justify-between" style={{ padding: '12px 0', borderBottom: '1px solid rgba(0,0,0,0.06)' }}>
            <div style={{ fontSize: '14px', color: 'var(--color-text-primary)' }}>WebSocket Telemetry Gateway</div>
            <div className="ds-flex-row ds-items-center" style={{ gap: '6px', fontSize: '13px', color: wsConnected ? 'var(--color-success-fg)' : 'var(--color-danger)' }}>
              <span style={{ fontSize: '8px' }}>●</span> {wsConnected ? 'Connected & Streaming' : 'Disconnected'}
            </div>
          </div>
          <div className="ds-flex-row ds-items-center ds-justify-between" style={{ padding: '12px 0', borderBottom: '1px solid rgba(0,0,0,0.06)' }}>
            <div style={{ fontSize: '14px', color: 'var(--color-text-primary)' }}>FastAPI Core Server</div>
            <div className="ds-flex-row ds-items-center" style={{ gap: '6px', fontSize: '13px', color: 'var(--color-success-fg)' }}>
              <span style={{ fontSize: '8px' }}>●</span> Online (Local PostgreSQL)
            </div>
          </div>
          <div className="ds-flex-row ds-items-center ds-justify-between" style={{ padding: '12px 0', borderBottom: '1px solid rgba(0,0,0,0.06)' }}>
            <div style={{ fontSize: '14px', color: 'var(--color-text-primary)' }}>Policy Enforcement Invariant</div>
            <div style={{ fontSize: '13px', color: 'var(--color-success-fg)', fontWeight: 600 }}>
              Fail-Closed Enabled (Codex-Safe)
            </div>
          </div>
          <div className="ds-flex-row ds-items-center ds-justify-between" style={{ padding: '12px 0' }}>
            <div style={{ fontSize: '14px', color: 'var(--color-text-primary)' }}>SPEMCS Platform Release</div>
            <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>2.0.0-PROD</div>
          </div>
        </div>
      </div>

      {/* Register User Modal */}
      <Modal
        open={createUserOpen}
        onClose={() => setCreateUserOpen(false)}
        title="Register Operator or Proctor Account"
        actions={
          <div className="ds-flex-row" style={{ gap: '8px' }}>
            <Button variant="ghost" onClick={() => setCreateUserOpen(false)}>Cancel</Button>
            <Button onClick={handleCreateUser} disabled={creatingUser}>
              {creatingUser ? 'Registering...' : 'Create Account'}
            </Button>
          </div>
        }
      >
        <form onSubmit={handleCreateUser} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <label style={{ fontSize: '11px', fontWeight: 700, color: '#A89F91', letterSpacing: '0.5px' }}>USERNAME *</label>
            <input
              type="text"
              className="ds-input"
              value={userForm.username}
              onChange={(e) => setUserForm({ ...userForm, username: e.target.value })}
              placeholder="e.g. proctor_smith"
              required
              style={{ width: '100%', marginTop: '6px' }}
            />
          </div>
          <div>
            <label style={{ fontSize: '11px', fontWeight: 700, color: '#A89F91', letterSpacing: '0.5px' }}>EMAIL ADDRESS *</label>
            <input
              type="email"
              className="ds-input"
              value={userForm.email}
              onChange={(e) => setUserForm({ ...userForm, email: e.target.value })}
              placeholder="e.g. proctor@university.edu"
              required
              style={{ width: '100%', marginTop: '6px' }}
            />
          </div>
          <div>
            <label style={{ fontSize: '11px', fontWeight: 700, color: '#A89F91', letterSpacing: '0.5px' }}>PASSWORD *</label>
            <input
              type="password"
              className="ds-input"
              value={userForm.password}
              onChange={(e) => setUserForm({ ...userForm, password: e.target.value })}
              placeholder="Min 8 characters"
              required
              style={{ width: '100%', marginTop: '6px' }}
            />
          </div>
          <div>
            <label style={{ fontSize: '11px', fontWeight: 700, color: '#A89F91', letterSpacing: '0.5px' }}>ACCOUNT ROLE *</label>
            <select
              className="ds-input"
              value={userForm.role}
              onChange={(e) => setUserForm({ ...userForm, role: e.target.value as any })}
              style={{ width: '100%', marginTop: '6px' }}
            >
              <option value="proctor">Proctor (Exam Launch & Monitoring)</option>
              <option value="admin">Administrator (Full Fleet & Key Access)</option>
            </select>
          </div>
        </form>
      </Modal>

    </div>
  );
}
