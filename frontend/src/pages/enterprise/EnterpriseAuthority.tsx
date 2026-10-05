import React, { useState, useEffect } from 'react';
import {
  Key,
  RefreshCw,
  RotateCw,
  Copy,
  Check,
  Lock,
  Info,
  X,
  FileCode,
  AlertTriangle,
} from 'lucide-react';
import * as api from '@/services/api';

interface SigningKey {
  key_id: string;
  public_key_pem: string;
  state: 'active' | 'retired' | 'revoked' | string;
  created_at?: string | null;
  retired_at?: string | null;
  revoked_at?: string | null;
  revocation_reason?: string | null;
}

interface SigningKeyring {
  active_key_id: string;
  keys: SigningKey[];
  revoked_key_ids: string[];
  ephemeral: boolean;
}

export function EnterpriseAuthority() {
  const [keyring, setKeyring] = useState<SigningKeyring | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Rotate Modal
  const [showRotateModal, setShowRotateModal] = useState(false);
  const [rotateReason, setRotateReason] = useState('');
  const [rotating, setRotating] = useState(false);

  // Revoke Modal
  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [revokeTargetKeyId, setRevokeTargetKeyId] = useState<string | null>(null);
  const [revokeReason, setRevokeReason] = useState('');
  const [revoking, setRevoking] = useState(false);

  // Selected Key for PEM inspection
  const [viewingPemKey, setViewingPemKey] = useState<SigningKey | null>(null);
  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null);

  const fetchKeyring = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getSigningKeyring();
      setKeyring(data);
    } catch (err: any) {
      console.error('Failed to load signing keyring:', err);
      setError(err?.message || 'Failed to query policy signing authority');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeyring();
  }, []);

  const handleCopyPem = (pem: string, id: string) => {
    navigator.clipboard.writeText(pem);
    setCopiedKeyId(id);
    setTimeout(() => setCopiedKeyId(null), 2000);
  };

  const handleRotate = async (e: React.FormEvent) => {
    e.preventDefault();
    setRotating(true);
    try {
      const updated = await api.rotateSigningKey(rotateReason.trim() || undefined);
      setKeyring(updated);
      setShowRotateModal(false);
      setRotateReason('');
    } catch (err: any) {
      alert(`Key rotation failed: ${err.message || 'Operation error'}`);
    } finally {
      setRotating(false);
    }
  };

  const handleRevoke = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!revokeTargetKeyId || !revokeReason.trim()) return;

    // Safety guard: Active key CANNOT be revoked
    if (revokeTargetKeyId === keyring?.active_key_id) {
      alert('The active signing key cannot be revoked directly. Rotate to a new key first, then revoke the retired key.');
      return;
    }

    setRevoking(true);
    try {
      const updated = await api.revokeSigningKey(revokeTargetKeyId, revokeReason.trim());
      setKeyring(updated);
      setShowRevokeModal(false);
      setRevokeTargetKeyId(null);
      setRevokeReason('');
    } catch (err: any) {
      alert(`Key revocation failed: ${err.message || 'Operation error'}`);
    } finally {
      setRevoking(false);
    }
  };

  const activeKey = keyring?.keys?.find((k) => k.key_id === keyring.active_key_id);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
      {/* Modern Page Header */}
      <div className="ep-page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--ep-cyan)', letterSpacing: '0.1em' }}>
              GOVERNANCE & TRUST // CRYPTOGRAPHIC AUTHORITY
            </span>
            <span className="ep-badge ep-badge-cyan">RSA-PSS 2048 / SHA-256</span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#FFFFFF', margin: 0, letterSpacing: '-0.3px' }}>
            Cryptographic Authority
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', margin: '4px 0 0 0' }}>
            Signing trust anchor, policy signature verification, and key rollover lifecycle management
          </p>
        </div>

        <div className="ep-header-actions">
          <button
            onClick={fetchKeyring}
            disabled={loading}
            className="ep-btn ep-btn-secondary"
            title="Refresh keyring from central authority"
          >
            <RefreshCw size={14} className={loading ? 'ep-spin' : ''} />
            <span>Refresh Keyring</span>
          </button>

          <button
            onClick={() => setShowRotateModal(true)}
            className="ep-btn ep-btn-primary"
          >
            <RotateCw size={14} />
            <span>Rotate Signing Key</span>
          </button>
        </div>
      </div>

      {/* Ephemeral Key Warning if applicable */}
      {keyring?.ephemeral && (
        <div
          style={{
            padding: '14px 18px',
            background: 'rgba(245, 158, 11, 0.1)',
            border: '1px solid rgba(245, 158, 11, 0.3)',
            borderRadius: '6px',
            color: '#fbbf24',
            fontSize: '13px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
          }}
        >
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Ephemeral Keyring Notice:</strong> The active signing key is currently memory-resident and will not persist across backend container restarts. In production, configure persistent key storage.
          </div>
        </div>
      )}

      {error && (
        <div style={{ padding: '12px 16px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', color: '#f87171', fontSize: '13px' }}>
          {error}
        </div>
      )}

      {/* Active Authority Hero Card */}
      <div className="ep-card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '8px',
                background: 'rgba(16, 185, 129, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                flexShrink: 0,
              }}
            >
              <Key size={20} color="var(--ep-emerald)" />
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Primary Signing Anchor
              </div>
              <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--ep-text-primary)' }}>
                Active Signing Authority Key
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="ep-badge ep-badge-emerald" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'currentColor' }} />
              ACTIVE & TRUSTED
            </span>
          </div>
        </div>

        {activeKey ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '20px', padding: '16px', background: 'var(--ep-surface-secondary)', borderRadius: '6px', border: '1px solid var(--ep-surface-border)' }}>
            <div>
              <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase' }}>Active Key ID</span>
              <div style={{ fontFamily: 'monospace', fontSize: '14px', fontWeight: 600, color: 'var(--ep-cyan)', marginTop: '4px', wordBreak: 'break-all' }}>
                {activeKey.key_id}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--ep-text-secondary)', marginTop: '6px' }}>
                Signs all compiled boundary policy manifests pushed to endpoint agents.
              </div>
              <div style={{ marginTop: '10px' }}>
                <button
                  onClick={() => setViewingPemKey(activeKey)}
                  className="ep-btn ep-btn-secondary"
                  style={{ fontSize: '11px', padding: '4px 10px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                >
                  <FileCode size={12} />
                  <span>View Public PEM</span>
                </button>
              </div>
            </div>

            <div>
              <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase' }}>Algorithm & Parameters</span>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--ep-text-primary)', marginTop: '4px' }}>
                RSA-PSS (2048-bit)
              </div>
              <div style={{ fontSize: '12px', color: 'var(--ep-text-muted)', marginTop: '2px' }}>
                Digest: SHA-256 (MGF1)
              </div>
            </div>

            <div>
              <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase' }}>Created Timestamp</span>
              <div style={{ fontSize: '13px', color: 'var(--ep-text-primary)', marginTop: '4px' }}>
                {activeKey.created_at ? new Date(activeKey.created_at).toLocaleString() : 'System Genesis'}
              </div>
            </div>
          </div>
        ) : (
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--ep-text-muted)' }}>
            No active signing key currently registered.
          </div>
        )}
      </div>

      {/* Keyring Inventory Table */}
      <div className="ep-table-container">
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--ep-surface-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--ep-text-primary)', margin: 0 }}>
              Published Signing Keyring
            </h3>
            <p style={{ fontSize: '12px', color: 'var(--ep-text-secondary)', margin: '2px 0 0' }}>
              Full certificate chain and rollover history served to endpoint agents via <code>/api/policies/signing-key/keyring</code>.
            </p>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--ep-text-muted)', fontFamily: 'monospace' }}>
            {keyring?.keys?.length || 0} KEYS PUBLISHED
          </span>
        </div>

        <table className="ep-table" style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={{ padding: '12px 16px' }}>Key ID</th>
              <th style={{ padding: '12px 16px' }}>Lifecycle State</th>
              <th style={{ padding: '12px 16px' }}>Created</th>
              <th style={{ padding: '12px 16px' }}>Retired / Revoked</th>
              <th style={{ padding: '12px 16px' }}>Revocation Justification</th>
              <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} style={{ padding: '40px', textAlign: 'center', color: 'var(--ep-text-muted)' }}>
                  <RefreshCw size={20} className="ep-spin" style={{ margin: '0 auto 8px', display: 'block' }} />
                  Loading keyring status...
                </td>
              </tr>
            ) : !keyring || keyring.keys.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: '40px', textAlign: 'center', color: 'var(--ep-text-muted)' }}>
                  No keys published in the keyring.
                </td>
              </tr>
            ) : (
              keyring.keys.map((k) => {
                const isActive = k.key_id === keyring.active_key_id;
                const isRevoked = k.state === 'revoked';
                const isRetired = k.state === 'retired';

                return (
                  <tr key={k.key_id}>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Lock size={14} color={isActive ? 'var(--ep-emerald)' : isRevoked ? 'var(--ep-crimson)' : 'var(--ep-text-muted)'} />
                        <span style={{ fontFamily: 'monospace', fontSize: '13px', fontWeight: 600, color: 'var(--ep-text-primary)' }}>
                          {k.key_id}
                        </span>
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      {isActive ? (
                        <span className="ep-badge ep-badge-emerald">ACTIVE (SIGNING)</span>
                      ) : isRevoked ? (
                        <span className="ep-badge ep-badge-crimson">REVOKED (UNTRUSTED)</span>
                      ) : isRetired ? (
                        <span className="ep-badge ep-badge-amber">RETIRED (VERIFIES PAST)</span>
                      ) : (
                        <span className="ep-badge ep-badge-slate">{k.state.toUpperCase()}</span>
                      )}
                    </td>
                    <td style={{ padding: '12px 16px', fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                      {k.created_at ? new Date(k.created_at).toLocaleString() : '—'}
                    </td>
                    <td style={{ padding: '12px 16px', fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                      {k.revoked_at ? (
                        <span style={{ color: 'var(--ep-crimson)' }}>{new Date(k.revoked_at).toLocaleString()}</span>
                      ) : k.retired_at ? (
                        <span>{new Date(k.retired_at).toLocaleString()}</span>
                      ) : (
                        <span style={{ color: 'var(--ep-text-muted)' }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: '12px 16px', fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                      {k.revocation_reason ? (
                        <span style={{ color: 'var(--ep-crimson)', fontStyle: 'italic' }}>{k.revocation_reason}</span>
                      ) : (
                        <span style={{ color: 'var(--ep-text-muted)' }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '8px', alignItems: 'center' }}>
                        <button
                          onClick={() => setViewingPemKey(k)}
                          className="ep-btn ep-btn-secondary"
                          style={{ padding: '4px 8px' }}
                          title="View Public Key PEM"
                        >
                          <FileCode size={13} />
                        </button>

                        {!isActive && !isRevoked && (
                          <button
                            onClick={() => {
                              setRevokeTargetKeyId(k.key_id);
                              setShowRevokeModal(true);
                            }}
                            className="ep-btn ep-btn-secondary"
                            style={{
                              color: 'var(--ep-amber)',
                              borderColor: 'rgba(245, 158, 11, 0.3)',
                              padding: '4px 8px',
                              fontSize: '11px',
                            }}
                            title="Revoke retired key"
                          >
                            Revoke
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Architectural Security Notice */}
      <div className="ep-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
          <Info size={18} color="var(--ep-cyan)" style={{ marginTop: '2px', flexShrink: 0 }} />
          <div style={{ fontSize: '12px', color: 'var(--ep-text-secondary)', lineHeight: '1.6' }}>
            <strong style={{ color: 'var(--ep-text-primary)' }}>Cryptographic Keyring Policy & Agent Verification:</strong>
            <br />
            1. <strong>Retirement vs. Revocation:</strong> When a key is rotated, the outgoing key becomes <em>Retired</em>. It remains published in the keyring so running endpoints can continuously verify policies signed prior to the rollover without disruption.
            <br />
            2. <strong>Revocation Enforcement:</strong> Revoking a key immediately marks it untrusted. All endpoint agents will reject any policy manifest signed by a revoked key ID, triggering immediate emergency firewall fail-safe behavior.
            <br />
            3. <strong>Signature Schema:</strong> Policy manifests are signed with <strong>RSA-PSS 2048-bit</strong> with MGF1 and SHA-256 digest hashing. Endpoint agents verify manifest integrity before committing Windows Firewall rules.
          </div>
        </div>
      </div>

      {/* Rotate Key Modal */}
      {showRotateModal && (
        <div className="ep-modal-backdrop" onClick={() => !rotating && setShowRotateModal(false)}>
          <div className="ep-modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--ep-surface-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--ep-text-primary)' }}>
                Rotate Signing Authority Key
              </div>
              <button onClick={() => !rotating && setShowRotateModal(false)} style={{ background: 'none', border: 'none', color: 'var(--ep-text-muted)', cursor: 'pointer' }}>
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleRotate} style={{ padding: '24px' }}>
              <div style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', marginBottom: '16px', lineHeight: '1.5' }}>
                Rotating will generate a new active RSA-PSS 2048 signing key. The current key will be moved to <strong>Retired</strong> state so existing deployed policies remain valid.
              </div>

              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: 'var(--ep-text-muted)', marginBottom: '6px' }}>
                  Rotation Reason (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. Scheduled quarterly rotation / fleet lifecycle"
                  value={rotateReason}
                  onChange={(e) => setRotateReason(e.target.value)}
                  className="ep-input"
                  style={{ width: '100%', fontSize: '13px', boxSizing: 'border-box' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
                <button type="button" onClick={() => setShowRotateModal(false)} disabled={rotating} className="ep-btn ep-btn-secondary">
                  Cancel
                </button>
                <button type="submit" disabled={rotating} className="ep-btn ep-btn-primary">
                  {rotating ? 'Rotating Key...' : 'Confirm Key Rotation'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Revoke Key Modal */}
      {showRevokeModal && (
        <div className="ep-modal-backdrop" onClick={() => !revoking && setShowRevokeModal(false)}>
          <div className="ep-modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--ep-surface-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--ep-crimson)' }}>
                Revoke Retired Signing Key
              </div>
              <button onClick={() => !revoking && setShowRevokeModal(false)} style={{ background: 'none', border: 'none', color: 'var(--ep-text-muted)', cursor: 'pointer' }}>
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleRevoke} style={{ padding: '24px' }}>
              <div style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', marginBottom: '16px', lineHeight: '1.5' }}>
                <strong>CRITICAL ACTION:</strong> Revoking key <code style={{ color: 'var(--ep-cyan)', wordBreak: 'break-all' }}>{revokeTargetKeyId}</code> will cause all endpoint agents to reject any policy signed by it. This is permanent and recorded in the audit trail.
              </div>

              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: 'var(--ep-text-muted)', marginBottom: '6px' }}>
                  Mandatory Revocation Reason *
                </label>
                <textarea
                  required
                  placeholder="e.g. Suspected key compromise / unauthorized machine access"
                  value={revokeReason}
                  onChange={(e) => setRevokeReason(e.target.value)}
                  className="ep-input"
                  rows={3}
                  style={{ width: '100%', fontSize: '13px', resize: 'vertical', boxSizing: 'border-box' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
                <button type="button" onClick={() => setShowRevokeModal(false)} disabled={revoking} className="ep-btn ep-btn-secondary">
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={revoking || !revokeReason.trim()}
                  className="ep-btn"
                  style={{ background: 'var(--ep-crimson)', color: '#FFFFFF', fontWeight: 600 }}
                >
                  {revoking ? 'Revoking...' : 'Permanently Revoke Key'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* View PEM Drawer / Modal */}
      {viewingPemKey && (
        <div className="ep-modal-backdrop" onClick={() => setViewingPemKey(null)}>
          <div className="ep-modal-dialog" style={{ width: '640px' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--ep-surface-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--ep-cyan)' }}>PUBLIC KEY PEM</div>
                <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--ep-text-primary)', wordBreak: 'break-all' }}>
                  {viewingPemKey.key_id}
                </div>
              </div>
              <button onClick={() => setViewingPemKey(null)} style={{ background: 'none', border: 'none', color: 'var(--ep-text-muted)', cursor: 'pointer' }}>
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: '24px' }}>
              <div style={{ position: 'relative', marginBottom: '16px' }}>
                <button
                  onClick={() => handleCopyPem(viewingPemKey.public_key_pem, viewingPemKey.key_id)}
                  className="ep-btn ep-btn-secondary"
                  style={{
                    position: 'absolute',
                    right: '12px',
                    top: '12px',
                    fontSize: '11px',
                    padding: '4px 8px',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  {copiedKeyId === viewingPemKey.key_id ? <Check size={12} color="var(--ep-emerald)" /> : <Copy size={12} />}
                  {copiedKeyId === viewingPemKey.key_id ? 'Copied' : 'Copy PEM'}
                </button>

                <pre
                  style={{
                    background: 'var(--ep-surface-subtle)',
                    padding: '16px',
                    borderRadius: '6px',
                    border: '1px solid var(--ep-surface-border)',
                    fontFamily: 'monospace',
                    fontSize: '11px',
                    color: 'var(--ep-cyan)',
                    overflowX: 'auto',
                    maxHeight: '340px',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    margin: 0,
                  }}
                >
                  {viewingPemKey.public_key_pem}
                </pre>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button onClick={() => setViewingPemKey(null)} className="ep-btn ep-btn-secondary">
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default EnterpriseAuthority;
