import { Key, ShieldCheck, RefreshCw, CheckCircle2, AlertCircle } from 'lucide-react';

export function CryptographicTrustSection() {
  return (
    <section id="cryptographic-trust" className="sp-section" style={{ background: '#06090E' }}>
      <div className="sp-container">
        
        {/* Section Header */}
        <div className="sp-section-header">
          <div className="sp-tag">Asymmetric Cryptography</div>
          <h2 className="sp-section-title">Policy integrity is part of the control plane.</h2>
          <p className="sp-section-desc">
            Centralized policy distribution without cryptographic proof of origin is an attack vector.
            SPEMCS embeds cryptographic signing and verification directly into the policy lifecycle.
          </p>
        </div>

        {/* Cryptographic Key Lifecycle Visualizer */}
        <div className="sp-panel" style={{ background: '#0D121B', padding: '2rem' }}>
          
          <div className="sp-flex-between" style={{ paddingBottom: '1.25rem', borderBottom: '1px solid #1E293B', flexWrap: 'wrap', gap: '1rem' }}>
            <div>
              <div className="sp-mono" style={{ fontSize: '0.72rem', color: '#6366F1', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                Cryptographic Trust Engine
              </div>
              <h3 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#FFFFFF', margin: '0.25rem 0 0 0' }}>
                Key Lifecycle State Machine
              </h3>
            </div>
            <div className="sp-flex-items-center sp-gap-2 sp-mono" style={{ fontSize: '0.75rem' }}>
              <span style={{ color: '#94A3B8' }}>ALGORITHM:</span>
              <span className="sp-badge sp-badge-indigo" style={{ fontSize: '0.72rem' }}>
                RSA-PSS 2048 / SHA-256
              </span>
            </div>
          </div>

          {/* Key States Pipeline */}
          <div className="sp-grid-3" style={{ margin: '2rem 0' }}>
            
            {/* Stage 1: ACTIVE */}
            <div className="sp-panel-inset" style={{ borderColor: 'rgba(16, 185, 129, 0.4)', background: 'rgba(16, 185, 129, 0.02)', padding: '1.25rem' }}>
              <div className="sp-flex-between" style={{ marginBottom: '0.75rem' }}>
                <span className="sp-badge sp-badge-green">
                  <span className="sp-pulse-dot" style={{ width: '5px', height: '5px' }} /> 01 // ACTIVE
                </span>
                <Key style={{ width: '16px', height: '16px', color: '#10B981' }} />
              </div>
              <p style={{ fontSize: '0.78rem', color: '#CBD5E1', lineHeight: 1.6, marginBottom: '1rem' }}>
                Currently used by the backend signing key manager to sign all newly created and updated policy payloads.
              </p>
              <div className="sp-mono" style={{ fontSize: '0.68rem', padding: '0.65rem', borderRadius: '4px', background: '#06090E', border: '1px solid #1E293B' }}>
                <div style={{ color: '#64748B' }}>KEY ID (LIVE EXAMPLE)</div>
                <div style={{ color: '#FFFFFF', wordBreak: 'break-all', marginTop: '2px' }}>spemcs-c19d7d3a5b8163ae99a7365e513960c1</div>
                <div style={{ color: '#10B981', paddingTop: '4px', fontWeight: 600 }}>STATUS: AUTHORITATIVE SIGNER</div>
              </div>
            </div>

            {/* Stage 2: RETIRED */}
            <div className="sp-panel-inset" style={{ borderColor: 'rgba(245, 158, 11, 0.35)', background: 'rgba(245, 158, 11, 0.02)', padding: '1.25rem' }}>
              <div className="sp-flex-between" style={{ marginBottom: '0.75rem' }}>
                <span className="sp-badge sp-badge-amber">
                  <RefreshCw style={{ width: '12px', height: '12px', marginRight: '4px' }} /> 02 // RETIRED
                </span>
                <Key style={{ width: '16px', height: '16px', color: '#F59E0B' }} />
              </div>
              <p style={{ fontSize: '0.78rem', color: '#CBD5E1', lineHeight: 1.6, marginBottom: '1rem' }}>
                Previous key version retained during rotation grace periods to allow verification of policies in transit.
              </p>
              <div className="sp-mono" style={{ fontSize: '0.68rem', padding: '0.65rem', borderRadius: '4px', background: '#06090E', border: '1px solid #1E293B' }}>
                <div style={{ color: '#64748B' }}>GRACE PERIOD WINDOW</div>
                <div style={{ color: '#FFFFFF', marginTop: '2px' }}>Active for verification only</div>
                <div style={{ color: '#F59E0B', paddingTop: '4px', fontWeight: 600 }}>NEW SIGNING: BLOCKED</div>
              </div>
            </div>

            {/* Stage 3: REVOKED */}
            <div className="sp-panel-inset" style={{ padding: '1.25rem', opacity: 0.85 }}>
              <div className="sp-flex-between" style={{ marginBottom: '0.75rem' }}>
                <span className="sp-badge sp-badge-red">
                  <AlertCircle style={{ width: '12px', height: '12px', marginRight: '4px' }} /> 03 // REVOKED
                </span>
                <Key style={{ width: '16px', height: '16px', color: '#EF4444' }} />
              </div>
              <p style={{ fontSize: '0.78rem', color: '#94A3B8', lineHeight: 1.6, marginBottom: '1rem' }}>
                Permanently invalidated. Any policy payload bearing a signature from a revoked key ID is immediately rejected.
              </p>
              <div className="sp-mono" style={{ fontSize: '0.68rem', padding: '0.65rem', borderRadius: '4px', background: '#06090E', border: '1px solid #1E293B' }}>
                <div style={{ color: '#64748B' }}>VERIFICATION OUTCOME</div>
                <div style={{ color: '#EF4444', fontWeight: 600, marginTop: '2px' }}>IMMEDIATE REJECTION</div>
                <div style={{ color: '#64748B', paddingTop: '4px' }}>AUDIT ALERT LOGGED</div>
              </div>
            </div>

          </div>

          {/* Verification Pipeline Step Breakdown */}
          <div className="sp-grid-2" style={{ borderTop: '1px solid #1E293B', paddingTop: '1.5rem', fontSize: '0.78rem' }}>
            <div className="sp-flex-col sp-gap-2">
              <div className="sp-flex-items-center sp-gap-2 sp-mono" style={{ color: '#00E5FF', fontWeight: 600 }}>
                <CheckCircle2 style={{ width: '15px', height: '15px', color: '#00E5FF' }} /> Control Plane Signing Sequence
              </div>
              <p style={{ color: '#94A3B8', margin: 0, lineHeight: 1.6 }}>
                When an operator creates or publishes a policy, the backend canonicalizes the JSON payload, computes
                the SHA-256 digest, and signs it using the active private key with RSA-PSS padding and salt.
              </p>
            </div>

            <div className="sp-flex-col sp-gap-2">
              <div className="sp-flex-items-center sp-gap-2 sp-mono" style={{ color: '#10B981', fontWeight: 600 }}>
                <CheckCircle2 style={{ width: '15px', height: '15px', color: '#10B981' }} /> Endpoint Pre-Execution Verification
              </div>
              <p style={{ color: '#94A3B8', margin: 0, lineHeight: 1.6 }}>
                Before committing rules to the Windows Firewall, the agent matches the Key ID, extracts the public
                key from its trusted store, and asserts mathematical signature validity. Mismatched payloads are aborted.
              </p>
            </div>
          </div>

        </div>

      </div>
    </section>
  );
}
