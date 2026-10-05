import { Shield, ArrowRight, Terminal, Server, Key, Activity, UserCheck } from 'lucide-react';
import { Link } from 'react-router-dom';

export function HeroSection() {
  const scrollToSection = (id: string) => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <section className="sp-hero">
      <div className="sp-container">
        <div className="sp-hero-grid">
          
          {/* Left Column (58%): Core Narrative & CTAs */}
          <div>
            <div className="sp-tag" style={{ marginBottom: '1.25rem' }}>
              <span className="sp-pulse-dot" style={{ width: '6px', height: '6px' }} />
              <span>Endpoint Security & Policy Enforcement</span>
            </div>

            <h1 className="sp-hero-title">
              Control the endpoint.<br />
              <span>Enforce the policy.</span>
            </h1>

            <p className="sp-hero-desc">
              SPEMCS provides centralized endpoint visibility, real-time security telemetry, and
              cryptographically verified policy enforcement for managed Windows environments.
            </p>

            <div className="sp-hero-actions">
              <button
                onClick={() => scrollToSection('capabilities')}
                className="sp-btn-primary"
              >
                Explore the Platform
              </button>
              <Link to="/login" className="sp-btn-secondary">
                Sign In <ArrowRight style={{ width: '15px', height: '15px', marginLeft: '4px', color: '#00E5FF' }} />
              </Link>
            </div>

            {/* Protocol Invariant Strip */}
            <div className="sp-hero-meta-strip">
              <div>
                <div className="sp-meta-label">Cryptographic Trust</div>
                <div className="sp-meta-val">RSA-PSS 2048 / SHA-256</div>
              </div>
              <div>
                <div className="sp-meta-label">Fleet Protocol</div>
                <div className="sp-meta-val">Dual-Secret WSS + TLS 1.3</div>
              </div>
              <div>
                <div className="sp-meta-label">Host Adapter</div>
                <div className="sp-meta-val" style={{ color: '#10B981' }}>Reversible Journal</div>
              </div>
            </div>
          </div>

          {/* Right Column (42%): Technical System Topology */}
          <div>
            <div className="sp-topology-box">
              
              {/* Header */}
              <div className="sp-flex-between" style={{ paddingBottom: '1rem', borderBottom: '1px solid #1E293B', marginBottom: '1.25rem' }}>
                <div className="sp-flex-items-center sp-gap-2">
                  <div className="sp-pulse-dot" />
                  <span className="sp-mono" style={{ fontSize: '0.75rem', fontWeight: 700, color: '#FFFFFF', letterSpacing: '0.05em' }}>
                    SYSTEM CONTROL TOPOLOGY
                  </span>
                </div>
                <span className="sp-badge sp-badge-cyan">
                  ACTIVE
                </span>
              </div>

              {/* Node 1: Windows Endpoints */}
              <div className="sp-panel-inset sp-flex-between" style={{ padding: '0.85rem' }}>
                <div className="sp-flex-items-center sp-gap-3">
                  <div style={{ width: '32px', height: '32px', borderRadius: '4px', background: '#121824', border: '1px solid #1E293B', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Terminal style={{ width: '16px', height: '16px', color: '#00E5FF' }} />
                  </div>
                  <div>
                    <div className="sp-mono" style={{ fontSize: '0.8rem', fontWeight: 600, color: '#FFFFFF' }}>Windows Endpoints</div>
                    <div className="sp-mono" style={{ fontSize: '0.68rem', color: '#64748B' }}>.NET 8 Agent Service • Local Adapter</div>
                  </div>
                </div>
                <span className="sp-badge sp-badge-green">
                  ENFORCING
                </span>
              </div>

              {/* Connecting Flow 1 */}
              <div className="sp-flow-arrow">
                <span className="sp-flow-line-vert" />
                <span>Bidirectional Heartbeat & Telemetry (WSS)</span>
                <span className="sp-flow-line-vert" />
              </div>

              {/* Node 2: SPEMCS Control Plane */}
              <div className="sp-panel-inset" style={{ padding: '0.9rem', borderColor: 'rgba(0, 229, 255, 0.35)', background: 'rgba(0, 229, 255, 0.02)' }}>
                <div className="sp-flex-between">
                  <div className="sp-flex-items-center sp-gap-3">
                    <div style={{ width: '32px', height: '32px', borderRadius: '4px', background: 'rgba(0, 229, 255, 0.1)', border: '1px solid rgba(0, 229, 255, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <Server style={{ width: '16px', height: '16px', color: '#00E5FF' }} />
                    </div>
                    <div>
                      <div className="sp-mono sp-flex-items-center sp-gap-2" style={{ fontSize: '0.8rem', fontWeight: 600, color: '#FFFFFF' }}>
                        SPEMCS Control Plane
                        <span className="sp-badge sp-badge-cyan" style={{ fontSize: '0.58rem', padding: '0.1rem 0.35rem' }}>CORE</span>
                      </div>
                      <div className="sp-mono" style={{ fontSize: '0.68rem', color: '#94A3B8' }}>
                        API Engine • Realtime Bus • PostgreSQL
                      </div>
                    </div>
                  </div>
                  <Key style={{ width: '16px', height: '16px', color: '#6366F1' }} />
                </div>

                <div className="sp-flex-between sp-mono" style={{ marginTop: '0.75rem', paddingTop: '0.65rem', borderTop: '1px solid #1E293B', fontSize: '0.68rem' }}>
                  <span style={{ color: '#64748B' }}>Signing Engine: <span style={{ color: '#F1F5F9' }}>RSA-PSS Active</span></span>
                  <span style={{ color: '#64748B' }}>Audit Trail: <span style={{ color: '#10B981' }}>Immutable</span></span>
                </div>
              </div>

              {/* Connecting Flow 2 */}
              <div className="sp-flow-arrow">
                <span className="sp-flow-line-vert" />
                <span>Cryptographic Verification & Telemetry Stream</span>
                <span className="sp-flow-line-vert" />
              </div>

              {/* Node 3: Policy & Telemetry Subsystems */}
              <div className="sp-grid-2" style={{ gap: '0.75rem' }}>
                <div className="sp-panel-inset" style={{ padding: '0.75rem' }}>
                  <div className="sp-flex-items-center sp-gap-2" style={{ marginBottom: '0.25rem' }}>
                    <Shield style={{ width: '14px', height: '14px', color: '#10B981' }} />
                    <span className="sp-mono" style={{ fontSize: '0.75rem', fontWeight: 600, color: '#FFFFFF' }}>Policy Enforce</span>
                  </div>
                  <div className="sp-mono" style={{ fontSize: '0.62rem', color: '#64748B' }}>
                    Signed payload validation before host rule commit
                  </div>
                </div>

                <div className="sp-panel-inset" style={{ padding: '0.75rem' }}>
                  <div className="sp-flex-items-center sp-gap-2" style={{ marginBottom: '0.25rem' }}>
                    <Activity style={{ width: '14px', height: '14px', color: '#00E5FF' }} />
                    <span className="sp-mono" style={{ fontSize: '0.75rem', fontWeight: 600, color: '#FFFFFF' }}>Telemetry</span>
                  </div>
                  <div className="sp-mono" style={{ fontSize: '0.62rem', color: '#64748B' }}>
                    Live process audits & network drift classification
                  </div>
                </div>
              </div>

              {/* Connecting Flow 3 */}
              <div className="sp-flow-arrow">
                <span className="sp-flow-line-vert" />
                <span>Operator Command & Incident Oversight</span>
                <span className="sp-flow-line-vert" />
              </div>

              {/* Node 4: Security Operator Console */}
              <div className="sp-panel-inset sp-flex-between" style={{ padding: '0.85rem' }}>
                <div className="sp-flex-items-center sp-gap-3">
                  <div style={{ width: '32px', height: '32px', borderRadius: '4px', background: '#121824', border: '1px solid #1E293B', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <UserCheck style={{ width: '16px', height: '16px', color: '#F59E0B' }} />
                  </div>
                  <div>
                    <div className="sp-mono" style={{ fontSize: '0.8rem', fontWeight: 600, color: '#FFFFFF' }}>Security Operator Console</div>
                    <div className="sp-mono" style={{ fontSize: '0.68rem', color: '#64748B' }}>Authenticated SOC & Threat Response HUD</div>
                  </div>
                </div>
                <span className="sp-badge sp-badge-amber">
                  AUTHORITATIVE
                </span>
              </div>

            </div>
          </div>

        </div>
      </div>
    </section>
  );
}
