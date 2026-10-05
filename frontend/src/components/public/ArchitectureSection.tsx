import { Server, Database, Key, Radio, Terminal, Monitor, Lock } from 'lucide-react';

export function ArchitectureSection() {
  return (
    <section id="architecture" className="sp-section" style={{ background: '#070A0F' }}>
      <div className="sp-container">
        
        {/* Section Header */}
        <div className="sp-section-header">
          <div className="sp-tag">System Engineering Architecture</div>
          <h2 className="sp-section-title">From policy definition to endpoint enforcement.</h2>
          <p className="sp-section-desc">
            An end-to-end security architecture separating the centralized policy authoring control plane from
            the local Windows enforcement engine.
          </p>
        </div>

        {/* 3-Tier Engineering Schematic */}
        <div className="sp-panel" style={{ background: '#0A0E15', padding: '2rem' }}>
          
          <div className="sp-arch-flow">
            
            {/* TIER 1: WINDOWS MANAGED ENDPOINTS */}
            <div className="sp-arch-tier">
              <div>
                <div className="sp-flex-between" style={{ paddingBottom: '0.75rem', borderBottom: '1px solid #1E293B', marginBottom: '1rem' }}>
                  <div className="sp-flex-items-center sp-gap-2">
                    <Terminal style={{ width: '16px', height: '16px', color: '#00E5FF' }} />
                    <span className="sp-mono" style={{ fontSize: '0.78rem', fontWeight: 700, color: '#FFFFFF', textTransform: 'uppercase' }}>
                      Tier 1: Windows Endpoints
                    </span>
                  </div>
                  <span className="sp-badge sp-badge-green" style={{ fontSize: '0.62rem' }}>
                    CLIENT HOST
                  </span>
                </div>

                <div className="sp-panel-inset sp-mono" style={{ fontSize: '0.75rem' }}>
                  <div className="sp-arch-item">
                    <div style={{ color: '#FFFFFF', fontWeight: 600 }}>.NET 8 Agent Service</div>
                    <div style={{ fontSize: '0.65rem', color: '#64748B', marginTop: '2px' }}>Background Windows Service / Worker</div>
                  </div>

                  <div className="sp-arch-item">
                    <div style={{ color: '#FFFFFF', fontWeight: 600 }}>Control Pipe Worker</div>
                    <div style={{ fontSize: '0.65rem', color: '#64748B', marginTop: '2px' }}>Local IPC & User Session Coordination</div>
                  </div>

                  <div className="sp-arch-item">
                    <div style={{ color: '#FFFFFF', fontWeight: 600 }}>Windows Firewall Adapter</div>
                    <div style={{ fontSize: '0.65rem', color: '#64748B', marginTop: '2px' }}>Host rule commit & active port blocking</div>
                  </div>

                  <div className="sp-arch-item" style={{ marginBottom: 0 }}>
                    <div style={{ color: '#FFFFFF', fontWeight: 600 }}>SQLite Rollback Journal</div>
                    <div style={{ fontSize: '0.65rem', color: '#10B981', marginTop: '2px' }}>Atomic transaction & failsafe restore</div>
                  </div>
                </div>
              </div>

              <div className="sp-mono" style={{ fontSize: '0.68rem', color: '#64748B', padding: '0.75rem', borderRadius: '4px', background: '#06090E', border: '1px solid rgba(255,255,255,0.06)', marginTop: '1rem' }}>
                Independent signature validation happens locally before any firewall rule modification.
              </div>
            </div>

            {/* TIER 2: SPEMCS CONTROL PLANE (CORE) */}
            <div className="sp-arch-tier">
              <div>
                <div className="sp-flex-between" style={{ paddingBottom: '0.75rem', borderBottom: '1px solid rgba(0, 229, 255, 0.3)', marginBottom: '1rem' }}>
                  <div className="sp-flex-items-center sp-gap-2">
                    <Server style={{ width: '16px', height: '16px', color: '#00E5FF' }} />
                    <span className="sp-mono" style={{ fontSize: '0.78rem', fontWeight: 700, color: '#FFFFFF', textTransform: 'uppercase' }}>
                      Tier 2: Control Plane
                    </span>
                  </div>
                  <span className="sp-badge sp-badge-cyan" style={{ fontSize: '0.62rem' }}>
                    CORE BACKEND
                  </span>
                </div>

                <div className="sp-panel-inset sp-mono" style={{ fontSize: '0.75rem', borderColor: 'rgba(0, 229, 255, 0.35)', background: 'rgba(0, 229, 255, 0.02)' }}>
                  <div className="sp-arch-item">
                    <div className="sp-flex-between">
                      <span style={{ color: '#FFFFFF', fontWeight: 600 }}>FastAPI Application Engine</span>
                      <span className="sp-badge sp-badge-cyan" style={{ fontSize: '0.55rem', padding: '0.1rem 0.3rem' }}>ASYNC</span>
                    </div>
                    <div style={{ fontSize: '0.65rem', color: '#64748B', marginTop: '2px' }}>REST API, Device Enrollment & Auth</div>
                  </div>

                  <div className="sp-arch-item">
                    <div className="sp-flex-between">
                      <span style={{ color: '#FFFFFF', fontWeight: 600 }}>Signing Key Manager</span>
                      <Lock style={{ width: '13px', height: '13px', color: '#6366F1' }} />
                    </div>
                    <div style={{ fontSize: '0.65rem', color: '#64748B', marginTop: '2px' }}>RSA-PSS 2048 key lifecycle & verification</div>
                  </div>

                  <div className="sp-arch-item">
                    <div className="sp-flex-between">
                      <span style={{ color: '#FFFFFF', fontWeight: 600 }}>Real-time Communication Bus</span>
                      <Radio style={{ width: '13px', height: '13px', color: '#10B981' }} />
                    </div>
                    <div style={{ fontSize: '0.65rem', color: '#64748B', marginTop: '2px' }}>In-memory / Redis WebSocket pubsub</div>
                  </div>

                  <div className="sp-arch-item" style={{ marginBottom: 0 }}>
                    <div className="sp-flex-between">
                      <span style={{ color: '#FFFFFF', fontWeight: 600 }}>PostgreSQL Database</span>
                      <Database style={{ width: '13px', height: '13px', color: '#CBD5E1' }} />
                    </div>
                    <div style={{ fontSize: '0.65rem', color: '#64748B', marginTop: '2px' }}>Relational state & immutable audit logs</div>
                  </div>
                </div>
              </div>

              <div className="sp-mono" style={{ fontSize: '0.68rem', color: '#94A3B8', padding: '0.75rem', borderRadius: '4px', background: '#06090E', border: '1px solid rgba(255,255,255,0.06)', marginTop: '1rem' }}>
                Reference AWS Deployment Architecture: Internet ➔ ALB ➔ ECS Fargate (FastAPI) ➔ RDS Multi-AZ.
              </div>
            </div>

            {/* TIER 3: SECURITY OPERATOR CONSOLE */}
            <div className="sp-arch-tier">
              <div>
                <div className="sp-flex-between" style={{ paddingBottom: '0.75rem', borderBottom: '1px solid #1E293B', marginBottom: '1rem' }}>
                  <div className="sp-flex-items-center sp-gap-2">
                    <Monitor style={{ width: '16px', height: '16px', color: '#F59E0B' }} />
                    <span className="sp-mono" style={{ fontSize: '0.78rem', fontWeight: 700, color: '#FFFFFF', textTransform: 'uppercase' }}>
                      Tier 3: Security Console
                    </span>
                  </div>
                  <span className="sp-badge sp-badge-amber" style={{ fontSize: '0.62rem' }}>
                    SOC CLIENT
                  </span>
                </div>

                <div className="sp-panel-inset sp-mono" style={{ fontSize: '0.75rem' }}>
                  <div className="sp-arch-item">
                    <div style={{ color: '#FFFFFF', fontWeight: 600 }}>Operator HUD & Analytics</div>
                    <div style={{ fontSize: '0.65rem', color: '#64748B', marginTop: '2px' }}>Fleet health & active enforcement posture</div>
                  </div>

                  <div className="sp-arch-item">
                    <div style={{ color: '#FFFFFF', fontWeight: 600 }}>Policy Authoring Studio</div>
                    <div style={{ fontSize: '0.65rem', color: '#64748B', marginTop: '2px' }}>Centrally compile and dispatch rules</div>
                  </div>

                  <div className="sp-arch-item">
                    <div style={{ color: '#FFFFFF', fontWeight: 600 }}>Real-time Telemetry Stream</div>
                    <div style={{ fontSize: '0.65rem', color: '#64748B', marginTop: '2px' }}>Live WebSocket subscription to alerts</div>
                  </div>

                  <div className="sp-arch-item" style={{ marginBottom: 0 }}>
                    <div style={{ color: '#FFFFFF', fontWeight: 600 }}>Forensic Incident Inspector</div>
                    <div style={{ fontSize: '0.65rem', color: '#64748B', marginTop: '2px' }}>Process trees, violation reasons & logs</div>
                  </div>
                </div>
              </div>

              <div className="sp-mono" style={{ fontSize: '0.68rem', color: '#64748B', padding: '0.75rem', borderRadius: '4px', background: '#06090E', border: '1px solid rgba(255,255,255,0.06)', marginTop: '1rem' }}>
                Operators authenticate via JWT with role-based authorization; all operations generate audit events.
              </div>
            </div>

          </div>

          {/* Inter-Tier Communication Protocol Strip */}
          <div className="sp-grid-2" style={{ marginTop: '2rem', paddingTop: '1.5rem', borderTop: '1px solid #1E293B', fontSize: '0.75rem' }}>
            <div className="sp-flex-items-center sp-gap-3 sp-panel-inset sp-mono" style={{ padding: '0.75rem' }}>
              <span className="sp-pulse-dot" style={{ width: '6px', height: '6px', background: '#00E5FF' }} />
              <div>
                <span style={{ color: '#FFFFFF', fontWeight: 600 }}>Endpoints ⇄ Control Plane:</span>
                <span style={{ color: '#94A3B8', marginLeft: '6px' }}>TLS 1.3 HTTPS + Dual-Secret WSS (`/api/v1/ws/dashboard`)</span>
              </div>
            </div>
            <div className="sp-flex-items-center sp-gap-3 sp-panel-inset sp-mono" style={{ padding: '0.75rem' }}>
              <span className="sp-pulse-dot" style={{ width: '6px', height: '6px', background: '#6366F1' }} />
              <div>
                <span style={{ color: '#FFFFFF', fontWeight: 600 }}>Console ⇄ Control Plane:</span>
                <span style={{ color: '#94A3B8', marginLeft: '6px' }}>Authenticated REST + Subscribed Telemetry Push</span>
              </div>
            </div>
          </div>

        </div>

      </div>
    </section>
  );
}
