import { Link } from 'react-router-dom';
import { Terminal, ArrowRight } from 'lucide-react';

export function ConsolePreviewSection() {
  return (
    <section id="console-preview" className="sp-section" style={{ background: '#06090E' }}>
      <div className="sp-container">
        
        {/* Section Header */}
        <div className="sp-section-header" style={{ textAlign: 'center', marginLeft: 'auto', marginRight: 'auto' }}>
          <div className="sp-tag">Operator Experience</div>
          <h2 className="sp-section-title">The SPEMCS Security Console</h2>
          <p className="sp-section-desc">
            Designed for cybersecurity operations, SOC incident triage, and continuous fleet management.
            No consumer clutter—only high-density operational telemetry.
          </p>
        </div>

        {/* 3D Perspective Console Window */}
        <div className="sp-perspective-container">
          <div className="sp-3d-console-tilt" style={{ background: '#0A0E15' }}>
            
            {/* Window Topbar */}
            <div className="sp-flex-between" style={{ padding: '0.75rem 1rem', background: '#0D121B', borderBottom: '1px solid #1E293B' }}>
              <div className="sp-flex-items-center sp-gap-2">
                <span style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#EF4444' }} />
                <span style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#F59E0B' }} />
                <span style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#10B981' }} />
                <span className="sp-mono" style={{ marginLeft: '0.75rem', fontSize: '0.75rem', color: '#94A3B8' }}>
                  SPEMCS Enterprise Console // Live Fleet Telemetry
                </span>
              </div>
              <div className="sp-flex-items-center sp-gap-2 sp-mono" style={{ fontSize: '0.7rem' }}>
                <span className="sp-pulse-dot" style={{ width: '5px', height: '5px' }} />
                <span style={{ color: '#10B981', fontWeight: 600 }}>SYSTEM NORMAL</span>
              </div>
            </div>

            {/* Inner Console Screen */}
            <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              
              {/* Stat Cards Strip */}
              <div className="sp-grid-4">
                <div className="sp-panel-inset">
                  <div className="sp-mono" style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: '#64748B' }}>Managed Endpoints</div>
                  <div className="sp-mono" style={{ fontSize: '1.5rem', fontWeight: 800, color: '#FFFFFF', marginTop: '0.25rem' }}>128</div>
                  <div className="sp-mono" style={{ fontSize: '0.65rem', color: '#10B981', marginTop: '0.25rem' }}>✓ 100% Verified Heartbeats</div>
                </div>

                <div className="sp-panel-inset">
                  <div className="sp-mono" style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: '#64748B' }}>Active Enforcements</div>
                  <div className="sp-mono" style={{ fontSize: '1.5rem', fontWeight: 800, color: '#00E5FF', marginTop: '0.25rem' }}>124</div>
                  <div className="sp-mono" style={{ fontSize: '0.65rem', color: '#CBD5E1', marginTop: '0.25rem' }}>4 Monitor Only</div>
                </div>

                <div className="sp-panel-inset">
                  <div className="sp-mono" style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: '#64748B' }}>Signing Key State</div>
                  <div className="sp-mono" style={{ fontSize: '1.35rem', fontWeight: 800, color: '#6366F1', marginTop: '0.25rem' }}>RSA-PSS</div>
                  <div className="sp-mono" style={{ fontSize: '0.65rem', color: '#94A3B8', marginTop: '0.25rem' }}>Key ID: spemcs-c19d...</div>
                </div>

                <div className="sp-panel-inset">
                  <div className="sp-mono" style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: '#64748B' }}>Security Events (24h)</div>
                  <div className="sp-mono" style={{ fontSize: '1.5rem', fontWeight: 800, color: '#F59E0B', marginTop: '0.25rem' }}>18</div>
                  <div className="sp-mono" style={{ fontSize: '0.65rem', color: '#10B981', marginTop: '0.25rem' }}>0 Open Anomalies</div>
                </div>
              </div>

              {/* Mock Fleet Table Snapshot */}
              <div className="sp-panel-inset" style={{ padding: 0, overflow: 'hidden' }}>
                <div className="sp-flex-between sp-mono" style={{ padding: '0.65rem 1rem', background: '#0D121B', borderBottom: '1px solid #1E293B', fontSize: '0.75rem' }}>
                  <span style={{ color: '#CBD5E1', fontWeight: 600 }}>FLEET POSTURE INVENTORY</span>
                  <span style={{ color: '#64748B', fontSize: '0.68rem' }}>FILTER: ALL WORKSTATIONS</span>
                </div>
                <div className="sp-mono" style={{ fontSize: '0.75rem' }}>
                  
                  <div className="sp-flex-between" style={{ padding: '0.65rem 1rem', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <div className="sp-flex-items-center sp-gap-3">
                      <Terminal style={{ width: '14px', height: '14px', color: '#00E5FF' }} />
                      <span style={{ color: '#FFFFFF', fontWeight: 600 }}>WS-SEC-104</span>
                      <span style={{ color: '#64748B', fontSize: '0.68rem' }}>10.240.14.82</span>
                    </div>
                    <div className="sp-flex-items-center sp-gap-4">
                      <span style={{ color: '#CBD5E1', fontSize: '0.68rem' }}>Windows 11 Ent (23H2)</span>
                      <span className="sp-badge sp-badge-green">ENFORCING</span>
                    </div>
                  </div>

                  <div className="sp-flex-between" style={{ padding: '0.65rem 1rem', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <div className="sp-flex-items-center sp-gap-3">
                      <Terminal style={{ width: '14px', height: '14px', color: '#00E5FF' }} />
                      <span style={{ color: '#FFFFFF', fontWeight: 600 }}>WS-SEC-105</span>
                      <span style={{ color: '#64748B', fontSize: '0.68rem' }}>10.240.14.83</span>
                    </div>
                    <div className="sp-flex-items-center sp-gap-4">
                      <span style={{ color: '#CBD5E1', fontSize: '0.68rem' }}>Windows 11 Ent (23H2)</span>
                      <span className="sp-badge sp-badge-green">ENFORCING</span>
                    </div>
                  </div>

                  <div className="sp-flex-between" style={{ padding: '0.65rem 1rem' }}>
                    <div className="sp-flex-items-center sp-gap-3">
                      <Terminal style={{ width: '14px', height: '14px', color: '#F59E0B' }} />
                      <span style={{ color: '#FFFFFF', fontWeight: 600 }}>WS-LAB-012</span>
                      <span style={{ color: '#64748B', fontSize: '0.68rem' }}>10.240.18.10</span>
                    </div>
                    <div className="sp-flex-items-center sp-gap-4">
                      <span style={{ color: '#CBD5E1', fontSize: '0.68rem' }}>Windows 10 Ent (22H2)</span>
                      <span className="sp-badge sp-badge-amber">MONITOR ONLY</span>
                    </div>
                  </div>

                </div>
              </div>

            </div>

            {/* Bottom Callout Banner */}
            <div className="sp-flex-between" style={{ padding: '1rem 1.5rem', background: '#0D121B', borderTop: '1px solid #1E293B', flexWrap: 'wrap', gap: '1rem' }}>
              <span className="sp-mono" style={{ fontSize: '0.78rem', color: '#94A3B8' }}>
                See the live security control plane in action.
              </span>
              <Link to="/login" className="sp-btn-primary" style={{ fontSize: '0.78rem', padding: '0.45rem 1rem' }}>
                Sign In to SPEMCS <ArrowRight style={{ width: '14px', height: '14px', marginLeft: '4px' }} />
              </Link>
            </div>

          </div>
        </div>

      </div>
    </section>
  );
}
