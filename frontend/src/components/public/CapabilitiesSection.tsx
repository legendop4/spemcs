import { Server, ShieldCheck, Activity, Key, CheckCircle2, ArrowRight } from 'lucide-react';

export function CapabilitiesSection() {
  return (
    <section id="capabilities" className="sp-section">
      <div className="sp-container">
        
        {/* Section Header */}
        <div className="sp-section-header">
          <div className="sp-tag">Core Platform Capabilities</div>
          <h2 className="sp-section-title">One control plane for the endpoint.</h2>
          <p className="sp-section-desc">
            SPEMCS bridges centralized cloud policy coordination with resilient, locally validated
            enforcement on managed Windows hosts.
          </p>
        </div>

        {/* 4 Distinctive Capability Modules */}
        <div className="sp-flex-col sp-gap-8">

          {/* Capability 01: Endpoint Visibility */}
          <div className="sp-panel" style={{ background: 'linear-gradient(135deg, #0D121B 0%, #0A0E17 100%)' }}>
            <div className="sp-cap-split">
              <div className="sp-flex-col sp-gap-4">
                <div className="sp-mono" style={{ fontSize: '0.72rem', color: '#00E5FF', letterSpacing: '0.08em' }}>
                  01 // FLEET MONITORING
                </div>
                <h3 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#FFFFFF', margin: 0 }}>
                  Endpoint Visibility
                </h3>
                <p style={{ color: '#94A3B8', fontSize: '0.95rem', lineHeight: 1.6, margin: 0 }}>
                  Real-time inventory, hardware verification, and continuous health tracking across all managed
                  Windows workstations. Heartbeats and system states synchronize over authenticated WebSockets.
                </p>
                <div className="sp-grid-2" style={{ gap: '0.75rem', marginTop: '0.5rem' }}>
                  <div className="sp-flex-items-center sp-gap-2 sp-mono" style={{ fontSize: '0.75rem', color: '#CBD5E1' }}>
                    <CheckCircle2 style={{ width: '14px', height: '14px', color: '#10B981', flexShrink: 0 }} /> Hardware UUID Binding
                  </div>
                  <div className="sp-flex-items-center sp-gap-2 sp-mono" style={{ fontSize: '0.75rem', color: '#CBD5E1' }}>
                    <CheckCircle2 style={{ width: '14px', height: '14px', color: '#10B981', flexShrink: 0 }} /> Heartbeat Telemetry
                  </div>
                  <div className="sp-flex-items-center sp-gap-2 sp-mono" style={{ fontSize: '0.75rem', color: '#CBD5E1' }}>
                    <CheckCircle2 style={{ width: '14px', height: '14px', color: '#10B981', flexShrink: 0 }} /> OS Build & Status Check
                  </div>
                  <div className="sp-flex-items-center sp-gap-2 sp-mono" style={{ fontSize: '0.75rem', color: '#CBD5E1' }}>
                    <CheckCircle2 style={{ width: '14px', height: '14px', color: '#10B981', flexShrink: 0 }} /> Real-time Connection Bus
                  </div>
                </div>
              </div>

              {/* Technical Endpoint State Widget */}
              <div>
                <div className="sp-panel-inset sp-mono" style={{ fontSize: '0.75rem' }}>
                  <div className="sp-flex-between" style={{ paddingBottom: '0.75rem', borderBottom: '1px solid #1E293B', fontSize: '0.7rem' }}>
                    <span style={{ color: '#64748B' }}>HOST: WS-104-FINANCE</span>
                    <span className="sp-badge sp-badge-green">
                      <span className="sp-pulse-dot" style={{ width: '5px', height: '5px' }} /> ONLINE / ENFORCING
                    </span>
                  </div>
                  <div className="sp-grid-2" style={{ gap: '0.75rem', marginTop: '0.85rem', fontSize: '0.72rem' }}>
                    <div>
                      <div style={{ color: '#64748B' }}>HARDWARE UUID</div>
                      <div style={{ color: '#FFFFFF', marginTop: '2px', wordBreak: 'break-all' }}>94811e8f-f3f3-407b-8155</div>
                    </div>
                    <div>
                      <div style={{ color: '#64748B' }}>AGENT VERSION</div>
                      <div style={{ color: '#FFFFFF', marginTop: '2px' }}>2.4.1 (x64 Service)</div>
                    </div>
                    <div>
                      <div style={{ color: '#64748B' }}>LAST HEARTBEAT</div>
                      <div style={{ color: '#00E5FF', marginTop: '2px' }}>1.2s ago (WSS)</div>
                    </div>
                    <div>
                      <div style={{ color: '#64748B' }}>ACTIVE POLICY</div>
                      <div style={{ color: '#CBD5E1', marginTop: '2px' }}>POL-SEC-2026-09</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Grid Layout: Capabilities 02 and 03 */}
          <div className="sp-grid-2">
            
            {/* Capability 02: Policy Enforcement */}
            <div className="sp-panel sp-flex-col sp-flex-between">
              <div className="sp-flex-col sp-gap-3">
                <div className="sp-mono" style={{ fontSize: '0.72rem', color: '#10B981', letterSpacing: '0.08em' }}>
                  02 // WINDOWS FIREWALL ENFORCEMENT
                </div>
                <h3 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#FFFFFF', margin: 0 }}>
                  Policy Enforcement
                </h3>
                <p style={{ color: '#94A3B8', fontSize: '0.9rem', lineHeight: 1.6, margin: 0 }}>
                  Distribute and enforce centrally managed host network and security policies. The agent interacts
                  directly with the host Windows Firewall adapter and maintains a local reversible SQLite rollback
                  journal to prevent lockout.
                </p>
              </div>

              <div className="sp-panel-inset sp-mono" style={{ marginTop: '1.5rem', fontSize: '0.72rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <div className="sp-flex-between">
                  <span style={{ color: '#64748B' }}>FIREWALL ADAPTER</span>
                  <span style={{ color: '#10B981' }}>WINDOWS NETSH / COM</span>
                </div>
                <div className="sp-flex-between">
                  <span style={{ color: '#64748B' }}>ROLLBACK JOURNAL</span>
                  <span style={{ color: '#00E5FF' }}>SQLITE ATOMIC COMMIT</span>
                </div>
                <div className="sp-flex-between">
                  <span style={{ color: '#64748B' }}>RECOVERY TIMEOUT</span>
                  <span style={{ color: '#FFFFFF' }}>FAILSAFE AUTO-RESTORE</span>
                </div>
              </div>
            </div>

            {/* Capability 03: Security Telemetry */}
            <div className="sp-panel sp-flex-col sp-flex-between">
              <div className="sp-flex-col sp-gap-3">
                <div className="sp-mono" style={{ fontSize: '0.72rem', color: '#F59E0B', letterSpacing: '0.08em' }}>
                  03 // PROCESS AUDIT & STREAM
                </div>
                <h3 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#FFFFFF', margin: 0 }}>
                  Security Telemetry
                </h3>
                <p style={{ color: '#94A3B8', fontSize: '0.9rem', lineHeight: 1.6, margin: 0 }}>
                  Collect endpoint process and security events with real-time security telemetry and event
                  classification. Continuously stream parent-child process relationships and outbound connection
                  attempts to the operator console.
                </p>
              </div>

              <div className="sp-panel-inset sp-mono" style={{ marginTop: '1.5rem', fontSize: '0.72rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <div className="sp-flex-between">
                  <span style={{ color: '#64748B' }}>TELEMETRY STREAM</span>
                  <span style={{ color: '#10B981' }}>REALTIME BUS (PUBSUB)</span>
                </div>
                <div className="sp-flex-between">
                  <span style={{ color: '#64748B' }}>CLASSIFICATION</span>
                  <span style={{ color: '#F59E0B' }}>RULE & ANOMALY FILTER</span>
                </div>
                <div className="sp-flex-between">
                  <span style={{ color: '#64748B' }}>EVENT DISPATCH</span>
                  <span style={{ color: '#FFFFFF' }}>OPERATOR HUD & AUDIT LOG</span>
                </div>
              </div>
            </div>

          </div>

          {/* Capability 04: Cryptographic Trust (Full Width Reversed) */}
          <div className="sp-panel" style={{ background: 'linear-gradient(135deg, #0D121B 0%, #121324 100%)' }}>
            <div className="sp-cap-split">
              
              {/* Crypto Verification Preview */}
              <div>
                <div className="sp-panel-inset sp-mono" style={{ fontSize: '0.75rem' }}>
                  <div className="sp-flex-between" style={{ paddingBottom: '0.75rem', borderBottom: '1px solid #1E293B' }}>
                    <span style={{ color: '#64748B' }}>SIGNING KEY MANAGER</span>
                    <span className="sp-badge sp-badge-indigo">
                      <Key style={{ width: '12px', height: '12px', marginRight: '4px' }} /> RSA-PSS 2048 / SHA-256
                    </span>
                  </div>
                  <div className="sp-flex-col sp-gap-2" style={{ marginTop: '0.85rem', fontSize: '0.72rem' }}>
                    <div style={{ color: '#64748B' }}>ACTIVE KEY ID:</div>
                    <div style={{ color: '#FFFFFF', background: '#06090E', padding: '0.5rem', borderRadius: '4px', border: '1px solid #1E293B', wordBreak: 'break-all' }}>
                      spemcs-c19d7d3a5b8163ae99a7365e513960c1
                    </div>
                    <div className="sp-flex-between" style={{ paddingTop: '0.25rem', color: '#64748B' }}>
                      <span>PAYLOAD SIGNATURE:</span>
                      <span style={{ color: '#10B981', fontWeight: 600 }}>VALIDATED BEFORE COMMIT</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Explanatory Content */}
              <div className="sp-flex-col sp-gap-4">
                <div className="sp-mono" style={{ fontSize: '0.72rem', color: '#6366F1', letterSpacing: '0.08em' }}>
                  04 // ASYMMETRIC ASSURANCE
                </div>
                <h3 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#FFFFFF', margin: 0 }}>
                  Cryptographic Integrity Verification
                </h3>
                <p style={{ color: '#94A3B8', fontSize: '0.95rem', lineHeight: 1.6, margin: 0 }}>
                  Every policy payload is signed at the control plane using RSA-PSS 2048-bit keys before dispatch.
                  Endpoints independently verify payload digests and signatures against their trusted keystore prior
                  to applying any firewall rules.
                </p>
                <div>
                  <a
                    href="#cryptographic-trust"
                    className="sp-flex-items-center sp-mono"
                    style={{ fontSize: '0.78rem', color: '#00E5FF', textDecoration: 'none' }}
                  >
                    View Key Lifecycle & Verification Pipeline <ArrowRight style={{ width: '14px', height: '14px', marginLeft: '4px' }} />
                  </a>
                </div>
              </div>

            </div>
          </div>

        </div>

      </div>
    </section>
  );
}
