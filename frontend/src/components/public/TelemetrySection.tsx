import { AlertTriangle } from 'lucide-react';

export function TelemetrySection() {
  return (
    <section id="telemetry" className="sp-section" style={{ background: '#070A0F' }}>
      <div className="sp-container">
        
        {/* Section Header */}
        <div className="sp-section-header">
          <div className="sp-tag">Operator Telemetry Stream</div>
          <h2 className="sp-section-title">Real-time security telemetry and event classification.</h2>
          <p className="sp-section-desc">
            Endpoint agents observe local execution and network activity, dispatching structured security
            events to the central console for immediate triage and audit compliance.
          </p>
        </div>

        {/* Forensic Event Inspector Card */}
        <div className="sp-panel" style={{ background: '#0A0E15', padding: '2rem' }}>
          
          <div className="sp-flex-between" style={{ paddingBottom: '1.25rem', borderBottom: '1px solid #1E293B', flexWrap: 'wrap', gap: '1rem' }}>
            <div className="sp-flex-items-center sp-gap-3">
              <div style={{ width: '32px', height: '32px', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <AlertTriangle style={{ width: '16px', height: '16px', color: '#EF4444' }} />
              </div>
              <div>
                <div className="sp-mono" style={{ fontSize: '0.8rem', fontWeight: 700, color: '#FFFFFF' }}>
                  INCIDENT TELEMETRY INSPECTOR
                </div>
                <div className="sp-mono" style={{ fontSize: '0.68rem', color: '#94A3B8' }}>
                  Event ID: EVT-9824-A19F // Illustrative Telemetry
                </div>
              </div>
            </div>

            <div className="sp-flex-items-center sp-gap-2">
              <span className="sp-badge sp-badge-red">
                UNAUTHORIZED EXECUTION
              </span>
              <span className="sp-mono" style={{ fontSize: '0.68rem', color: '#64748B', border: '1px solid #1E293B', padding: '0.2rem 0.5rem', borderRadius: '3px', background: '#06090E' }}>
                Sample Event
              </span>
            </div>
          </div>

          {/* Structured Event Grid */}
          <div className="sp-grid-6 sp-mono" style={{ padding: '1.5rem 0', borderBottom: '1px solid #1E293B', fontSize: '0.78rem' }}>
            <div>
              <div style={{ fontSize: '0.65rem', color: '#64748B', textTransform: 'uppercase' }}>HOST</div>
              <div style={{ color: '#FFFFFF', fontWeight: 600, marginTop: '4px' }}>WS-104</div>
            </div>
            <div>
              <div style={{ fontSize: '0.65rem', color: '#64748B', textTransform: 'uppercase' }}>PROCESS</div>
              <div style={{ color: '#00E5FF', fontWeight: 600, marginTop: '4px' }}>powershell.exe</div>
            </div>
            <div>
              <div style={{ fontSize: '0.65rem', color: '#64748B', textTransform: 'uppercase' }}>PID</div>
              <div style={{ color: '#FFFFFF', fontWeight: 600, marginTop: '4px' }}>4812</div>
            </div>
            <div>
              <div style={{ fontSize: '0.65rem', color: '#64748B', textTransform: 'uppercase' }}>CLASSIFICATION</div>
              <div style={{ color: '#EF4444', fontWeight: 600, marginTop: '4px' }}>UNAUTHORIZED</div>
            </div>
            <div>
              <div style={{ fontSize: '0.65rem', color: '#64748B', textTransform: 'uppercase' }}>ACTION</div>
              <div style={{ color: '#10B981', fontWeight: 600, marginTop: '4px' }}>BLOCKED (JOURNALED)</div>
            </div>
            <div>
              <div style={{ fontSize: '0.65rem', color: '#64748B', textTransform: 'uppercase' }}>TIMESTAMP</div>
              <div style={{ color: '#94A3B8', fontWeight: 600, marginTop: '4px' }}>14:32:08 UTC</div>
            </div>
          </div>

          {/* Detailed Forensic Context */}
          <div className="sp-cap-split" style={{ paddingTop: '1.5rem' }}>
            
            <div className="sp-panel-inset sp-mono" style={{ fontSize: '0.75rem' }}>
              <div style={{ color: '#64748B', fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                DETECTION REASON & COMMAND LINE:
              </div>
              <div style={{ color: '#FFFFFF', marginTop: '0.4rem', lineHeight: 1.5 }}>
                Outbound connection attempt to unapproved destination <span style={{ color: '#EF4444' }}>198.51.100.44:443</span> while restricted enforcement mode was active.
              </div>
              <div style={{ color: '#94A3B8', fontSize: '0.7rem', background: '#06090E', padding: '0.65rem', borderRadius: '4px', border: '1px solid #1E293B', marginTop: '0.75rem', wordBreak: 'break-all' }}>
                powershell.exe -NoP -NonInteractive -ExecutionPolicy Bypass -Command &quot;Invoke-RestMethod -Uri https://198.51.100.44/telemetry&quot;
              </div>
            </div>

            <div className="sp-flex-col sp-gap-3" style={{ fontSize: '0.85rem', color: '#94A3B8', lineHeight: 1.6 }}>
              <div style={{ color: '#FFFFFF', fontWeight: 700, fontSize: '0.95rem' }}>Centralized Operator Oversight</div>
              <p style={{ margin: 0 }}>
                SPEMCS provides real-time visibility into unauthorized process activity, network policy violations,
                and endpoint state changes across the entire managed fleet.
              </p>
              <div className="sp-mono" style={{ fontSize: '0.75rem', color: '#00E5FF' }}>
                ✓ Telemetry streamed across authenticated WebSockets
              </div>
            </div>

          </div>

        </div>

      </div>
    </section>
  );
}
