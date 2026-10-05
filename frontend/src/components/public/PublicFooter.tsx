import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';

export function PublicFooter() {
  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <footer className="sp-footer">
      <div className="sp-container">
        
        <div className="sp-footer-grid">
          
          {/* Brand Info */}
          <div className="sp-flex-col sp-gap-3">
            <div className="sp-flex-items-center sp-gap-2" style={{ color: '#FFFFFF' }}>
              <div style={{ width: '26px', height: '26px', borderRadius: '4px', background: '#0D121B', border: '1px solid #1E293B', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Shield style={{ width: '14px', height: '14px', color: '#00E5FF' }} />
              </div>
              <span style={{ fontWeight: 800, fontSize: '0.95rem', letterSpacing: '-0.02em' }}>SPEMCS</span>
            </div>
            <p style={{ fontSize: '0.78rem', color: '#64748B', maxWidth: '420px', lineHeight: 1.6, fontFamily: 'Inter, sans-serif', margin: 0 }}>
              Secure Policy & Endpoint Monitoring Control System. Centralized Windows endpoint security,
              cryptographically signed policy enforcement, and real-time operational telemetry.
            </p>
            <div style={{ fontSize: '0.7rem', color: '#475569', marginTop: '0.5rem' }}>
              Cryptographic Invariant: RSA-PSS 2048-bit with SHA-256 Digest Verification.
            </div>
          </div>

          {/* Platform Navigation */}
          <div>
            <div style={{ fontSize: '0.72rem', textTransform: 'uppercase', color: '#FFFFFF', fontWeight: 700, letterSpacing: '0.06em' }}>
              Platform & Architecture
            </div>
            <ul className="sp-footer-list">
              <li><a href="#capabilities" className="sp-footer-link">Platform Capabilities</a></li>
              <li><a href="#architecture" className="sp-footer-link">System Architecture</a></li>
              <li><a href="#cryptographic-trust" className="sp-footer-link">Cryptographic Trust</a></li>
              <li><a href="#telemetry" className="sp-footer-link">Security Telemetry</a></li>
            </ul>
          </div>

          {/* Security Console Links */}
          <div>
            <div style={{ fontSize: '0.72rem', textTransform: 'uppercase', color: '#FFFFFF', fontWeight: 700, letterSpacing: '0.06em' }}>
              Security Console
            </div>
            <ul className="sp-footer-list">
              <li><Link to="/login" className="sp-footer-link">Operator Sign In</Link></li>
              <li><Link to="/console/overview" className="sp-footer-link">Console Overview</Link></li>
              <li><Link to="/console/endpoints" className="sp-footer-link">Endpoint Inventory</Link></li>
              <li><Link to="/console/events" className="sp-footer-link">Security Event Stream</Link></li>
            </ul>
          </div>

        </div>

        {/* Bottom Bar */}
        <div className="sp-flex-between" style={{ paddingTop: '1.75rem', borderTop: '1px solid rgba(255, 255, 255, 0.06)', fontSize: '0.72rem', color: '#64748B', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            © {new Date().getFullYear()} SPEMCS. Enterprise Endpoint Security & Policy Enforcement.
          </div>
          <button
            onClick={scrollToTop}
            className="sp-footer-link"
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
          >
            ↑ Back to top
          </button>
        </div>

      </div>
    </footer>
  );
}
