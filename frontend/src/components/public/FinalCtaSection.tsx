import { Link } from 'react-router-dom';
import { Shield, ArrowRight } from 'lucide-react';

export function FinalCtaSection() {
  return (
    <section className="sp-section" style={{ background: 'linear-gradient(180deg, #070A0F 0%, #04060A 100%)', textAlign: 'center', overflow: 'hidden' }}>
      
      {/* Background radial glow */}
      <div
        style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          width: '600px',
          height: '300px',
          background: 'rgba(0, 229, 255, 0.035)',
          borderRadius: '50%',
          filter: 'blur(90px)',
          pointerEvents: 'none',
        }}
      />

      <div className="sp-container" style={{ maxWidth: '800px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1.25rem' }}>
        <div className="sp-tag">
          <Shield style={{ width: '13px', height: '13px' }} /> ENTERPRISE ENDPOINT CONTROL
        </div>

        <h2 style={{ fontSize: '3rem', fontWeight: 800, color: '#FFFFFF', letterSpacing: '-0.035em', lineHeight: 1.15, margin: 0 }}>
          Your endpoints.<br />
          Your policies.<br />
          <span style={{ background: 'linear-gradient(135deg, #FFFFFF 0%, #CBD5E1 50%, #94A3B8 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            One control plane.
          </span>
        </h2>

        <p style={{ fontSize: '1.1rem', color: '#94A3B8', maxWidth: '580px', lineHeight: 1.6, margin: 0 }}>
          Explore the SPEMCS security console. Centrally manage Windows endpoints with cryptographic
          certainty and real-time operational oversight.
        </p>

        <div className="sp-flex-items-center sp-gap-4" style={{ marginTop: '1rem', flexWrap: 'wrap', justifyContent: 'center' }}>
          <Link to="/login" className="sp-btn-primary" style={{ padding: '0.75rem 1.75rem', fontSize: '0.9rem' }}>
            Open Security Console <ArrowRight style={{ width: '16px', height: '16px', marginLeft: '6px' }} />
          </Link>
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="sp-btn-secondary"
            style={{ padding: '0.75rem 1.75rem', fontSize: '0.9rem' }}
          >
            Review GitHub Repository
          </a>
        </div>
      </div>

    </section>
  );
}
