import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Shield, ArrowRight, Menu, X } from 'lucide-react';

export function PublicNavbar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 25);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToSection = (id: string) => {
    setMobileMenuOpen(false);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <header className={`sp-navbar ${scrolled ? 'scrolled' : ''}`}>
      <div className="sp-container">
        <div className="sp-nav-inner">
          
          {/* Brand Mark */}
          <Link to="/" className="sp-flex-items-center sp-gap-3" style={{ textDecoration: 'none' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '4px',
                backgroundColor: '#0D121B',
                border: '1px solid #1E293B',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Shield style={{ width: '16px', height: '16px', color: '#00E5FF' }} />
            </div>
            <div className="sp-flex-items-center sp-gap-2">
              <span className="sp-mono" style={{ fontWeight: 800, fontSize: '1.15rem', color: '#FFFFFF', letterSpacing: '-0.02em' }}>
                SPEMCS
              </span>
              <span className="sp-badge sp-badge-cyan" style={{ fontSize: '0.62rem' }}>
                ENTERPRISE
              </span>
            </div>
          </Link>

          {/* Desktop Navigation Links */}
          <nav className="sp-nav-links">
            <button onClick={() => scrollToSection('capabilities')} className="sp-nav-link">
              Capabilities
            </button>
            <button onClick={() => scrollToSection('architecture')} className="sp-nav-link">
              Architecture
            </button>
            <button onClick={() => scrollToSection('cryptographic-trust')} className="sp-nav-link">
              Cryptographic Trust
            </button>
            <button onClick={() => scrollToSection('telemetry')} className="sp-nav-link">
              Telemetry
            </button>
            <button onClick={() => scrollToSection('console-preview')} className="sp-nav-link">
              Console
            </button>
          </nav>

          {/* Action CTAs */}
          <div className="sp-nav-actions">
            <Link to="/login" className="sp-btn-secondary" style={{ padding: '0.45rem 1rem', fontSize: '0.8rem' }}>
              Sign In <ArrowRight style={{ width: '14px', height: '14px', marginLeft: '4px' }} />
            </Link>
            <Link to="/console/overview" className="sp-btn-primary" style={{ padding: '0.45rem 1.15rem', fontSize: '0.8rem' }}>
              Launch Console
            </Link>
          </div>

          {/* Mobile Toggle Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="sp-mobile-toggle"
            aria-label="Toggle Navigation"
          >
            {mobileMenuOpen ? <X style={{ width: '22px', height: '22px' }} /> : <Menu style={{ width: '22px', height: '22px' }} />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      <div className={`sp-mobile-menu ${mobileMenuOpen ? 'open' : ''}`}>
        <button onClick={() => scrollToSection('capabilities')} className="sp-nav-link" style={{ textAlign: 'left', padding: '0.5rem 0' }}>
          Capabilities
        </button>
        <button onClick={() => scrollToSection('architecture')} className="sp-nav-link" style={{ textAlign: 'left', padding: '0.5rem 0' }}>
          Architecture
        </button>
        <button onClick={() => scrollToSection('cryptographic-trust')} className="sp-nav-link" style={{ textAlign: 'left', padding: '0.5rem 0' }}>
          Cryptographic Trust
        </button>
        <button onClick={() => scrollToSection('telemetry')} className="sp-nav-link" style={{ textAlign: 'left', padding: '0.5rem 0' }}>
          Telemetry
        </button>
        <button onClick={() => scrollToSection('console-preview')} className="sp-nav-link" style={{ textAlign: 'left', padding: '0.5rem 0' }}>
          Console Preview
        </button>
        <div className="sp-flex-col sp-gap-2" style={{ paddingTop: '1rem', borderTop: '1px solid #1E293B' }}>
          <Link to="/login" className="sp-btn-secondary" style={{ justifyContent: 'center' }}>
            Sign In
          </Link>
          <Link to="/console/overview" className="sp-btn-primary" style={{ justifyContent: 'center' }}>
            Launch Console
          </Link>
        </div>
      </div>
    </header>
  );
}
