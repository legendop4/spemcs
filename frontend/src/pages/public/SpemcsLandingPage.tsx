import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { PublicNavbar } from '@/components/public/PublicNavbar';
import { HeroSection } from '@/components/public/HeroSection';
import { CapabilitiesSection } from '@/components/public/CapabilitiesSection';
import { ArchitectureSection } from '@/components/public/ArchitectureSection';
import { CryptographicTrustSection } from '@/components/public/CryptographicTrustSection';
import { TelemetrySection } from '@/components/public/TelemetrySection';
import { ConsolePreviewSection } from '@/components/public/ConsolePreviewSection';
import { FinalCtaSection } from '@/components/public/FinalCtaSection';
import { PublicFooter } from '@/components/public/PublicFooter';
import '@/landing.css';

gsap.registerPlugin(ScrollTrigger);

export function SpemcsLandingPage() {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Check for prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) return;

    const ctx = gsap.context(() => {
      // Subtle staggered reveals for section content
      const sections = ['#capabilities', '#architecture', '#cryptographic-trust', '#telemetry', '#console-preview'];
      
      sections.forEach(selector => {
        const el = document.querySelector(selector);
        if (el) {
          gsap.fromTo(
            el.querySelectorAll('.sp-panel, .sp-tag, h2, .sp-3d-console-tilt'),
            {
              opacity: 0,
              y: 20,
            },
            {
              opacity: 1,
              y: 0,
              duration: 0.65,
              stagger: 0.08,
              ease: 'power2.out',
              scrollTrigger: {
                trigger: el,
                start: 'top 82%',
                toggleActions: 'play none none none',
              },
            }
          );
        }
      });
    }, containerRef);

    return () => ctx.revert();
  }, []);

  return (
    <div ref={containerRef} className="sp-landing">
      {/* Background Architectural Canvas */}
      <div className="sp-grid-canvas" />
      <div className="sp-ambient-top" />

      {/* Navigation */}
      <PublicNavbar />

      {/* Main Flow */}
      <main>
        {/* 01: Hero */}
        <HeroSection />

        {/* 02: Platform & Capabilities */}
        <CapabilitiesSection />

        {/* 03: Technical Architecture */}
        <ArchitectureSection />

        {/* 04: Cryptographic Trust */}
        <CryptographicTrustSection />

        {/* 05: Security Telemetry */}
        <TelemetrySection />

        {/* 06: Product Console Preview */}
        <ConsolePreviewSection />

        {/* 07: Final CTA */}
        <FinalCtaSection />
      </main>

      {/* Footer */}
      <PublicFooter />
    </div>
  );
}

export default SpemcsLandingPage;
