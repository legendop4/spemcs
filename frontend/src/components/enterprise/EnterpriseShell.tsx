import { useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { EnterpriseSidebar } from './EnterpriseSidebar';
import { EnterpriseTopBar } from './EnterpriseTopBar';
import '@/enterprise.css';

export function EnterpriseShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  // Determine topbar title & description based on enterprise subpath
  let title = 'Enterprise Console';
  let subtitle = 'SPEMCS Endpoint Security & Policy Enforcement';

  const path = location.pathname;
  if (path.startsWith('/console/overview')) {
    title = 'Security Overview';
    subtitle = 'Real-time Fleet Telemetry & Threat Posture';
  } else if (path.startsWith('/console/endpoints')) {
    title = 'Fleet Endpoints';
    subtitle = 'Host Inventory, Integrity States & Policy Enforcement';
  } else if (path.startsWith('/console/events')) {
    title = 'Security Events';
    subtitle = 'Process Activity, Policy Violations & Threat Audit Stream';
  } else if (path.startsWith('/console/alerts')) {
    title = 'Incident Alerts';
    subtitle = 'Triage & Resolution of Endpoint Security Violations';
  } else if (path.startsWith('/console/policies')) {
    title = 'Network Policies';
    subtitle = 'Firewall Rule Configuration & Cryptographic Profiles';
  } else if (path.startsWith('/console/sessions')) {
    title = 'Enforcement Sessions';
    subtitle = 'Active Policy Runs & Host Restriction Control';
  } else if (path.startsWith('/console/audit')) {
    title = 'Audit Trail';
    subtitle = 'Append-Only Record of Operator & System Actions';
  } else if (path.startsWith('/console/authority')) {
    title = 'Cryptographic Authority';
    subtitle = 'Key Lifecycle, RSA-PSS Signing & Trust Verification';
  } else if (path.startsWith('/console/settings')) {
    title = 'System Settings';
    subtitle = 'Platform Configuration & Telemetry Health Probes';
  }

  return (
    <div className="enterprise-root" style={{ width: '100%', overflowX: 'hidden' }}>
      <div style={{ display: 'flex', width: '100%', minHeight: '100vh', overflowX: 'hidden' }}>
        {/* Sidebar */}
        <EnterpriseSidebar
          collapsed={collapsed}
          onToggle={() => setCollapsed(!collapsed)}
          mobileOpen={mobileOpen}
          onMobileClose={() => setMobileOpen(false)}
        />

        {/* Content Container */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, width: '100%', overflowX: 'hidden' }}>
          <EnterpriseTopBar
            title={title}
            subtitle={subtitle}
            onMobileMenu={() => setMobileOpen(true)}
          />

          <main className="ep-page-container" style={{ flex: 1, minWidth: 0, boxSizing: 'border-box' }}>
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}
