import { useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

const pageMeta: Record<string, { title: string; description: string }> = {
  '/dashboard': { title: 'Dashboard', description: 'Monitor your campus security infrastructure and exam protection.' },
  '/exam-shield': { title: 'Exam Shield', description: 'Manage and monitor exam protection across all computers.' },
  '/alerts': { title: 'Alerts & Violations', description: 'Track, investigate, and resolve security incidents.' },
  '/audit-logs': { title: 'Audit Logs', description: 'Complete record of all security-relevant actions.' },
  '/settings': { title: 'Settings', description: 'Manage your account and security preferences.' },
};

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  const meta = pageMeta[location.pathname] ?? { title: 'CampusShield', description: '' };

  return (
    <div className="app-shell">
      <div className="bg-blob bg-blob-1" />
      <div className="bg-blob bg-blob-2" />
      <div className="bg-blob bg-blob-3" />
      <div className="bg-grid-overlay" />

      <Sidebar
        collapsed={collapsed}
        onToggle={() => setCollapsed(!collapsed)}
        mobileOpen={mobileOpen}
        onMobileClose={() => setMobileOpen(false)}
      />

      <div className={`app-main ${collapsed ? 'sidebar-collapsed' : ''}`}>
        <TopBar
          title={meta.title}
          description={meta.description}
          onMobileMenu={() => setMobileOpen(true)}
        />
        <main className="app-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
