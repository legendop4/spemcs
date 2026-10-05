import { NavLink, useLocation } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Server,
  Activity,
  AlertTriangle,
  FileCode,
  Lock,
  ScrollText,
  Key,
  Sliders,
  ChevronLeft,
  ChevronRight,
  X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

interface NavItem {
  label: string;
  path: string;
  icon: LucideIcon;
  badge?: string | number;
}

interface NavGroup {
  group: string;
  items: NavItem[];
}

interface EnterpriseSidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  mobileOpen: boolean;
  onMobileClose: () => void;
}

export function EnterpriseSidebar({
  collapsed,
  onToggle,
  mobileOpen,
  onMobileClose,
}: EnterpriseSidebarProps) {
  const location = useLocation();

  const navGroups: NavGroup[] = [
    {
      group: 'Security Operations',
      items: [
        { label: 'Overview', path: '/console/overview', icon: LayoutDashboard },
        { label: 'Endpoints', path: '/console/endpoints', icon: Server },
        { label: 'Security Events', path: '/console/events', icon: Activity },
        { label: 'Incident Alerts', path: '/console/alerts', icon: AlertTriangle },
      ],
    },
    {
      group: 'Policy & Control',
      items: [
        { label: 'Network Policies', path: '/console/policies', icon: FileCode },
        { label: 'Enforcement Sessions', path: '/console/sessions', icon: Lock },
      ],
    },
    {
      group: 'Governance & Trust',
      items: [
        { label: 'Audit Trail', path: '/console/audit', icon: ScrollText },
        { label: 'Cryptographic Authority', path: '/console/authority', icon: Key },
      ],
    },
    {
      group: 'System',
      items: [
        { label: 'Settings', path: '/console/settings', icon: Sliders },
      ],
    },
  ];

  const renderNavLinks = (isMobileDrawer = false) => (
    <div style={{ flex: 1, overflowY: 'auto', padding: '14px 10px' }}>
      {navGroups.map((group) => (
        <div key={group.group} style={{ marginBottom: '20px' }}>
          {(!collapsed || isMobileDrawer) && (
            <div
              style={{
                fontSize: '10px',
                fontWeight: '700',
                textTransform: 'uppercase',
                letterSpacing: '0.8px',
                color: 'var(--ep-text-muted)',
                padding: '0 8px',
                marginBottom: '8px',
              }}
            >
              {group.group}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
            {group.items.map((item) => {
              const isActive =
                location.pathname === item.path ||
                location.pathname.startsWith(`${item.path}/`);

              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  onClick={() => {
                    if (isMobileDrawer) {
                      onMobileClose();
                    }
                  }}
                  title={collapsed && !isMobileDrawer ? item.label : undefined}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: collapsed && !isMobileDrawer ? 'center' : 'flex-start',
                    gap: '10px',
                    padding: '8px 10px',
                    borderRadius: '6px',
                    fontSize: '13px',
                    fontWeight: isActive ? '600' : '500',
                    textDecoration: 'none',
                    color: isActive ? '#FFFFFF' : 'var(--ep-text-secondary)',
                    backgroundColor: isActive
                      ? 'rgba(6, 182, 212, 0.12)'
                      : 'transparent',
                    borderLeft: isActive
                      ? '3px solid var(--ep-cyan)'
                      : '3px solid transparent',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <item.icon
                    size={17}
                    style={{ color: isActive ? 'var(--ep-cyan)' : 'inherit', flexShrink: 0 }}
                  />
                  {(!collapsed || isMobileDrawer) && <span>{item.label}</span>}
                </NavLink>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );

  return (
    <>
      {/* Mobile Drawer Overlay */}
      {mobileOpen && (
        <>
          <div
            className="ep-sidebar-backdrop"
            onClick={onMobileClose}
            aria-hidden="true"
          />
          <aside className="ep-sidebar-drawer" role="dialog" aria-modal="true" aria-label="Navigation drawer">
            <div
              style={{
                height: '64px',
                borderBottom: '1px solid var(--ep-surface-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0 18px',
                flexShrink: 0,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '34px',
                    height: '34px',
                    borderRadius: '8px',
                    backgroundColor: 'rgba(6, 182, 212, 0.12)',
                    border: '1px solid rgba(6, 182, 212, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--ep-cyan)',
                  }}
                >
                  <Shield size={20} />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <span
                    style={{
                      fontSize: '15px',
                      fontWeight: '700',
                      letterSpacing: '1px',
                      color: '#FFFFFF',
                      lineHeight: '1.1',
                    }}
                  >
                    SPEMCS
                  </span>
                  <span
                    style={{
                      fontSize: '10px',
                      color: 'var(--ep-cyan)',
                      letterSpacing: '0.6px',
                      textTransform: 'uppercase',
                      fontWeight: '600',
                    }}
                  >
                    Enterprise Security
                  </span>
                </div>
              </div>

              <button
                onClick={onMobileClose}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--ep-text-secondary)',
                  cursor: 'pointer',
                  padding: '6px',
                  borderRadius: '4px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
                aria-label="Close navigation"
              >
                <X size={20} />
              </button>
            </div>

            {renderNavLinks(true)}
          </aside>
        </>
      )}

      {/* Desktop Persistent Sidebar */}
      <aside
        className="ep-desktop-only"
        style={{
          width: collapsed ? '68px' : '260px',
          backgroundColor: 'var(--ep-sidebar-bg)',
          borderRight: '1px solid var(--ep-surface-border)',
          display: 'flex',
          flexDirection: 'column',
          transition: 'width 0.2s ease',
          zIndex: 45,
          height: '100vh',
          position: 'sticky',
          top: 0,
          flexShrink: 0,
        }}
      >
        {/* Brand Header */}
        <div
          style={{
            height: '64px',
            borderBottom: '1px solid var(--ep-surface-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: collapsed ? 'center' : 'space-between',
            padding: collapsed ? '0' : '0 18px',
            flexShrink: 0,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '34px',
                height: '34px',
                borderRadius: '8px',
                backgroundColor: 'rgba(6, 182, 212, 0.12)',
                border: '1px solid rgba(6, 182, 212, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--ep-cyan)',
              }}
            >
              <Shield size={20} />
            </div>

            {!collapsed && (
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <span
                  style={{
                    fontSize: '15px',
                    fontWeight: '700',
                    letterSpacing: '1px',
                    color: '#FFFFFF',
                    lineHeight: '1.1',
                  }}
                >
                  SPEMCS
                </span>
                <span
                  style={{
                    fontSize: '10px',
                    color: 'var(--ep-cyan)',
                    letterSpacing: '0.6px',
                    textTransform: 'uppercase',
                    fontWeight: '600',
                  }}
                >
                  Enterprise Security
                </span>
              </div>
            )}
          </div>

          {!collapsed && (
            <button
              onClick={onToggle}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--ep-text-secondary)',
                cursor: 'pointer',
                padding: '6px',
                borderRadius: '4px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
              title="Collapse sidebar"
            >
              <ChevronLeft size={16} />
            </button>
          )}
        </div>

        {/* Navigation List */}
        {renderNavLinks(false)}

        {/* Footer: Clean collapse toggle */}
        <div
          style={{
            padding: '12px 10px',
            borderTop: '1px solid var(--ep-surface-border)',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            flexShrink: 0,
          }}
        >
          {collapsed ? (
            <button
              onClick={onToggle}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--ep-text-secondary)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '6px',
                borderRadius: '4px',
              }}
              title="Expand sidebar"
            >
              <ChevronRight size={18} />
            </button>
          ) : (
            <button
              onClick={onToggle}
              style={{
                background: 'transparent',
                border: '1px solid var(--ep-surface-border)',
                color: 'var(--ep-text-muted)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                padding: '6px 10px',
                borderRadius: '6px',
                fontSize: '12px',
                transition: 'all 0.15s ease',
              }}
              title="Collapse sidebar"
            >
              <ChevronLeft size={14} />
              <span>Collapse Menu</span>
            </button>
          )}
        </div>
      </aside>
    </>
  );
}
