import { NavLink, useLocation } from 'react-router-dom';
import { useApp } from '@/context/AppContext';
import {
  LayoutDashboard,
  ShieldCheck,
  AlertTriangle,
  ScrollText,
  Settings,
  ChevronLeft,
  PanelLeftClose,
  Monitor,
  FileText,
  Wifi,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

interface NavItem {
  label: string;
  path: string;
  icon: LucideIcon;
  badge?: number;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  mobileOpen: boolean;
  onMobileClose: () => void;
}

export function Sidebar({ collapsed, onToggle, mobileOpen, onMobileClose }: SidebarProps) {
  const location = useLocation();
  const { alerts, wsConnected } = useApp();
  const openAlertCount = alerts.filter((a: any) => a.status === 'open').length;

  const navSections: NavSection[] = [
    {
      title: 'Overview',
      items: [{ label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard }],
    },
    {
      title: 'Proctoring',
      items: [
        { label: 'Exam Shield', path: '/exam-shield', icon: ShieldCheck },
        { label: 'Devices', path: '/devices', icon: Monitor },
        { label: 'Alerts', path: '/alerts', icon: AlertTriangle, badge: openAlertCount },
      ],
    },
    {
      title: 'Analytics',
      items: [
        { label: 'Reports', path: '/reports', icon: FileText },
        { label: 'Audit Logs', path: '/audit-logs', icon: ScrollText },
      ],
    },
    {
      title: 'System',
      items: [{ label: 'Settings', path: '/settings', icon: Settings }],
    },
  ];

  return (
    <>
      {mobileOpen && <div className="sidebar-overlay" onClick={onMobileClose} />}
      <aside className={`sidebar ${collapsed ? 'collapsed' : ''} ${mobileOpen ? 'mobile-open' : ''}`}>
        <div className="sidebar-brand">
          <div className="sidebar-logo">
            <img src="/logo.jpg" alt="CampusShield Logo" width="32" height="32" style={{ borderRadius: '6px', objectFit: 'cover' }} />
          </div>
          {!collapsed && (
            <div className="sidebar-brand-text">
              <span className="sidebar-brand-line1">CAMPUS</span>
              <span className="sidebar-brand-line2">SHIELD</span>
            </div>
          )}
          <button className="sidebar-collapse-btn desktop-only" onClick={onToggle} aria-label="Toggle sidebar">
            {collapsed ? <ChevronLeft size={18} className="rotate-180" /> : <ChevronLeft size={18} />}
          </button>
        </div>

        <nav className="sidebar-nav">
          {navSections.map((section) => (
            <div key={section.title} className="sidebar-section">
              {!collapsed && <div className="sidebar-section-title">{section.title}</div>}
              {section.items.map((item) => {
                const isActive = location.pathname === item.path || location.pathname.startsWith(item.path + '/');
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={`sidebar-nav-item ${isActive ? 'active' : ''}`}
                    onClick={onMobileClose}
                    title={collapsed ? item.label : undefined}
                  >
                    <span className="sidebar-nav-icon">
                      <item.icon size={18} />
                    </span>
                    {!collapsed && <span className="sidebar-nav-label">{item.label}</span>}
                    {!collapsed && item.badge && item.badge > 0 && (
                      <span className="sidebar-nav-badge">{item.badge}</span>
                    )}
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>



        {collapsed && (
          <button className="sidebar-expand-btn" onClick={onToggle} aria-label="Expand sidebar">
            <PanelLeftClose size={18} className="rotate-180" />
          </button>
        )}
      </aside>
    </>
  );
}
