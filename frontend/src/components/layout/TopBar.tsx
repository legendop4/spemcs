import { useState, useRef, useEffect, type ChangeEvent } from 'react';
import { useApp } from '@/context/AppContext';
import { Search, Bell, Menu } from 'lucide-react';

interface TopBarProps {
  title: string;
  description?: string;
  onMobileMenu: () => void;
}

interface SearchResult {
  type: 'building' | 'lab' | 'computer' | 'alert';
  id: string;
  label: string;
  sublabel: string;
}

export function TopBar({ title, description, onMobileMenu }: TopBarProps) {
  const { currentUser, labs = [], alerts = [], devices = [] } = useApp() as any;
  const [query, setQuery] = useState('');
  const [showResults, setShowResults] = useState(false);
  const [showNotifs, setShowNotifs] = useState(false);
  const searchRef = useRef<HTMLDivElement>(null);
  const notifRef = useRef<HTMLDivElement>(null);

  const openAlerts = (alerts || []).filter((a: any) => a.status === 'open' || a.status === 'investigating');

  const results: SearchResult[] = query.trim().length > 1
    ? [
        ...(labs || [])
          .filter((l: any) => (l.name || l.lab_name || '').toLowerCase().includes(query.toLowerCase()) || (l.code || '').toLowerCase().includes(query.toLowerCase()))
          .map((l: any) => ({ type: 'lab' as const, id: l.id || l.lab_id, label: l.name || l.lab_name, sublabel: l.code || '' })),
        ...(devices || [])
          .filter((c: any) => (c.name || c.device_name || '').toLowerCase().includes(query.toLowerCase()) || (c.registered_ip || '').toLowerCase().includes(query.toLowerCase()))
          .map((c: any) => ({ type: 'computer' as const, id: c.id || c.device_id, label: c.name || c.device_name, sublabel: c.registered_ip || '' })),
        ...(alerts || [])
          .filter((a: any) => (a.type || a.event_type || '').toLowerCase().includes(query.toLowerCase()) || (a.description || a.message || '').toLowerCase().includes(query.toLowerCase()))
          .map((a: any) => ({ type: 'alert' as const, id: a.id || a.alert_id, label: a.type || a.event_type || 'Alert', sublabel: a.severity || '' })),
      ].slice(0, 8)
    : [];

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) setShowResults(false);
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) setShowNotifs(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  return (
    <header className="topbar">
      <button className="topbar-menu-btn mobile-only" onClick={onMobileMenu} aria-label="Menu">
        <Menu size={20} />
      </button>

      <div className="topbar-titles">
        <h2 className="topbar-title">{title}</h2>
        {description && <p className="topbar-description">{description}</p>}
      </div>

      <div className="topbar-right">
        <div className="topbar-search" ref={searchRef}>
          <Search size={16} className="topbar-search-icon" />
          <input
            type="text"
            className="topbar-search-input"
            placeholder="Search buildings, labs, computers..."
            value={query}
            onChange={(e: ChangeEvent<HTMLInputElement>) => {
              setQuery(e.target.value);
              setShowResults(true);
            }}
            onFocus={() => setShowResults(true)}
          />
          {showResults && results.length > 0 && (
            <div className="search-results">
              {results.map((r) => (
                <div key={`${r.type}-${r.id}`} className="search-result-item">
                  <span className={`search-result-type type-${r.type}`}>{r.type}</span>
                  <span className="search-result-label">{r.label}</span>
                  <span className="search-result-sublabel">{r.sublabel}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="topbar-notif" ref={notifRef}>
          <button className="topbar-icon-btn" onClick={() => setShowNotifs(!showNotifs)} aria-label="Notifications">
            <Bell size={18} />
            {openAlerts.length > 0 && <span className="notif-badge">{openAlerts.length}</span>}
          </button>
          {showNotifs && (
            <div className="notif-dropdown">
              <div className="notif-dropdown-header">
                <span>Notifications</span>
                <span className="notif-count">{openAlerts.length} active</span>
              </div>
              <div className="notif-dropdown-body">
                {openAlerts.length === 0 ? (
                  <div className="notif-empty">No active notifications</div>
                ) : (
                  openAlerts.slice(0, 5).map((a: any) => (
                    <div key={a.alert_id || a.id} className="notif-item">
                      <span className={`notif-dot severity-${a.severity}`} />
                      <div className="notif-item-content">
                        <span className="notif-item-title">{a.type}</span>
                        <span className="notif-item-sub">{a.severity} · {a.status}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        <div className="topbar-user">
          <div className="topbar-user-avatar" style={{ background: currentUser?.avatarColor ?? '#6B2F12' }}>
            {(currentUser?.name || currentUser?.username || 'A').charAt(0).toUpperCase()}
          </div>
          <div className="topbar-user-info desktop-only">
            <span className="topbar-user-name">{currentUser?.name || currentUser?.username || 'Admin'}</span>
            <span className="topbar-user-status">
              <span className="topbar-user-status-dot" />
              Online
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
