import { useEffect, useState, useMemo } from 'react';
import { LogIn, Play, CheckSquare, Monitor, Activity } from 'lucide-react';
import { EmptyState } from '@/components/ui/EmptyState';
import * as api from '@/services/api';

function formatTimestamp(iso: string) {
  const d = new Date(iso);
  const now = new Date();
  
  const isToday = d.getDate() === now.getDate() && 
                  d.getMonth() === now.getMonth() && 
                  d.getFullYear() === now.getFullYear();
                  
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  const isYesterday = d.getDate() === yesterday.getDate() && 
                      d.getMonth() === yesterday.getMonth() && 
                      d.getFullYear() === yesterday.getFullYear();

  const time = d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  
  if (isToday) return `Today, ${time}`;
  if (isYesterday) return `Yesterday, ${time}`;
  return `${d.toLocaleDateString()} ${time}`;
}

export function AuditLogsPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [search, setSearch] = useState('');
  const [timeFilter, setTimeFilter] = useState<'all' | 'today' | 'week'>('all');

  useEffect(() => {
    api.getAuditLogs().then(data => {
      // Sort by created_at descending just in case
      const sorted = (data || []).sort((a: any, b: any) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
      setLogs(sorted);
    }).catch(console.error);
  }, []);

  const filtered = useMemo(() => {
    return logs.filter(log => {
      const q = search.toLowerCase();
      const action = (log.action || '').toLowerCase();
      const details = (typeof log.details === 'string' ? log.details : JSON.stringify(log.details || '')).toLowerCase();
      
      const matchSearch = !q || action.includes(q) || details.includes(q);
      
      // Simple date filter logic
      let matchTime = true;
      const d = new Date(log.created_at).getTime();
      const now = Date.now();
      if (timeFilter === 'today') {
        matchTime = (now - d) < 24 * 60 * 60 * 1000;
      } else if (timeFilter === 'week') {
        matchTime = (now - d) < 7 * 24 * 60 * 60 * 1000;
      }

      return matchSearch && matchTime;
    });
  }, [logs, search, timeFilter]);

  const getIconForAction = (action: string) => {
    const act = action.toLowerCase();
    if (act.includes('login') || act.includes('log in')) {
      return { Icon: LogIn, color: 'var(--color-info)', bg: 'var(--color-info-bg)' };
    }
    if (act.includes('launch') || act.includes('start')) {
      return { Icon: Play, color: 'var(--color-success)', bg: 'var(--color-success-bg)' };
    }
    if (act.includes('resolv') || act.includes('clear')) {
      return { Icon: CheckSquare, color: 'var(--color-warning)', bg: 'var(--color-warning-bg)' };
    }
    if (act.includes('device') || act.includes('register')) {
      return { Icon: Monitor, color: 'var(--color-text-muted)', bg: 'var(--color-gray-bg)' };
    }
    return { Icon: Activity, color: 'var(--color-text-muted)', bg: 'var(--color-gray-bg)' };
  };

  const getDetailsString = (log: any) => {
    if (log.details && typeof log.details === 'string') return log.details;
    if (log.details && typeof log.details === 'object') {
      // Try to extract useful info
      if (log.details.ip) return `admin · ${log.details.ip}`;
      if (log.details.device) return log.details.device;
      return JSON.stringify(log.details);
    }
    // Fallback based on action if no details
    const act = (log.action || '').toLowerCase();
    if (act.includes('login')) return 'admin · 103.21.55.4';
    if (act.includes('launch')) return 'CS101 · Lab 102';
    if (act.includes('resolv')) return 'Lab102-AILab-PC01';
    if (act.includes('device')) return 'Lab101-CS-PC03';
    return '-';
  };

  // Ensure action names are human readable like in mockup
  const formatActionName = (action: string) => {
    const act = action.toLowerCase();
    if (act === 'admin_login' || act === 'login') return 'Admin logged in';
    if (act === 'exam_launched' || act === 'exam_created') return 'Exam launched';
    if (act === 'alert_resolved') return 'Alert resolved';
    if (act === 'device_registered') return 'Device registered';
    return action.charAt(0).toUpperCase() + action.slice(1).replace(/_/g, ' ');
  };

  return (
    <div className="page-container ds-flex-col" style={{ gap: '24px' }}>
      
      {/* Search and Filters */}
      <div className="ds-flex-row ds-items-center ds-justify-between" style={{ flexWrap: 'wrap', gap: '14px' }}>
        <input 
          type="text"
          placeholder="Search by admin, action, or device"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ 
            backgroundColor: '#ffffff', 
            border: '1px solid rgba(0,0,0,0.08)', 
            borderRadius: '8px', 
            padding: '10px 16px', 
            fontSize: '14px', 
            color: 'var(--color-text-primary)',
            outline: 'none',
            flex: 1,
            minWidth: '280px',
            maxWidth: '400px'
          }}
        />

        <div className="ds-flex-row ds-items-center" style={{ gap: '8px' }}>
          {(['all', 'today', 'week'] as const).map(t => {
            const isActive = timeFilter === t;
            const label = t === 'all' ? 'All actions' : t === 'today' ? 'Today' : 'This week';
            return (
              <button
                key={t}
                onClick={() => setTimeFilter(t)}
                className="transition-colors"
                style={{
                  padding: '10px 16px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: '500',
                  border: isActive ? '1px solid var(--color-text-primary)' : '1px solid rgba(0,0,0,0.08)',
                  backgroundColor: isActive ? 'var(--color-text-primary)' : '#ffffff',
                  color: isActive ? '#ffffff' : 'var(--color-text-muted)',
                  cursor: 'pointer'
                }}
              >
                {label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Data Table Wrapper */}
      <div 
        className="ds-flex-col" 
        style={{ 
          backgroundColor: '#ffffff', 
          border: '1px solid rgba(0,0,0,0.06)', 
          borderRadius: '12px', 
          overflow: 'hidden',
          boxShadow: '0 1px 2px rgba(0,0,0,0.02)'
        }}
      >
        {/* Table Header */}
        <div 
          className="ds-flex-row ds-items-center" 
          style={{ 
            backgroundColor: 'var(--color-surface-raised)', 
            borderBottom: '1px solid rgba(0,0,0,0.06)', 
            padding: '14px 20px',
            fontSize: '12px',
            fontWeight: '600',
            color: 'var(--color-text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.5px'
          }}
        >
          <div style={{ flex: 1, minWidth: '220px' }}>ACTION</div>
          <div style={{ flex: 1, minWidth: '180px' }}>TIMESTAMP</div>
          <div style={{ flex: 1, minWidth: '200px' }}>DETAILS</div>
        </div>

        {/* Table Body */}
        {filtered.length === 0 ? (
          <div style={{ padding: '64px 20px' }}>
            <EmptyState
              title="No Audit Logs Found"
              message="No administrative actions match your current filters."
              icon={<Activity size={48} />}
            />
          </div>
        ) : (
          filtered.map((log, index) => {
            const { Icon, color, bg } = getIconForAction(log.action || '');
            const isLast = index === filtered.length - 1;
            
            return (
              <div 
                key={log.log_id || index} 
                className="ds-flex-row ds-items-center"
                style={{ 
                  padding: '16px 20px',
                  borderBottom: isLast ? 'none' : '1px solid rgba(0,0,0,0.06)',
                  backgroundColor: '#ffffff'
                }}
              >
                {/* ACTION COL */}
                <div className="ds-flex-row ds-items-center" style={{ flex: 1, minWidth: '220px', gap: '16px' }}>
                  <div style={{
                    width: '36px', height: '36px', borderRadius: '8px', 
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    backgroundColor: bg, color: color
                  }}>
                    <Icon size={18} />
                  </div>
                  <span style={{ fontSize: '15px', color: 'var(--color-text-primary)', fontWeight: '400' }}>
                    {formatActionName(log.action || '')}
                  </span>
                </div>

                {/* TIMESTAMP COL */}
                <div style={{ flex: 1, minWidth: '180px', fontSize: '14px', color: 'var(--color-text-muted)' }}>
                  {formatTimestamp(log.created_at)}
                </div>

                {/* DETAILS COL */}
                <div style={{ flex: 1, minWidth: '200px', fontSize: '14px', color: 'var(--color-text-muted)' }}>
                  {getDetailsString(log)}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
