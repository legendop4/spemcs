import { useApp } from '@/context/AppContext';
import { Menu, LogOut, Radio, User } from 'lucide-react';

interface EnterpriseTopBarProps {
  title: string;
  subtitle?: string;
  onMobileMenu: () => void;
}

export function EnterpriseTopBar({
  title,
  subtitle,
  onMobileMenu,
}: EnterpriseTopBarProps) {
  const { currentUser, wsConnected, logout } = useApp();

  return (
    <header
      style={{
        height: '64px',
        backgroundColor: 'var(--ep-header-bg)',
        backdropFilter: 'blur(8px)',
        borderBottom: '1px solid var(--ep-surface-border)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 20px',
        position: 'sticky',
        top: 0,
        zIndex: 30,
        flexShrink: 0,
        width: '100%',
        boxSizing: 'border-box',
      }}
    >
      {/* Title & Subtitle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0 }}>
        <button
          onClick={onMobileMenu}
          className="ep-mobile-only"
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--ep-text-primary)',
            cursor: 'pointer',
            padding: '6px',
            borderRadius: '4px',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          aria-label="Open Navigation Menu"
        >
          <Menu size={22} />
        </button>

        <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>
          <h1
            style={{
              fontSize: '16px',
              fontWeight: '700',
              color: '#FFFFFF',
              letterSpacing: '-0.3px',
              margin: 0,
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {title}
          </h1>
          {subtitle && (
            <span
              className="ep-desktop-only"
              style={{
                fontSize: '12px',
                color: 'var(--ep-text-secondary)',
                marginTop: '1px',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              {subtitle}
            </span>
          )}
        </div>
      </div>

      {/* Right Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexShrink: 0 }}>
        {/* Realtime Connection Badge */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 8px',
            borderRadius: '20px',
            backgroundColor: wsConnected
              ? 'rgba(16, 185, 129, 0.1)'
              : 'rgba(239, 68, 68, 0.1)',
            border: `1px solid ${
              wsConnected ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'
            }`,
            fontSize: '11px',
            fontWeight: '600',
            color: wsConnected ? '#34D399' : '#F87171',
            letterSpacing: '0.5px',
          }}
          title={
            wsConnected
              ? 'WebSocket stream active (/api/v1/ws/dashboard)'
              : 'WebSocket disconnected - attempting reconnection'
          }
        >
          <Radio
            size={12}
            style={{
              animation: wsConnected ? 'pulse 2s infinite' : 'none',
              flexShrink: 0,
            }}
          />
          <span className="ep-desktop-only">{wsConnected ? 'CONNECTED' : 'DISCONNECTED'}</span>
        </div>

        {/* Environment Tag */}
        <div
          className="ep-desktop-only"
          style={{
            alignItems: 'center',
            gap: '6px',
            padding: '4px 8px',
            borderRadius: '4px',
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            border: '1px solid var(--ep-surface-border)',
            fontSize: '11px',
            fontWeight: '500',
            color: 'var(--ep-text-muted)',
          }}
        >
          <span>REGION:</span>
          <span style={{ color: 'var(--ep-text-secondary)', fontFamily: 'var(--ep-font-mono)' }}>
            ap-south-1
          </span>
        </div>

        {/* Operator Profile */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            paddingLeft: '10px',
            borderLeft: '1px solid var(--ep-surface-border)',
          }}
        >
          <div
            style={{
              width: '30px',
              height: '30px',
              borderRadius: '50%',
              backgroundColor: 'rgba(99, 102, 241, 0.15)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--ep-indigo)',
              flexShrink: 0,
            }}
          >
            <User size={15} />
          </div>

          <div
            className="ep-desktop-only"
            style={{ display: 'flex', flexDirection: 'column' }}
          >
            <span
              style={{
                fontSize: '12px',
                fontWeight: '600',
                color: '#FFFFFF',
                lineHeight: '1.2',
              }}
            >
              {currentUser?.username || 'SecOps Operator'}
            </span>
            <span
              style={{
                fontSize: '10px',
                color: 'var(--ep-cyan)',
                textTransform: 'uppercase',
                fontWeight: '700',
                letterSpacing: '0.5px',
              }}
            >
              {currentUser?.role || 'ADMIN'}
            </span>
          </div>

          <button
            onClick={logout}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--ep-text-muted)',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '4px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'color 0.15s ease',
            }}
            title="Sign out of SPEMCS"
            aria-label="Sign out"
          >
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </header>
  );
}
