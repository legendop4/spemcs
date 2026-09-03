import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import { LogOut } from 'lucide-react';

export function SettingsPage() {
  const { currentUser, logout, wsConnected } = useApp();

  return (
    <div className="page-container ds-flex-col" style={{ gap: '24px' }}>
      
      {/* Account Card */}
      <div 
        className="ds-flex-col" 
        style={{ 
          backgroundColor: '#ffffff', 
          border: '1px solid rgba(0,0,0,0.06)', 
          borderRadius: '12px', 
          padding: '24px', 
          boxShadow: '0 1px 2px rgba(0,0,0,0.02)' 
        }}
      >
        <div style={{ fontSize: '12px', fontWeight: '500', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '24px' }}>
          ACCOUNT
        </div>
        <div className="ds-flex-row ds-items-center ds-justify-between" style={{ marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
          <div className="ds-flex-row ds-items-center" style={{ gap: '16px' }}>
            <div 
              style={{ 
                width: '48px', 
                height: '48px', 
                borderRadius: '50%', 
                backgroundColor: 'var(--color-text-primary)', 
                color: 'var(--color-warning)', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                fontSize: '18px', 
                fontWeight: '500' 
              }}
            >
              {currentUser?.username?.charAt(0).toUpperCase() || 'A'}
            </div>
            <div className="ds-flex-col">
              <div style={{ fontSize: '15px', color: 'var(--color-text-primary)', fontWeight: '500' }}>
                {currentUser?.username || 'admin'}
              </div>
              <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>
                {currentUser?.email || 'admin@campusshield.edu'}
              </div>
            </div>
          </div>
          <div style={{ 
            backgroundColor: 'var(--color-warning-bg)', 
            color: 'var(--color-warning-fg)', 
            padding: '4px 12px', 
            borderRadius: '6px', 
            fontSize: '12px', 
            fontWeight: '500' 
          }}>
            {currentUser?.role === 'admin' ? 'Admin' : (currentUser?.role || 'Admin')}
          </div>
        </div>
        <div>
          <button 
            onClick={logout} 
            className="ds-flex-row ds-items-center" 
            style={{ 
              gap: '8px', 
              backgroundColor: '#ffffff', 
              border: '1px solid rgba(0,0,0,0.08)', 
              borderRadius: '8px', 
              padding: '10px 16px', 
              fontSize: '13px', 
              fontWeight: '500', 
              color: 'var(--color-text-primary)', 
              cursor: 'pointer' 
            }}
          >
            <LogOut size={16} style={{ color: 'var(--color-text-muted)' }} />
            Sign out
          </button>
        </div>
      </div>

      {/* System Status Card */}
      <div 
        className="ds-flex-col" 
        style={{ 
          backgroundColor: '#ffffff', 
          border: '1px solid rgba(0,0,0,0.06)', 
          borderRadius: '12px', 
          padding: '24px', 
          boxShadow: '0 1px 2px rgba(0,0,0,0.02)' 
        }}
      >
        <div style={{ fontSize: '12px', fontWeight: '500', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '16px' }}>
          SYSTEM STATUS
        </div>
        <div className="ds-flex-col">
          <div className="ds-flex-row ds-items-center ds-justify-between" style={{ padding: '12px 0', borderBottom: '1px solid rgba(0,0,0,0.06)' }}>
            <div style={{ fontSize: '14px', color: 'var(--color-text-primary)' }}>WebSocket connection</div>
            <div className="ds-flex-row ds-items-center" style={{ gap: '6px', fontSize: '13px', color: wsConnected ? 'var(--color-success-fg)' : 'var(--color-danger)' }}>
              <span style={{ fontSize: '8px' }}>●</span> {wsConnected ? 'Connected' : 'Disconnected'}
            </div>
          </div>
          <div className="ds-flex-row ds-items-center ds-justify-between" style={{ padding: '12px 0', borderBottom: '1px solid rgba(0,0,0,0.06)' }}>
            <div style={{ fontSize: '14px', color: 'var(--color-text-primary)' }}>Backend API</div>
            <div className="ds-flex-row ds-items-center" style={{ gap: '6px', fontSize: '13px', color: 'var(--color-success-fg)' }}>
              <span style={{ fontSize: '8px' }}>●</span> Online
            </div>
          </div>
          <div className="ds-flex-row ds-items-center ds-justify-between" style={{ padding: '12px 0' }}>
            <div style={{ fontSize: '14px', color: 'var(--color-text-primary)' }}>Version</div>
            <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>2.0.0</div>
          </div>
        </div>
      </div>

    </div>
  );
}
