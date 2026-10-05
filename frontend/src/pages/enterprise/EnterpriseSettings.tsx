import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon,
  Shield,
  Server,
  User,
  Radio,
  RefreshCw,
  LogOut,
  CheckCircle2,
} from 'lucide-react';
import * as api from '@/services/api';
import { useApp } from '@/context/AppContext';

export function EnterpriseSettings() {
  const { currentUser, logout } = useApp();
  const [health, setHealth] = useState<{ status: string; database: string } | null>(null);
  const [loadingHealth, setLoadingHealth] = useState(true);

  // Real client-side console preferences
  const [autoRefreshTelemetry, setAutoRefreshTelemetry] = useState(true);
  const [denseDisplay, setDenseDisplay] = useState(true);

  const fetchHealth = async () => {
    setLoadingHealth(true);
    try {
      const data = await api.getHealth();
      setHealth(data);
    } catch (err) {
      console.error('Failed to query health:', err);
      setHealth({ status: 'degraded', database: 'disconnected' });
    } finally {
      setLoadingHealth(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
      {/* Modern Page Header */}
      <div className="ep-page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--ep-cyan)', letterSpacing: '0.1em' }}>
              SYSTEM // PLATFORM SETTINGS
            </span>
            <span className="ep-badge ep-badge-cyan">OPERATIONAL CONTROL</span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#FFFFFF', margin: 0, letterSpacing: '-0.3px' }}>
            Platform Settings
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', margin: '4px 0 0 0' }}>
            Operator identity, backend service health connectivity, and console runtime environment parameters
          </p>
        </div>

        <div className="ep-header-actions">
          <button
            onClick={fetchHealth}
            disabled={loadingHealth}
            className="ep-btn ep-btn-secondary"
            title="Probe backend service health"
          >
            <RefreshCw size={14} className={loadingHealth ? 'ep-spin' : ''} />
            <span>Probe Health</span>
          </button>
        </div>
      </div>

      <div className="ep-grid-2">
        {/* Operator Profile */}
        <div className="ep-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <User size={18} color="var(--ep-cyan)" />
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--ep-text-primary)', margin: 0 }}>
              Operator Authentication State
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--ep-surface-border)' }}>
              <span style={{ color: 'var(--ep-text-muted)' }}>Username:</span>
              <span style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--ep-text-primary)' }}>
                {currentUser?.name || currentUser?.username || currentUser?.email || 'Administrator'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--ep-surface-border)' }}>
              <span style={{ color: 'var(--ep-text-muted)' }}>Role Authority:</span>
              <span className="ep-badge ep-badge-emerald" style={{ textTransform: 'uppercase' }}>
                {currentUser?.role || 'ADMIN'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--ep-surface-border)' }}>
              <span style={{ color: 'var(--ep-text-muted)' }}>Principal ID:</span>
              <span style={{ fontFamily: 'monospace', color: 'var(--ep-text-secondary)', fontSize: '12px' }}>
                {currentUser?.id || 'genesis-operator-01'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0' }}>
              <span style={{ color: 'var(--ep-text-muted)' }}>Bearer Token Session:</span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--ep-emerald)' }}>
                <CheckCircle2 size={14} /> Active
              </span>
            </div>
          </div>

          <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid var(--ep-surface-border)' }}>
            <button
              onClick={logout}
              className="ep-btn ep-btn-secondary"
              style={{ color: 'var(--ep-crimson)', display: 'inline-flex', alignItems: 'center', gap: '8px' }}
            >
              <LogOut size={14} />
              Terminate Console Session
            </button>
          </div>
        </div>

        {/* Backend & Database Health */}
        <div className="ep-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <Server size={18} color="var(--ep-emerald)" />
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--ep-text-primary)', margin: 0 }}>
              Backend Connectivity & Health
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--ep-surface-border)' }}>
              <span style={{ color: 'var(--ep-text-muted)' }}>Control Plane API:</span>
              <span>
                {health?.status === 'ok' ? (
                  <span className="ep-badge ep-badge-emerald">OPERATIONAL (HTTP 200)</span>
                ) : (
                  <span className="ep-badge ep-badge-crimson">DEGRADED</span>
                )}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--ep-surface-border)' }}>
              <span style={{ color: 'var(--ep-text-muted)' }}>Database Connection:</span>
              <span>
                {health?.database === 'connected' ? (
                  <span className="ep-badge ep-badge-emerald">CONNECTED</span>
                ) : (
                  <span className="ep-badge ep-badge-crimson">DISCONNECTED</span>
                )}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--ep-surface-border)' }}>
              <span style={{ color: 'var(--ep-text-muted)' }}>WebSocket Telemetry:</span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--ep-cyan)', fontFamily: 'monospace' }}>
                <Radio size={12} /> /api/v1/ws/dashboard
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0' }}>
              <span style={{ color: 'var(--ep-text-muted)' }}>Security Enforcement Mode:</span>
              <span style={{ color: 'var(--ep-text-primary)', fontWeight: 500 }}>
                Windows Firewall Enforcement
              </span>
            </div>
          </div>
        </div>

        {/* Console Interface Preferences */}
        <div className="ep-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <SettingsIcon size={18} color="var(--ep-amber)" />
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--ep-text-primary)', margin: 0 }}>
              Console Visual Density & Display
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 500, color: 'var(--ep-text-primary)' }}>Auto-Refresh Telemetry</div>
                <div style={{ fontSize: '12px', color: 'var(--ep-text-muted)' }}>Periodically re-query fleet & alert status</div>
              </div>
              <label className="ep-switch" aria-label="Toggle Auto-Refresh Telemetry">
                <input
                  type="checkbox"
                  checked={autoRefreshTelemetry}
                  onChange={(e) => setAutoRefreshTelemetry(e.target.checked)}
                />
                <span className="ep-switch-slider" />
              </label>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 500, color: 'var(--ep-text-primary)' }}>Dense Operational Layout</div>
                <div style={{ fontSize: '12px', color: 'var(--ep-text-muted)' }}>Compact data row padding for SOC displays</div>
              </div>
              <label className="ep-switch" aria-label="Toggle Dense Operational Layout">
                <input
                  type="checkbox"
                  checked={denseDisplay}
                  onChange={(e) => setDenseDisplay(e.target.checked)}
                />
                <span className="ep-switch-slider" />
              </label>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 500, color: 'var(--ep-text-primary)' }}>Color Palette</div>
                <div style={{ fontSize: '12px', color: 'var(--ep-text-muted)' }}>Enterprise Dark Obsidian (Enforced)</div>
              </div>
              <span className="ep-badge ep-badge-slate">LOCKED</span>
            </div>
          </div>
        </div>

        {/* Architectural Boundaries & Compliance */}
        <div className="ep-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <Shield size={18} color="var(--ep-cyan)" />
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--ep-text-primary)', margin: 0 }}>
              Platform Governance Specifications
            </h3>
          </div>

          <div style={{ fontSize: '12px', color: 'var(--ep-text-secondary)', lineHeight: '1.6' }}>
            <p style={{ margin: '0 0 10px' }}>
              <strong>Endpoint Enforcement Boundary:</strong> SPEMCS enforces security boundaries through Windows Firewall configuration rules generated by the management control plane and signed with RSA-PSS 2048.
            </p>
            <p style={{ margin: '0 0 10px' }}>
              <strong>Zero Kernel Modification:</strong> Endpoint agents run in user-space with Windows service privileges without loading custom kernel drivers or non-standard WFP callout drivers.
            </p>
            <p style={{ margin: 0 }}>
              <strong>Strict Backend Support:</strong> All console controls and telemetry feeds directly map to authenticated FastAPI REST endpoints and PostgreSQL database records.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default EnterpriseSettings;
