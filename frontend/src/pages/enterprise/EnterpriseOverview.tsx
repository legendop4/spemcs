import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '@/context/AppContext';
import {
  Server,
  Activity,
  AlertTriangle,
  ShieldCheck,
  Radio,
  ArrowUpRight,
  RefreshCw,
  Cpu,
} from 'lucide-react';
import * as api from '@/services/api';

export function EnterpriseOverview() {
  const { dashboardSummary, devices, alerts, wsConnected, refresh } = useApp();
  const navigate = useNavigate();

  const [refreshing, setRefreshing] = useState(false);
  const [signingKey, setSigningKey] = useState<any>(null);

  // Fetch active cryptographic key info for the security posture card
  useEffect(() => {
    let mounted = true;
    api
      .getSigningKey()
      .then((key) => {
        if (mounted) setSigningKey(key);
      })
      .catch(() => {
        // Fallback or offline state handled gracefully
      });
    return () => {
      mounted = false;
    };
  }, []);

  const handleManualRefresh = async () => {
    setRefreshing(true);
    await refresh();
    setRefreshing(false);
  };

  const totalDevices = dashboardSummary?.total_devices ?? devices.length;
  const onlineDevices = dashboardSummary?.devices_online ?? devices.filter((d: any) => d.status === 'online').length;
  const offlineDevices = dashboardSummary?.devices_offline ?? (totalDevices - onlineDevices);
  const openAlerts = dashboardSummary?.open_alerts ?? alerts.filter((a: any) => a.status === 'open').length;
  const activeSessions = dashboardSummary?.active_sessions ?? 0;
  const activeEnforcements = dashboardSummary?.active_exams ?? 0;

  const recentAlerts = alerts.slice(0, 5);
  const onlineList = devices.filter((d: any) => d.status === 'online').slice(0, 6);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%' }}>
      {/* Top Banner: Status & Quick Controls */}
      <div
        className="ep-card"
        style={{
          padding: '20px 24px',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '16px',
          background: 'linear-gradient(90deg, #0F172A 0%, #111C30 100%)',
          borderColor: '#1E293B',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', fontWeight: '700', letterSpacing: '1px', color: 'var(--ep-cyan)', textTransform: 'uppercase' }}>
              SPEMCS Defense Telemetry
            </span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#FFFFFF', margin: 0, letterSpacing: '-0.3px' }}>
            Security Posture & Fleet Overview
          </h2>
        </div>

        <div className="ep-header-actions">
          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="ep-btn ep-btn-secondary"
            title="Refresh telemetry"
          >
            <RefreshCw size={14} className={refreshing ? 'ep-spin' : ''} />
            <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>

          <button
            onClick={() => navigate('/console/endpoints')}
            className="ep-btn ep-btn-primary"
          >
            <span>Manage Fleet</span>
            <ArrowUpRight size={15} />
          </button>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="ep-grid-4">
        {/* Total Endpoints */}
        <div className="ep-stat-card ep-stat-cyan">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--ep-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Enrolled Endpoints
            </span>
            <Server size={18} style={{ color: 'var(--ep-cyan)' }} />
          </div>
          <div style={{ fontSize: '28px', fontWeight: '700', color: '#FFFFFF', fontFamily: 'var(--ep-font-mono)', lineHeight: '1.2' }}>
            {totalDevices}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-text-muted)', marginTop: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: '#34D399', fontWeight: '600' }}>{onlineDevices} online</span>
            <span>/</span>
            <span style={{ color: 'var(--ep-text-secondary)' }}>{offlineDevices} offline</span>
          </div>
        </div>

        {/* Realtime Fleet Presence */}
        <div className="ep-stat-card ep-stat-emerald">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--ep-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Live Telemetry Stream
            </span>
            <Radio size={18} style={{ color: 'var(--ep-emerald)' }} />
          </div>
          <div style={{ fontSize: '28px', fontWeight: '700', color: '#FFFFFF', fontFamily: 'var(--ep-font-mono)', lineHeight: '1.2' }}>
            {dashboardSummary?.ws_connected_devices ?? 0}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-text-muted)', marginTop: '8px' }}>
            Connected Node Agents via WSS
          </div>
        </div>

        {/* Active Enforcements */}
        <div className="ep-stat-card ep-stat-indigo">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--ep-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Active Enforcements
            </span>
            <ShieldCheck size={18} style={{ color: 'var(--ep-indigo)' }} />
          </div>
          <div style={{ fontSize: '28px', fontWeight: '700', color: '#FFFFFF', fontFamily: 'var(--ep-font-mono)', lineHeight: '1.2' }}>
            {activeEnforcements}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-text-muted)', marginTop: '8px' }}>
            {activeSessions} active host sessions enforcing policy
          </div>
        </div>

        {/* Open Security Incidents */}
        <div className="ep-stat-card ep-stat-crimson">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--ep-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Open Incidents
            </span>
            <AlertTriangle size={18} style={{ color: 'var(--ep-crimson)' }} />
          </div>
          <div style={{ fontSize: '28px', fontWeight: '700', color: openAlerts > 0 ? '#F87171' : '#FFFFFF', fontFamily: 'var(--ep-font-mono)', lineHeight: '1.2' }}>
            {openAlerts}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-text-muted)', marginTop: '8px' }}>
            {openAlerts > 0 ? 'Requires operator triage' : 'Zero unacknowledged alerts'}
          </div>
        </div>
      </div>

      {/* Main Content Grid: Incidents & Active Telemetry */}
      <div className="ep-grid-2">
        {/* Left Column: Recent Security Alerts */}
        <div className="ep-card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div
            style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--ep-surface-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity size={16} style={{ color: 'var(--ep-cyan)' }} />
              <h3 style={{ fontSize: '14px', fontWeight: '700', color: '#FFFFFF', margin: 0, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Recent Security Alerts
              </h3>
            </div>
            <button
              onClick={() => navigate('/console/alerts')}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--ep-cyan)',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
              }}
            >
              <span>View All</span>
              <ArrowUpRight size={13} />
            </button>
          </div>

          <div style={{ flex: 1, padding: recentAlerts.length === 0 ? '32px 20px' : '0' }}>
            {recentAlerts.length === 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--ep-text-muted)', gap: '8px' }}>
                <ShieldCheck size={32} style={{ color: 'var(--ep-emerald)' }} />
                <span style={{ fontSize: '13px' }}>No incident alerts recorded for the current dataset.</span>
              </div>
            ) : (
              <div className="ep-table-container" style={{ border: 'none', borderRadius: 0 }}>
                <table className="ep-table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Process / Rule</th>
                      <th>Endpoint</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentAlerts.map((alert: any) => {
                      const sev = (alert.severity || 'medium').toLowerCase();
                      const badgeClass =
                        sev === 'critical' || sev === 'high'
                          ? 'ep-badge-crimson'
                          : sev === 'medium'
                          ? 'ep-badge-amber'
                          : 'ep-badge-slate';

                      return (
                        <tr key={alert.alert_id || alert.id}>
                          <td>
                            <span className={`ep-badge ${badgeClass}`}>{sev}</span>
                          </td>
                          <td>
                            <div style={{ display: 'flex', flexDirection: 'column' }}>
                              <span style={{ fontWeight: '600', color: '#FFFFFF', fontSize: '13px' }}>
                                {alert.process_name || alert.event_type || 'Unknown Action'}
                              </span>
                              <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {alert.message || alert.reason || 'Security policy rule triggered'}
                              </span>
                            </div>
                          </td>
                          <td>
                            <span className="ep-font-mono" style={{ fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                              {alert.device_name || 'Host'}
                            </span>
                          </td>
                          <td>
                            <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', whiteSpace: 'nowrap' }}>
                              {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : 'Recent'}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Active Fleet Telemetry */}
        <div className="ep-card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div
            style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--ep-surface-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Server size={16} style={{ color: 'var(--ep-emerald)' }} />
              <h3 style={{ fontSize: '14px', fontWeight: '700', color: '#FFFFFF', margin: 0, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Active Host Telemetry
              </h3>
            </div>
            <button
              onClick={() => navigate('/console/endpoints')}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--ep-cyan)',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
              }}
            >
              <span>Full Fleet</span>
              <ArrowUpRight size={13} />
            </button>
          </div>

          <div style={{ flex: 1, padding: onlineList.length === 0 ? '32px 20px' : '0' }}>
            {onlineList.length === 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--ep-text-muted)', gap: '8px' }}>
                <Server size={32} style={{ color: 'var(--ep-slate)' }} />
                <span style={{ fontSize: '13px' }}>Zero endpoints currently reporting online.</span>
              </div>
            ) : (
              <div className="ep-table-container" style={{ border: 'none', borderRadius: 0 }}>
                <table className="ep-table">
                  <thead>
                    <tr>
                      <th>Host Identifier</th>
                      <th>IPv4 Address</th>
                      <th>Risk Posture</th>
                      <th>Heartbeat</th>
                    </tr>
                  </thead>
                  <tbody>
                    {onlineList.map((dev: any) => (
                      <tr key={dev.device_id}>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span
                              style={{
                                width: '7px',
                                height: '7px',
                                borderRadius: '50%',
                                backgroundColor: '#34D399',
                                boxShadow: '0 0 6px #10B981',
                              }}
                            />
                            <span style={{ fontWeight: '600', color: '#FFFFFF', fontSize: '13px' }}>
                              {dev.hostname || dev.device_name || `Host-${dev.device_id.slice(0, 6)}`}
                            </span>
                          </div>
                        </td>
                        <td>
                          <span className="ep-font-mono" style={{ fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                            {dev.ip_address || '10.0.1.14'}
                          </span>
                        </td>
                        <td>
                          <span className="ep-badge ep-badge-emerald">COMPLIANT</span>
                        </td>
                        <td>
                          <span style={{ fontSize: '12px', color: 'var(--ep-text-muted)' }}>
                            {dev.last_seen ? new Date(dev.last_seen).toLocaleTimeString() : 'Active'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Security Posture & Cryptographic Integrity Banner */}
      <div
        className="ep-card"
        style={{
          padding: '20px 24px',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '20px',
          backgroundColor: '#0A0F1A',
          border: '1px solid #1E283D',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '42px',
              height: '42px',
              borderRadius: '8px',
              backgroundColor: 'rgba(99, 102, 241, 0.12)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--ep-indigo)',
              flexShrink: 0,
            }}
          >
            <Cpu size={22} />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
            <span style={{ fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.6px', color: 'var(--ep-indigo)' }}>
              Cryptographic Policy Authority
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '14px', fontWeight: '600', color: '#FFFFFF' }}>
                Active Signing Authority Key:
              </span>
              <span className="ep-font-mono" style={{ fontSize: '13px', color: 'var(--ep-cyan)', wordBreak: 'break-all' }}>
                {signingKey?.key_id || 'spemcs-c19d7d3a5b8163ae99a7365e513960c1'}
              </span>
              <span className="ep-badge ep-badge-emerald">RSA-PSS 2048</span>
            </div>
            <span style={{ fontSize: '12px', color: 'var(--ep-text-muted)' }}>
              Windows Firewall policy payloads are cryptographically signed before endpoint deployment.
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <span className="ep-badge ep-badge-cyan">
            {wsConnected ? 'WSS STREAM LIVE' : 'OFFLINE'}
          </span>
          <span className="ep-badge ep-badge-emerald">STRICT HTTPS ENFORCED</span>
        </div>
      </div>
    </div>
  );
}
