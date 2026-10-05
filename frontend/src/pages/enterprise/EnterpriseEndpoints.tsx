import React, { useState, useMemo } from 'react';
import { useApp } from '@/context/AppContext';
import {
  Server,
  Search,
  RefreshCw,
  Eye,
  X,
  Shield,
} from 'lucide-react';
import * as api from '@/services/api';

interface DeviceItem {
  device_id: string;
  device_name: string;
  hardware_uuid: string | null;
  building_name?: string | null;
  lab_name?: string | null;
  pc_number?: string | null;
  registered_ip: string | null;
  status: string;
  last_seen: string | null;
  created_at?: string;
  risk_score?: number;
  risk_level?: string;
}

export function EnterpriseEndpoints() {
  const { devices, refresh } = useApp();

  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'online' | 'offline'>('all');

  // Selected endpoint for Inspector Drawer
  const [selectedDevice, setSelectedDevice] = useState<DeviceItem | null>(null);
  const [deviceStatusDetail, setDeviceStatusDetail] = useState<any | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const handleInspect = async (dev: DeviceItem) => {
    setSelectedDevice(dev);
    setLoadingDetail(true);
    try {
      const detail = await api.getDeviceStatus(dev.device_id);
      setDeviceStatusDetail(detail);
    } catch (err) {
      console.error('Failed to load device status detail:', err);
      setDeviceStatusDetail(null);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleManualRefresh = async () => {
    setLoading(true);
    await refresh();
    setLoading(false);
  };

  const filtered = useMemo(() => {
    return devices.filter((d: DeviceItem) => {
      const q = search.toLowerCase().trim();
      const matchSearch =
        !q ||
        (d.device_name || '').toLowerCase().includes(q) ||
        (d.registered_ip || '').toLowerCase().includes(q) ||
        (d.hardware_uuid || '').toLowerCase().includes(q);

      const matchFilter =
        filter === 'all' ||
        (filter === 'online' && d.status === 'online') ||
        (filter === 'offline' && d.status !== 'online');

      return matchSearch && matchFilter;
    });
  }, [devices, search, filter]);

  const onlineCount = devices.filter((d: any) => d.status === 'online').length;
  const offlineCount = devices.length - onlineCount;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
      {/* Modern Page Header */}
      <div className="ep-page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-cyan)', textTransform: 'uppercase', letterSpacing: '1px' }}>
              SECURITY OPERATIONS // FLEET INVENTORY
            </span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#FFFFFF', margin: 0, letterSpacing: '-0.3px' }}>
            Fleet Endpoints
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', margin: '4px 0 0 0' }}>
            {devices.length} registered host{devices.length === 1 ? '' : 's'} ({onlineCount} online, {offlineCount} offline)
          </p>
        </div>

        <div className="ep-header-actions">
          <button
            onClick={handleManualRefresh}
            disabled={loading}
            className="ep-btn ep-btn-secondary"
            title="Refresh fleet inventory"
          >
            <RefreshCw size={14} className={loading ? 'ep-spin' : ''} />
            <span>{loading ? 'Refreshing...' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {/* Toolbar: Search and Filter */}
      <div className="ep-toolbar">
        {/* Search Box */}
        <div style={{ position: 'relative', flex: '1', minWidth: '220px' }}>
          <Search
            size={14}
            style={{
              position: 'absolute',
              left: '12px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--ep-text-dim)',
            }}
          />
          <input
            type="text"
            className="ep-input"
            style={{ paddingLeft: '34px', width: '100%', boxSizing: 'border-box' }}
            placeholder="Search hostname, IP, UUID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Filter Pills */}
        <div
          style={{
            display: 'flex',
            backgroundColor: '#0A0F1A',
            border: '1px solid var(--ep-surface-border)',
            borderRadius: '6px',
            padding: '2px',
          }}
        >
          {(['all', 'online', 'offline'] as const).map((type) => (
            <button
              key={type}
              onClick={() => setFilter(type)}
              style={{
                padding: '6px 14px',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: '600',
                border: 'none',
                cursor: 'pointer',
                backgroundColor: filter === type ? 'var(--ep-surface-subtle)' : 'transparent',
                color: filter === type ? '#FFFFFF' : 'var(--ep-text-muted)',
                textTransform: 'capitalize',
                transition: 'all 0.15s ease',
              }}
            >
              {type}
            </button>
          ))}
        </div>
      </div>

      {/* Main Table */}
      <div className="ep-table-container">
        {filtered.length === 0 ? (
          <div
            style={{
              padding: '60px 20px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '12px',
              color: 'var(--ep-text-muted)',
            }}
          >
            <Server size={36} style={{ color: 'var(--ep-slate)' }} />
            <span style={{ fontSize: '14px', fontWeight: '500' }}>
              No endpoints found matching your criteria.
            </span>
          </div>
        ) : (
          <table className="ep-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Hostname</th>
                <th>Hardware UUID</th>
                <th>IPv4 Address</th>
                <th>Risk Posture</th>
                <th>Last Seen</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((d: DeviceItem) => {
                const isOnline = d.status === 'online';
                const riskScore = d.risk_score ?? 0;
                const riskClass =
                  riskScore > 50
                    ? 'ep-badge-crimson'
                    : riskScore > 20
                    ? 'ep-badge-amber'
                    : 'ep-badge-emerald';

                return (
                  <tr
                    key={d.device_id}
                    onClick={() => handleInspect(d)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <span
                        className={`ep-badge ${isOnline ? 'ep-badge-emerald' : 'ep-badge-slate'}`}
                      >
                        <span
                          style={{
                            width: '6px',
                            height: '6px',
                            borderRadius: '50%',
                            backgroundColor: isOnline ? '#34D399' : '#64748B',
                          }}
                        />
                        {d.status || 'unknown'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column' }}>
                        <span style={{ fontWeight: '600', color: '#FFFFFF' }}>
                          {d.device_name}
                        </span>
                        {d.pc_number && (
                          <span style={{ fontSize: '11px', color: 'var(--ep-text-dim)' }}>
                            Node: {d.pc_number}
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      <span
                        className="ep-font-mono"
                        style={{
                          fontSize: '11px',
                          color: 'var(--ep-text-secondary)',
                          backgroundColor: 'rgba(255, 255, 255, 0.03)',
                          padding: '2px 6px',
                          borderRadius: '4px',
                          border: '1px solid var(--ep-surface-border-subtle)',
                        }}
                      >
                        {d.hardware_uuid || 'UNREGISTERED_HW'}
                      </span>
                    </td>
                    <td>
                      <span className="ep-font-mono" style={{ fontSize: '12px', color: 'var(--ep-cyan)' }}>
                        {d.registered_ip || '127.0.0.1'}
                      </span>
                    </td>
                    <td>
                      <span className={`ep-badge ${riskClass}`}>
                        {d.risk_level ? d.risk_level.toUpperCase() : `SCORE: ${riskScore}`}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: '12px', color: 'var(--ep-text-muted)', whiteSpace: 'nowrap' }}>
                        {d.last_seen ? new Date(d.last_seen).toLocaleString() : 'Never'}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleInspect(d);
                        }}
                        className="ep-btn ep-btn-secondary"
                        style={{ padding: '4px 10px', fontSize: '11px' }}
                      >
                        <Eye size={13} />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Endpoint Inspector Drawer */}
      {selectedDevice && (
        <div className="ep-drawer-backdrop" onClick={() => setSelectedDevice(null)}>
          <div className="ep-drawer-panel" onClick={(e) => e.stopPropagation()}>
            {/* Drawer Header */}
            <div
              style={{
                padding: '18px 24px',
                borderBottom: '1px solid var(--ep-surface-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Server size={20} style={{ color: 'var(--ep-cyan)' }} />
                <div>
                  <h3 style={{ fontSize: '16px', fontWeight: '700', color: '#FFFFFF', margin: 0 }}>
                    {selectedDevice.device_name}
                  </h3>
                  <span style={{ fontSize: '11px', color: 'var(--ep-text-secondary)', fontFamily: 'var(--ep-font-mono)' }}>
                    {selectedDevice.hardware_uuid || 'Hardware UUID not populated'}
                  </span>
                </div>
              </div>

              <button
                onClick={() => setSelectedDevice(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--ep-text-secondary)',
                  cursor: 'pointer',
                  padding: '6px',
                }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Drawer Body */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Telemetry Status Card */}
              <div className="ep-card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ fontSize: '12px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--ep-cyan)', letterSpacing: '0.6px' }}>
                  Node Telemetry Status
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)' }}>Presence</span>
                    <span
                      style={{
                        fontSize: '13px',
                        fontWeight: '600',
                        color: selectedDevice.status === 'online' ? '#34D399' : '#94A3B8',
                      }}
                    >
                      {selectedDevice.status === 'online' ? 'Active Online' : 'Offline'}
                    </span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)' }}>WebSocket Stream</span>
                    <span style={{ fontSize: '13px', fontWeight: '600', color: deviceStatusDetail?.ws_connected ? '#34D399' : '#94A3B8' }}>
                      {loadingDetail ? 'Probing...' : deviceStatusDetail?.ws_connected ? 'Connected' : 'Disconnected'}
                    </span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)' }}>Registered IPv4</span>
                    <span className="ep-font-mono" style={{ fontSize: '12px', color: '#FFFFFF' }}>
                      {selectedDevice.registered_ip || '127.0.0.1'}
                    </span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)' }}>Last Heartbeat</span>
                    <span style={{ fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                      {selectedDevice.last_seen ? new Date(selectedDevice.last_seen).toLocaleString() : 'Never'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Policy Enforcement State */}
              <div className="ep-card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ fontSize: '12px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--ep-indigo)', letterSpacing: '0.6px' }}>
                  Enforcement Window & Policy
                </div>

                {deviceStatusDetail?.active_exam ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: '13px', fontWeight: '600', color: '#FFFFFF' }}>
                        {deviceStatusDetail.active_exam.exam_name}
                      </span>
                      <span className="ep-badge ep-badge-emerald">STRICT ENFORCEMENT</span>
                    </div>
                    <span style={{ fontSize: '11px', color: 'var(--ep-text-secondary)', fontFamily: 'var(--ep-font-mono)' }}>
                      Session ID: {deviceStatusDetail.active_exam.exam_id}
                    </span>
                  </div>
                ) : (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--ep-text-muted)' }}>
                    <Shield size={16} />
                    <span style={{ fontSize: '13px' }}>
                      No active enforcement session assigned to this host.
                    </span>
                  </div>
                )}
              </div>

              {/* Risk Assessment */}
              <div className="ep-card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ fontSize: '12px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--ep-amber)', letterSpacing: '0.6px' }}>
                  Endpoint Threat Posture
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ fontSize: '24px', fontWeight: '700', color: '#FFFFFF', fontFamily: 'var(--ep-font-mono)' }}>
                    {selectedDevice.risk_score ?? 0}
                  </div>
                  <span
                    className={`ep-badge ${
                      (selectedDevice.risk_score ?? 0) > 50
                        ? 'ep-badge-crimson'
                        : (selectedDevice.risk_score ?? 0) > 20
                        ? 'ep-badge-amber'
                        : 'ep-badge-emerald'
                    }`}
                  >
                    {selectedDevice.risk_level?.toUpperCase() || 'NORMAL'}
                  </span>
                </div>
                <span style={{ fontSize: '12px', color: 'var(--ep-text-muted)' }}>
                  Computed dynamically based on historical unauthorized process violations and network attempts.
                </span>
              </div>
            </div>

            {/* Drawer Footer */}
            <div
              style={{
                padding: '16px 24px',
                borderTop: '1px solid var(--ep-surface-border)',
                display: 'flex',
                justifyContent: 'flex-end',
              }}
            >
              <button
                onClick={() => setSelectedDevice(null)}
                className="ep-btn ep-btn-secondary"
              >
                Close Panel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
