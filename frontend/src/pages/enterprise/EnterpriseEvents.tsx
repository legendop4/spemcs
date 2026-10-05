import React, { useState, useEffect, useMemo } from 'react';
import {
  Activity,
  Search,
  RefreshCw,
  Eye,
  X,
  FileCode,
} from 'lucide-react';
import * as api from '@/services/api';

interface EventItem {
  event_id: string;
  session_id?: string | null;
  device_id: string;
  device_name: string;
  ip_address?: string | null;
  event_type: string;
  timestamp: string;
  process_name?: string | null;
  pid?: number | null;
  executable_path?: string | null;
  classification: string;
  reason?: string | null;
  resolution_status?: string | null;
}

export function EnterpriseEvents() {
  const [events, setEvents] = useState<EventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [classFilter, setClassFilter] = useState<'all' | 'unauthorized' | 'essential_protected' | 'allowed'>('all');
  const [selectedEvent, setSelectedEvent] = useState<EventItem | null>(null);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const data = await api.getEvents();
      setEvents(data || []);
    } catch (err) {
      console.error('Failed to load events:', err);
      setEvents([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, []);

  const filtered = useMemo(() => {
    return events.filter((ev: EventItem) => {
      const q = search.toLowerCase().trim();
      const matchSearch =
        !q ||
        (ev.process_name || '').toLowerCase().includes(q) ||
        (ev.executable_path || '').toLowerCase().includes(q) ||
        (ev.device_name || '').toLowerCase().includes(q) ||
        (ev.event_type || '').toLowerCase().includes(q) ||
        (ev.reason || '').toLowerCase().includes(q);

      const matchClass =
        classFilter === 'all' ||
        (ev.classification || '').toLowerCase() === classFilter;

      return matchSearch && matchClass;
    });
  }, [events, search, classFilter]);

  const unauthorizedCount = events.filter((e) => (e.classification || '').toLowerCase() === 'unauthorized').length;
  const protectedCount = events.filter((e) => (e.classification || '').toLowerCase() === 'essential_protected').length;
  const allowedCount = events.filter((e) => (e.classification || '').toLowerCase() === 'allowed').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
      {/* Modern Page Header */}
      <div className="ep-page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-cyan)', textTransform: 'uppercase', letterSpacing: '1px' }}>
              SECURITY OPERATIONS // TELEMETRY AUDIT STREAM
            </span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#FFFFFF', margin: 0, letterSpacing: '-0.3px' }}>
            Security Events
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', margin: '4px 0 0 0' }}>
            {events.length} security events recorded ({unauthorizedCount} unauthorized, {protectedCount} protected, {allowedCount} allowed)
          </p>
        </div>

        <div className="ep-header-actions">
          <button
            onClick={fetchEvents}
            disabled={loading}
            className="ep-btn ep-btn-secondary"
            title="Refresh event stream"
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
            placeholder="Search process, path, host..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Classification Filters */}
        <div
          style={{
            display: 'flex',
            backgroundColor: '#0A0F1A',
            border: '1px solid var(--ep-surface-border)',
            borderRadius: '6px',
            padding: '2px',
            flexWrap: 'wrap',
          }}
        >
          {(['all', 'unauthorized', 'essential_protected', 'allowed'] as const).map((type) => {
            const label =
              type === 'all'
                ? 'All'
                : type === 'unauthorized'
                ? 'Unauthorized'
                : type === 'essential_protected'
                ? 'Protected'
                : 'Allowed';

            return (
              <button
                key={type}
                onClick={() => setClassFilter(type)}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontWeight: '600',
                  border: 'none',
                  cursor: 'pointer',
                  backgroundColor: classFilter === type ? 'var(--ep-surface-subtle)' : 'transparent',
                  color: classFilter === type ? '#FFFFFF' : 'var(--ep-text-muted)',
                  transition: 'all 0.15s ease',
                }}
              >
                {label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Table */}
      <div className="ep-table-container">
        {loading ? (
          <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--ep-text-muted)' }}>
            <RefreshCw size={24} className="ep-spin" style={{ margin: '0 auto 12px auto', color: 'var(--ep-cyan)' }} />
            <span>Loading telemetry stream...</span>
          </div>
        ) : filtered.length === 0 ? (
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
            <Activity size={36} style={{ color: 'var(--ep-slate)' }} />
            <span style={{ fontSize: '14px', fontWeight: '500' }}>
              No security telemetry events match the selected filters.
            </span>
          </div>
        ) : (
          <table className="ep-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Classification</th>
                <th>Process / Action</th>
                <th>PID</th>
                <th>Host</th>
                <th>Reason / Observation</th>
                <th style={{ textAlign: 'right' }}>Details</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((ev: EventItem) => {
                const cls = (ev.classification || '').toLowerCase();
                const badgeClass =
                  cls === 'unauthorized'
                    ? 'ep-badge-crimson'
                    : cls === 'essential_protected'
                    ? 'ep-badge-amber'
                    : 'ep-badge-emerald';

                return (
                  <tr
                    key={ev.event_id}
                    onClick={() => setSelectedEvent(ev)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column' }}>
                        <span style={{ fontSize: '12px', color: '#FFFFFF', whiteSpace: 'nowrap' }}>
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </span>
                        <span style={{ fontSize: '10px', color: 'var(--ep-text-dim)', whiteSpace: 'nowrap' }}>
                          {new Date(ev.timestamp).toLocaleDateString()}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className={`ep-badge ${badgeClass}`}>
                        {cls.replace('_', ' ')}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column' }}>
                        <span style={{ fontWeight: '600', color: '#FFFFFF', fontSize: '13px' }}>
                          {ev.process_name || ev.event_type}
                        </span>
                        {ev.executable_path && (
                          <span
                            className="ep-font-mono"
                            style={{
                              fontSize: '11px',
                              color: 'var(--ep-text-dim)',
                              maxWidth: '260px',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {ev.executable_path}
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className="ep-font-mono" style={{ fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                        {ev.pid ?? '—'}
                      </span>
                    </td>
                    <td>
                      <span className="ep-font-mono" style={{ fontSize: '12px', color: 'var(--ep-cyan)' }}>
                        {ev.device_name || ev.device_id.slice(0, 8)}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          fontSize: '12px',
                          color: 'var(--ep-text-secondary)',
                          maxWidth: '300px',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          display: '-webkit-box',
                          WebkitLineClamp: 2,
                          WebkitBoxOrient: 'vertical',
                        }}
                      >
                        {ev.reason || 'Event policy evaluation completed'}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(ev);
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

      {/* Event Details Drawer */}
      {selectedEvent && (
        <div className="ep-drawer-backdrop" onClick={() => setSelectedEvent(null)}>
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
                <Activity size={20} style={{ color: 'var(--ep-cyan)' }} />
                <div>
                  <h3 style={{ fontSize: '16px', fontWeight: '700', color: '#FFFFFF', margin: 0 }}>
                    Event Telemetry Detail
                  </h3>
                  <span style={{ fontSize: '11px', color: 'var(--ep-text-secondary)', fontFamily: 'var(--ep-font-mono)' }}>
                    ID: {selectedEvent.event_id}
                  </span>
                </div>
              </div>

              <button
                onClick={() => setSelectedEvent(null)}
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
              <div className="ep-card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '12px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--ep-cyan)' }}>
                    Classification & Action
                  </span>
                  <span
                    className={`ep-badge ${
                      selectedEvent.classification === 'unauthorized'
                        ? 'ep-badge-crimson'
                        : selectedEvent.classification === 'essential_protected'
                        ? 'ep-badge-amber'
                        : 'ep-badge-emerald'
                    }`}
                  >
                    {selectedEvent.classification.toUpperCase()}
                  </span>
                </div>

                <div style={{ fontSize: '15px', fontWeight: '600', color: '#FFFFFF' }}>
                  {selectedEvent.process_name || selectedEvent.event_type}
                </div>

                {selectedEvent.reason && (
                  <div style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', lineHeight: '1.4' }}>
                    {selectedEvent.reason}
                  </div>
                )}
              </div>

              {/* Execution Context */}
              <div className="ep-card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ fontSize: '12px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--ep-indigo)' }}>
                  Process Execution Context
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px' }}>
                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', display: 'block' }}>Process ID (PID)</span>
                    <span className="ep-font-mono" style={{ fontSize: '13px', color: '#FFFFFF' }}>
                      {selectedEvent.pid ?? 'N/A'}
                    </span>
                  </div>

                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', display: 'block' }}>Timestamp</span>
                    <span style={{ fontSize: '13px', color: '#FFFFFF' }}>
                      {new Date(selectedEvent.timestamp).toLocaleString()}
                    </span>
                  </div>

                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', display: 'block' }}>Endpoint</span>
                    <span style={{ fontSize: '13px', color: '#FFFFFF' }}>
                      {selectedEvent.device_name}
                    </span>
                  </div>

                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', display: 'block' }}>Host IP</span>
                    <span className="ep-font-mono" style={{ fontSize: '13px', color: 'var(--ep-cyan)' }}>
                      {selectedEvent.ip_address || '10.0.1.14'}
                    </span>
                  </div>
                </div>

                {selectedEvent.executable_path && (
                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', display: 'block', marginBottom: '4px' }}>
                      Executable Path
                    </span>
                    <div
                      className="ep-font-mono"
                      style={{
                        fontSize: '11px',
                        color: 'var(--ep-text-secondary)',
                        backgroundColor: 'rgba(0, 0, 0, 0.3)',
                        padding: '8px 12px',
                        borderRadius: '4px',
                        border: '1px solid var(--ep-surface-border)',
                        wordBreak: 'break-all',
                      }}
                    >
                      {selectedEvent.executable_path}
                    </div>
                  </div>
                )}
              </div>

              {/* Policy Session Context */}
              {selectedEvent.session_id && (
                <div className="ep-card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <FileCode size={16} style={{ color: 'var(--ep-emerald)' }} />
                    <span style={{ fontSize: '12px', fontWeight: '700', textTransform: 'uppercase', color: 'var(--ep-emerald)' }}>
                      Active Enforcement Session Context
                    </span>
                  </div>
                  <span className="ep-font-mono" style={{ fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                    Session ID: {selectedEvent.session_id}
                  </span>
                </div>
              )}
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
                onClick={() => setSelectedEvent(null)}
                className="ep-btn ep-btn-secondary"
              >
                Close Details
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
