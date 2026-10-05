import { useState, useEffect, useMemo } from 'react';
import {
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  Terminal,
  ShieldAlert,
  X,
  ExternalLink,
} from 'lucide-react';
import * as api from '@/services/api';
import type { Alert } from '@/types';

export interface IncidentAlert extends Alert {
  violation_type?: string;
  details?: string;
}

export function EnterpriseAlerts() {
  const [alerts, setAlerts] = useState<IncidentAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedAlert, setSelectedAlert] = useState<IncidentAlert | null>(null);

  const fetchAlerts = async () => {
    try {
      setError(null);
      const data = await api.getAlerts();
      setAlerts(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err.message || 'Failed to load incident alerts');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchAlerts();
  };

  const handleUpdateStatus = async (alertId: string, newStatus: 'acknowledged' | 'resolved') => {
    try {
      await api.updateAlert(alertId, { status: newStatus });
      setAlerts((prev) =>
        prev.map((a) => (a.alert_id === alertId ? { ...a, status: newStatus } : a))
      );
      if (selectedAlert && selectedAlert.alert_id === alertId) {
        setSelectedAlert((prev) => (prev ? { ...prev, status: newStatus } : null));
      }
    } catch (err: any) {
      alert(`Failed to update alert: ${err.message}`);
    }
  };

  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      const matchSearch =
        search === '' ||
        (a.process_name || '').toLowerCase().includes(search.toLowerCase()) ||
        (a.device_name || '').toLowerCase().includes(search.toLowerCase()) ||
        (a.violation_type || '').toLowerCase().includes(search.toLowerCase()) ||
        (a.details || '').toLowerCase().includes(search.toLowerCase());

      const matchSeverity =
        severityFilter === 'all' || (a.severity || '').toLowerCase() === severityFilter;

      const matchStatus =
        statusFilter === 'all' || (a.status || '').toLowerCase() === statusFilter;

      return matchSearch && matchSeverity && matchStatus;
    });
  }, [alerts, search, severityFilter, statusFilter]);

  const stats = useMemo(() => {
    const total = alerts.length;
    const critical = alerts.filter((a) => (a.severity || '').toLowerCase() === 'critical').length;
    const open = alerts.filter((a) => (a.status || '').toLowerCase() === 'open').length;
    const resolved = alerts.filter((a) => (a.status || '').toLowerCase() === 'resolved').length;
    return { total, critical, open, resolved };
  }, [alerts]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-cyan)', textTransform: 'uppercase', letterSpacing: '1px' }}>
              Security Operations // Telemetry Triage
            </span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#FFFFFF', margin: 0, letterSpacing: '-0.3px' }}>
            Incident Alerts & Anomaly Stream
          </h2>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="ep-btn ep-btn-secondary"
            title="Refresh alerts"
          >
            <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
            <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {/* KPI Stats Strip */}
      <div className="ep-grid-4">
        <div className="ep-card" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)', textTransform: 'uppercase' }}>
            Total Incidents
          </div>
          <div style={{ fontSize: '24px', fontWeight: '800', fontFamily: 'var(--ep-font-mono)', color: '#FFFFFF', marginTop: '6px' }}>
            {stats.total}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--ep-text-secondary)', marginTop: '4px' }}>
            Recorded across managed fleet
          </div>
        </div>

        <div className="ep-card" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)', textTransform: 'uppercase' }}>
            Critical Severity
          </div>
          <div style={{ fontSize: '24px', fontWeight: '800', fontFamily: 'var(--ep-font-mono)', color: stats.critical > 0 ? 'var(--ep-crimson)' : '#FFFFFF', marginTop: '6px' }}>
            {stats.critical}
          </div>
          <div style={{ fontSize: '11px', color: stats.critical > 0 ? 'var(--ep-crimson)' : 'var(--ep-emerald)', marginTop: '4px' }}>
            {stats.critical > 0 ? 'Requires immediate triage' : 'No critical anomalies'}
          </div>
        </div>

        <div className="ep-card" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)', textTransform: 'uppercase' }}>
            Open / Unacknowledged
          </div>
          <div style={{ fontSize: '24px', fontWeight: '800', fontFamily: 'var(--ep-font-mono)', color: stats.open > 0 ? 'var(--ep-amber)' : 'var(--ep-emerald)', marginTop: '6px' }}>
            {stats.open}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--ep-text-secondary)', marginTop: '4px' }}>
            Awaiting analyst review
          </div>
        </div>

        <div className="ep-card" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)', textTransform: 'uppercase' }}>
            Resolved
          </div>
          <div style={{ fontSize: '24px', fontWeight: '800', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-emerald)', marginTop: '6px' }}>
            {stats.resolved}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--ep-emerald)', marginTop: '4px' }}>
            Closed forensic records
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="ep-toolbar">
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
            placeholder="Search by host, process, or violation..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--ep-text-muted)' }}>
            <Filter size={13} />
            <span>Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={{
                background: 'var(--ep-surface-secondary)',
                border: '1px solid var(--ep-surface-border)',
                color: '#FFFFFF',
                borderRadius: '4px',
                padding: '6px 10px',
                fontSize: '12px',
                outline: 'none',
              }}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--ep-text-muted)' }}>
            <span>Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{
                background: 'var(--ep-surface-secondary)',
                border: '1px solid var(--ep-surface-border)',
                color: '#FFFFFF',
                borderRadius: '4px',
                padding: '6px 10px',
                fontSize: '12px',
                outline: 'none',
              }}
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="ep-table-container">
        {loading ? (
          <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--ep-text-secondary)', fontSize: '13px' }}>
            <RefreshCw size={20} className="ep-spin" style={{ margin: '0 auto 12px auto', display: 'block', color: 'var(--ep-cyan)' }} />
            Streaming incident alerts from control plane...
          </div>
        ) : error ? (
          <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--ep-crimson)', fontSize: '13px' }}>
            {error}
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--ep-text-secondary)', fontSize: '13px' }}>
            <CheckCircle2 size={32} style={{ color: 'var(--ep-emerald)', margin: '0 auto 12px auto', display: 'block' }} />
            <div style={{ color: '#FFFFFF', fontWeight: '600', marginBottom: '4px' }}>No Incident Alerts Found</div>
            <div style={{ color: 'var(--ep-text-muted)', fontSize: '12px' }}>
              No incident alerts recorded for the current dataset.
            </div>
          </div>
        ) : (
          <table className="ep-table">
              <thead>
                <tr>
                  <th>SEVERITY</th>
                  <th>TIMESTAMP</th>
                  <th>ENDPOINT / HOST</th>
                  <th>PROCESS / ARTIFACT</th>
                  <th>VIOLATION TYPE</th>
                  <th>STATUS</th>
                  <th style={{ textAlign: 'right' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((alert) => {
                  const sev = (alert.severity || 'medium').toLowerCase();
                  return (
                    <tr
                      key={alert.alert_id}
                      onClick={() => setSelectedAlert(alert)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <span
                          className={`ep-badge ${
                            sev === 'critical'
                              ? 'ep-badge-crimson'
                              : sev === 'high'
                              ? 'ep-badge-amber'
                              : 'ep-badge-cyan'
                          }`}
                        >
                          {alert.severity || 'UNKNOWN'}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--ep-font-mono)', fontSize: '12px' }}>
                        {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : 'N/A'}
                      </td>
                      <td style={{ fontWeight: '600', color: '#FFFFFF' }}>
                        {alert.device_name || 'Generic Workstation'}
                      </td>
                      <td style={{ fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-cyan)' }}>
                        {alert.process_name || 'N/A'}
                      </td>
                      <td style={{ color: 'var(--ep-text-secondary)', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {alert.violation_type || alert.details || 'Policy deviation'}
                      </td>
                      <td>
                        <span
                          className={`ep-badge ${
                            alert.status === 'resolved'
                              ? 'ep-badge-emerald'
                              : alert.status === 'acknowledged'
                              ? 'ep-badge-cyan'
                              : 'ep-badge-amber'
                          }`}
                        >
                          {alert.status || 'OPEN'}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAlert(alert);
                          }}
                          className="ep-btn ep-btn-secondary"
                          style={{ padding: '3px 8px', fontSize: '11px' }}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
        )}
      </div>

      {/* Forensic Inspector Drawer / Modal */}
      {selectedAlert && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            display: 'flex',
            justifyContent: 'flex-end',
            zIndex: 100,
          }}
          onClick={() => setSelectedAlert(null)}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '560px',
              height: '100%',
              backgroundColor: 'var(--ep-surface-primary)',
              borderLeft: '1px solid var(--ep-surface-border)',
              padding: '24px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              boxShadow: '-8px 0 32px rgba(0,0,0,0.8)',
              overflowY: 'auto',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div>
              {/* Drawer Top */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '16px', borderBottom: '1px solid var(--ep-surface-border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldAlert size={18} style={{ color: 'var(--ep-crimson)' }} />
                  <span style={{ fontSize: '14px', fontWeight: '700', color: '#FFFFFF', textTransform: 'uppercase' }}>
                    Incident Forensic Dossier
                  </span>
                </div>
                <button
                  onClick={() => setSelectedAlert(null)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--ep-text-secondary)', cursor: 'pointer' }}
                >
                  <X size={18} />
                </button>
              </div>

              {/* Inspector Content */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '20px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  <div className="ep-card" style={{ padding: '12px' }}>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)' }}>ALERT ID</div>
                    <div style={{ fontSize: '12px', fontFamily: 'var(--ep-font-mono)', color: '#FFFFFF', marginTop: '4px', wordBreak: 'break-all' }}>
                      {selectedAlert.alert_id}
                    </div>
                  </div>
                  <div className="ep-card" style={{ padding: '12px' }}>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)' }}>SEVERITY LEVEL</div>
                    <div style={{ marginTop: '4px' }}>
                      <span className={`ep-badge ${selectedAlert.severity === 'critical' ? 'ep-badge-crimson' : 'ep-badge-amber'}`}>
                        {selectedAlert.severity}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="ep-card" style={{ padding: '14px' }}>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)', marginBottom: '8px' }}>
                    HOST & PROCESS TELEMETRY
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '12px', fontFamily: 'var(--ep-font-mono)' }}>
                    <div>
                      <span style={{ color: 'var(--ep-text-muted)' }}>Host Name: </span>
                      <span style={{ color: '#FFFFFF' }}>{selectedAlert.device_name || 'N/A'}</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--ep-text-muted)' }}>Device ID: </span>
                      <span style={{ color: 'var(--ep-cyan)' }}>{selectedAlert.device_id?.slice(0, 8)}...</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--ep-text-muted)' }}>Process: </span>
                      <span style={{ color: '#00E5FF' }}>{selectedAlert.process_name || 'N/A'}</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--ep-text-muted)' }}>Timestamp: </span>
                      <span style={{ color: '#FFFFFF' }}>{selectedAlert.created_at ? new Date(selectedAlert.created_at).toUTCString() : 'N/A'}</span>
                    </div>
                  </div>
                </div>

                <div className="ep-card" style={{ padding: '14px' }}>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)', marginBottom: '6px' }}>
                    VIOLATION CLASSIFICATION & DETAILS
                  </div>
                  <div style={{ fontSize: '13px', color: '#FFFFFF', lineHeight: 1.5 }}>
                    {selectedAlert.details || selectedAlert.violation_type || 'Unspecified network or process violation observed.'}
                  </div>
                </div>
              </div>
            </div>

            {/* Action Bar */}
            <div style={{ paddingTop: '20px', borderTop: '1px solid var(--ep-surface-border)', display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              {selectedAlert.status !== 'acknowledged' && (
                <button
                  onClick={() => handleUpdateStatus(selectedAlert.alert_id || selectedAlert.id || '', 'acknowledged')}
                  className="ep-btn ep-btn-secondary"
                >
                  Mark Acknowledged
                </button>
              )}
              {selectedAlert.status !== 'resolved' && (
                <button
                  onClick={() => handleUpdateStatus(selectedAlert.alert_id || selectedAlert.id || '', 'resolved')}
                  className="ep-btn ep-btn-primary"
                >
                  Mark Resolved
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default EnterpriseAlerts;
