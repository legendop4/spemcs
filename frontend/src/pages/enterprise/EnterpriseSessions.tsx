import React, { useState, useEffect, useMemo } from 'react';
import {
  ShieldAlert,
  Search,
  RefreshCw,
  Play,
  Square,
  Eye,
  X,
  Laptop,
  CheckCircle2,
  AlertTriangle,
  Layers,
} from 'lucide-react';
import * as api from '@/services/api';

interface EnforcementPolicySession {
  id: string;
  examName?: string;
  exam_name?: string;
  examLink?: string;
  exam_link?: string;
  status: string;
  startedAt?: string;
  started_at?: string;
  endedAt?: string;
  ended_at?: string;
  deviceCount?: number;
  device_count?: number;
  alertCount?: number;
  alert_count?: number;
  sessionCount?: number;
  session_count?: number;
}

interface EndpointSessionRecord {
  session_id: string;
  exam_id: string;
  device_id: string;
  student_roll_number: string;
  status: string;
  started_at?: string;
  ended_at?: string;
}

export function EnterpriseSessions() {
  const [sessions, setSessions] = useState<EnforcementPolicySession[]>([]);
  const [endpointSessions, setEndpointSessions] = useState<EndpointSessionRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Search & Filter
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'scheduled' | 'completed'>('all');
  const [viewTab, setViewTab] = useState<'enforcement' | 'endpoint_sessions'>('enforcement');

  // Inspector Drawer for Session Compliance
  const [selectedSession, setSelectedSession] = useState<EnforcementPolicySession | null>(null);
  const [deviceCompliance, setDeviceCompliance] = useState<any[]>([]);
  const [loadingCompliance, setLoadingCompliance] = useState(false);

  // Safe mutation confirmation modal state (replaces window.confirm)
  const [confirmModal, setConfirmModal] = useState<{
    type: 'activate' | 'deactivate';
    session: EnforcementPolicySession;
  } | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [confirmError, setConfirmError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [examsRes, sessionsRes] = await Promise.allSettled([
        api.getExams(),
        api.getSessions(),
      ]);

      if (examsRes.status === 'fulfilled') {
        const rawExams = Array.isArray(examsRes.value) ? examsRes.value : [];
        setSessions(rawExams.map((ex: any) => ({
          id: ex.id || ex.exam_id,
          examName: ex.examName || ex.exam_name || 'Enforcement Session',
          examLink: ex.examLink || ex.exam_link || '',
          status: ex.status || 'unknown',
          startedAt: ex.startedAt || ex.started_at,
          endedAt: ex.endedAt || ex.ended_at,
          deviceCount: ex.deviceCount ?? ex.device_count ?? 0,
          alertCount: ex.alertCount ?? ex.alert_count ?? 0,
          sessionCount: ex.sessionCount ?? ex.session_count ?? 0,
        })));
      } else {
        console.error('Failed to load enforcement sessions:', examsRes.reason);
      }

      if (sessionsRes.status === 'fulfilled') {
        setEndpointSessions(Array.isArray(sessionsRes.value) ? sessionsRes.value : []);
      }
    } catch (err: any) {
      console.error('Error fetching sessions:', err);
      setError(err?.message || 'Failed to retrieve enforcement sessions');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleExecuteAction = async () => {
    if (!confirmModal) return;
    setConfirming(true);
    setConfirmError(null);

    const { type, session } = confirmModal;
    try {
      if (type === 'activate') {
        await api.activateExam(session.id);
      } else {
        await api.deactivateExam(session.id);
      }
      setConfirmModal(null);
      await fetchData();
    } catch (err: any) {
      setConfirmError(err.message || `Failed to ${type} session`);
    } finally {
      setConfirming(false);
    }
  };

  const handleInspect = async (session: EnforcementPolicySession) => {
    setSelectedSession(session);
    setLoadingCompliance(true);
    try {
      const states = await api.getExamDevicePolicyStates(session.id);
      setDeviceCompliance(Array.isArray(states) ? states : []);
    } catch (err) {
      console.error('Failed to load device policy states:', err);
      setDeviceCompliance([]);
    } finally {
      setLoadingCompliance(false);
    }
  };

  // Metrics
  const metrics = useMemo(() => {
    const activeSessions = sessions.filter(s => s.status.toLowerCase() === 'active').length;
    const scheduled = sessions.filter(s => s.status.toLowerCase() === 'pending' || s.status.toLowerCase() === 'scheduled').length;
    const totalEndpoints = sessions.reduce((acc, s) => acc + (s.deviceCount || 0), 0);
    const activeEndpointSessions = endpointSessions.filter(s => s.status?.toLowerCase() === 'active').length;
    return { activeSessions, scheduled, totalEndpoints, activeEndpointSessions };
  }, [sessions, endpointSessions]);

  // Filtered Sessions
  const filteredSessions = useMemo(() => {
    return sessions.filter((s) => {
      const matchSearch =
        s.examName?.toLowerCase().includes(search.toLowerCase()) ||
        s.id.toLowerCase().includes(search.toLowerCase());

      const st = s.status.toLowerCase();
      let matchStatus = true;
      if (statusFilter === 'active') matchStatus = st === 'active';
      else if (statusFilter === 'scheduled') matchStatus = st === 'pending' || st === 'scheduled';
      else if (statusFilter === 'completed') matchStatus = st === 'completed' || st === 'concluded' || st === 'ended';

      return matchSearch && matchStatus;
    });
  }, [sessions, search, statusFilter]);

  // Filtered Endpoint Sessions
  const filteredEndpointSessions = useMemo(() => {
    return endpointSessions.filter((s) => {
      return (
        s.student_roll_number?.toLowerCase().includes(search.toLowerCase()) ||
        s.device_id?.toLowerCase().includes(search.toLowerCase()) ||
        s.session_id?.toLowerCase().includes(search.toLowerCase())
      );
    });
  }, [endpointSessions, search]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
      {/* Modern Page Header */}
      <div className="ep-page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-cyan)', textTransform: 'uppercase', letterSpacing: '1px' }}>
              SECURITY CONTROL // ENFORCEMENT SESSIONS
            </span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#FFFFFF', margin: 0, letterSpacing: '-0.3px' }}>
            Enforcement Sessions
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', margin: '4px 0 0 0' }}>
            Active boundary enforcement orchestration, real-time device policy states, and host session tracking
          </p>
        </div>

        <div className="ep-header-actions">
          <button
            onClick={fetchData}
            disabled={loading}
            className="ep-btn ep-btn-secondary"
            title="Refresh sessions"
          >
            <RefreshCw size={14} className={loading ? 'ep-spin' : ''} />
            <span>{loading ? 'Refreshing...' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="ep-grid-4">
        <div className="ep-stat-card ep-stat-emerald">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Active Sessions
            </span>
            <ShieldAlert size={16} color="var(--ep-emerald)" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--ep-text-primary)' }}>
            {metrics.activeSessions}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-emerald)', marginTop: '4px' }}>
            Strict policy enforced
          </div>
        </div>

        <div className="ep-stat-card ep-stat-amber">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Scheduled / Staged
            </span>
            <Layers size={16} color="var(--ep-amber)" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--ep-text-primary)' }}>
            {metrics.scheduled}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-text-muted)', marginTop: '4px' }}>
            Awaiting execution window
          </div>
        </div>

        <div className="ep-stat-card ep-stat-cyan">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Enrolled Hosts
            </span>
            <Laptop size={16} color="var(--ep-cyan)" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--ep-text-primary)' }}>
            {metrics.totalEndpoints}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-cyan)', marginTop: '4px' }}>
            Bound to active policies
          </div>
        </div>

        <div className="ep-stat-card ep-stat-indigo">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Endpoint Sessions
            </span>
            <CheckCircle2 size={16} color="var(--ep-indigo)" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--ep-text-primary)' }}>
            {metrics.activeEndpointSessions}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-indigo)', marginTop: '4px' }}>
            Active authenticated nodes
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--ep-surface-border)' }}>
        <button
          onClick={() => setViewTab('enforcement')}
          style={{
            padding: '10px 16px',
            fontSize: '13px',
            fontWeight: 600,
            background: 'none',
            border: 'none',
            borderBottom: viewTab === 'enforcement' ? '2px solid var(--ep-cyan)' : '2px solid transparent',
            color: viewTab === 'enforcement' ? 'var(--ep-cyan)' : 'var(--ep-text-secondary)',
            cursor: 'pointer',
          }}
        >
          Enforcement Sessions ({sessions.length})
        </button>
        <button
          onClick={() => setViewTab('endpoint_sessions')}
          style={{
            padding: '10px 16px',
            fontSize: '13px',
            fontWeight: 600,
            background: 'none',
            border: 'none',
            borderBottom: viewTab === 'endpoint_sessions' ? '2px solid var(--ep-cyan)' : '2px solid transparent',
            color: viewTab === 'endpoint_sessions' ? 'var(--ep-cyan)' : 'var(--ep-text-secondary)',
            cursor: 'pointer',
          }}
        >
          Endpoint Sessions ({endpointSessions.length})
        </button>
      </div>

      {/* Toolbar: Filter and Search */}
      <div className="ep-toolbar">
        <div style={{ position: 'relative', flex: 1, minWidth: '220px' }}>
          <Search size={14} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--ep-text-muted)' }} />
          <input
            type="text"
            placeholder={viewTab === 'enforcement' ? 'Filter by session title or UUID...' : 'Filter by endpoint or session ID...'}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="ep-input"
            style={{ width: '100%', paddingLeft: '34px', fontSize: '13px', boxSizing: 'border-box' }}
          />
        </div>

        {viewTab === 'enforcement' && (
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {(['all', 'active', 'scheduled', 'completed'] as const).map((filterKey) => (
              <button
                key={filterKey}
                onClick={() => setStatusFilter(filterKey)}
                className={`ep-btn ${statusFilter === filterKey ? 'ep-btn-primary' : 'ep-btn-secondary'}`}
                style={{ fontSize: '12px', textTransform: 'capitalize', padding: '6px 14px' }}
              >
                {filterKey}
              </button>
            ))}
          </div>
        )}
      </div>

      {error && (
        <div style={{ padding: '12px 16px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', color: '#f87171', fontSize: '13px' }}>
          {error}
        </div>
      )}

      {/* Main Tab Content */}
      {viewTab === 'enforcement' ? (
        <div className="ep-table-container">
          <table className="ep-table" style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ padding: '12px 16px' }}>Session Title</th>
                <th style={{ padding: '12px 16px' }}>Status</th>
                <th style={{ padding: '12px 16px' }}>Target Endpoints</th>
                <th style={{ padding: '12px 16px' }}>Security Alerts</th>
                <th style={{ padding: '12px 16px' }}>Execution Window</th>
                <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} style={{ padding: '40px', textAlign: 'center', color: 'var(--ep-text-muted)' }}>
                    <RefreshCw size={20} className="ep-spin" style={{ margin: '0 auto 8px', display: 'block' }} />
                    Loading enforcement sessions...
                  </td>
                </tr>
              ) : filteredSessions.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: '40px', textAlign: 'center', color: 'var(--ep-text-muted)' }}>
                    No enforcement sessions matching current query.
                  </td>
                </tr>
              ) : (
                filteredSessions.map((session) => {
                  const isActive = session.status.toLowerCase() === 'active';
                  const isPending = session.status.toLowerCase() === 'pending' || session.status.toLowerCase() === 'scheduled';

                  return (
                    <tr
                      key={session.id}
                      onClick={() => handleInspect(session)}
                      style={{ cursor: 'pointer', transition: 'background 0.15s ease' }}
                    >
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ fontWeight: 600, color: 'var(--ep-text-primary)', fontSize: '13px' }}>
                          {session.examName}
                        </div>
                        <div style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--ep-text-muted)' }}>
                          ID: {session.id}
                        </div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        {isActive ? (
                          <span className="ep-badge ep-badge-emerald" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'currentColor' }} />
                            ENFORCING
                          </span>
                        ) : isPending ? (
                          <span className="ep-badge ep-badge-amber">STAGED</span>
                        ) : (
                          <span className="ep-badge ep-badge-slate">CONCLUDED</span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{ fontFamily: 'monospace', fontSize: '13px', color: 'var(--ep-text-primary)' }}>
                          {session.deviceCount} endpoints
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        {session.alertCount && session.alertCount > 0 ? (
                          <span className="ep-badge ep-badge-crimson">
                            {session.alertCount} Alerts
                          </span>
                        ) : (
                          <span style={{ fontSize: '12px', color: 'var(--ep-text-muted)' }}>0 alerts</span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                        {session.startedAt ? (
                          <div>{new Date(session.startedAt).toLocaleString()}</div>
                        ) : (
                          <span style={{ color: 'var(--ep-text-muted)' }}>Not started</span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '8px', alignItems: 'center' }}>
                          {isActive ? (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setConfirmModal({ type: 'deactivate', session });
                              }}
                              className="ep-btn ep-btn-secondary"
                              style={{ color: 'var(--ep-crimson)', padding: '5px 12px', fontSize: '12px' }}
                              title="Deactivate enforcement"
                            >
                              <Square size={12} style={{ marginRight: '4px' }} />
                              Deactivate
                            </button>
                          ) : isPending ? (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setConfirmModal({ type: 'activate', session });
                              }}
                              className="ep-btn ep-btn-primary"
                              style={{ padding: '5px 12px', fontSize: '12px' }}
                              title="Activate Windows Firewall enforcement"
                            >
                              <Play size={12} style={{ marginRight: '4px' }} />
                              Activate
                            </button>
                          ) : null}

                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleInspect(session);
                            }}
                            className="ep-btn ep-btn-secondary"
                            style={{ padding: '5px 10px' }}
                            title="Inspect Policy Compliance"
                          >
                            <Eye size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      ) : (
        /* Endpoint Sessions Subtab */
        <div className="ep-table-container">
          <table className="ep-table" style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ padding: '12px 16px' }}>Endpoint / User Session</th>
                <th style={{ padding: '12px 16px' }}>Device ID</th>
                <th style={{ padding: '12px 16px' }}>Enforcement Session</th>
                <th style={{ padding: '12px 16px' }}>Status</th>
                <th style={{ padding: '12px 16px' }}>Session Window</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} style={{ padding: '40px', textAlign: 'center', color: 'var(--ep-text-muted)' }}>
                    <RefreshCw size={20} className="ep-spin" style={{ margin: '0 auto 8px', display: 'block' }} />
                    Loading endpoint sessions...
                  </td>
                </tr>
              ) : filteredEndpointSessions.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ padding: '40px', textAlign: 'center', color: 'var(--ep-text-muted)' }}>
                    No endpoint sessions recorded.
                  </td>
                </tr>
              ) : (
                filteredEndpointSessions.map((rec) => (
                  <tr key={rec.session_id}>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--ep-text-primary)', fontSize: '13px' }}>
                        {rec.student_roll_number || 'Unassigned Session'}
                      </div>
                      <div style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--ep-text-muted)' }}>
                        Session: {rec.session_id}
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontSize: '12px', color: 'var(--ep-cyan)' }}>
                      {rec.device_id}
                    </td>
                    <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                      {rec.exam_id}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <span className={`ep-badge ${rec.status?.toLowerCase() === 'active' ? 'ep-badge-emerald' : 'ep-badge-slate'}`}>
                        {rec.status || 'Active'}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px', fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                      {rec.started_at ? new Date(rec.started_at).toLocaleString() : 'N/A'}
                      {rec.ended_at && (
                        <span style={{ color: 'var(--ep-text-muted)' }}> &rarr; {new Date(rec.ended_at).toLocaleTimeString()}</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Styled Mutation Confirmation Modal (replaces window.confirm) */}
      {confirmModal && (
        <div className="ep-modal-backdrop" onClick={() => !confirming && setConfirmModal(null)}>
          <div className="ep-modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--ep-surface-border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '6px',
                    backgroundColor: confirmModal.type === 'activate' ? 'var(--ep-emerald-bg)' : 'var(--ep-crimson-bg)',
                    border: `1px solid ${confirmModal.type === 'activate' ? 'var(--ep-emerald-border)' : 'var(--ep-crimson-border)'}`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: confirmModal.type === 'activate' ? 'var(--ep-emerald)' : 'var(--ep-crimson)',
                  }}
                >
                  {confirmModal.type === 'activate' ? <Play size={16} /> : <Square size={16} />}
                </div>
                <h3 style={{ fontSize: '16px', fontWeight: '700', color: '#FFFFFF', margin: 0 }}>
                  {confirmModal.type === 'activate' ? 'Activate Policy Enforcement' : 'Deactivate Policy Enforcement'}
                </h3>
              </div>
              <button
                onClick={() => !confirming && setConfirmModal(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--ep-text-secondary)', cursor: 'pointer' }}
                disabled={confirming}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <p style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', margin: 0, lineHeight: 1.5 }}>
                {confirmModal.type === 'activate' ? (
                  <>
                    Are you sure you want to activate enforcement session <strong style={{ color: '#FFFFFF' }}>{confirmModal.session.examName}</strong>?
                  </>
                ) : (
                  <>
                    Are you sure you want to deactivate enforcement session <strong style={{ color: '#FFFFFF' }}>{confirmModal.session.examName}</strong>?
                  </>
                )}
              </p>

              <div
                style={{
                  padding: '12px',
                  borderRadius: '6px',
                  backgroundColor: confirmModal.type === 'activate' ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                  border: `1px solid ${confirmModal.type === 'activate' ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
                  fontSize: '12px',
                  color: confirmModal.type === 'activate' ? '#34D399' : '#F87171',
                  lineHeight: 1.4,
                }}
              >
                <strong>Consequence: </strong>
                {confirmModal.type === 'activate'
                  ? `Windows Firewall rules will be cryptographically compiled and enforced across ${confirmModal.session.deviceCount} target endpoints immediately.`
                  : `Active firewall enforcement rules will be revoked across ${confirmModal.session.deviceCount} target endpoints and restored to default permissive network baselines.`}
              </div>

              {confirmError && (
                <div style={{ padding: '10px 12px', borderRadius: '6px', backgroundColor: 'var(--ep-crimson-bg)', border: '1px solid var(--ep-crimson-border)', color: 'var(--ep-crimson)', fontSize: '12px' }}>
                  {confirmError}
                </div>
              )}
            </div>

            <div style={{ padding: '16px 24px', borderTop: '1px solid var(--ep-surface-border)', display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                type="button"
                onClick={() => setConfirmModal(null)}
                disabled={confirming}
                className="ep-btn ep-btn-secondary"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleExecuteAction}
                disabled={confirming}
                className="ep-btn"
                style={{
                  backgroundColor: confirmModal.type === 'activate' ? 'var(--ep-emerald)' : 'var(--ep-crimson)',
                  color: '#FFFFFF',
                  fontWeight: 600,
                }}
              >
                {confirming
                  ? confirmModal.type === 'activate'
                    ? 'Activating...'
                    : 'Deactivating...'
                  : confirmModal.type === 'activate'
                  ? 'Confirm & Enforce'
                  : 'Confirm & Deactivate'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Inspector Drawer for Session Compliance */}
      {selectedSession && (
        <div
          className="ep-drawer-backdrop"
          onClick={() => setSelectedSession(null)}
        >
          <div
            className="ep-drawer-panel"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Drawer Header */}
            <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--ep-surface-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--ep-cyan)', letterSpacing: '0.08em' }}>
                  SESSION POLICY COMPLIANCE
                </div>
                <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--ep-text-primary)', marginTop: '2px' }}>
                  {selectedSession.examName}
                </div>
              </div>
              <button
                onClick={() => setSelectedSession(null)}
                style={{ background: 'none', border: 'none', color: 'var(--ep-text-muted)', cursor: 'pointer', padding: '4px' }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Drawer Body */}
            <div style={{ padding: '24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="ep-card" style={{ padding: '16px' }}>
                <div style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase', marginBottom: '8px' }}>
                  Enforcement Parameters
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '12px' }}>
                  <div>
                    <span style={{ color: 'var(--ep-text-muted)' }}>Session ID:</span>
                    <div style={{ fontFamily: 'monospace', color: 'var(--ep-text-primary)', marginTop: '2px', wordBreak: 'break-all' }}>{selectedSession.id}</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--ep-text-muted)' }}>Status:</span>
                    <div style={{ marginTop: '2px' }}>
                      <span className={`ep-badge ${selectedSession.status.toLowerCase() === 'active' ? 'ep-badge-emerald' : 'ep-badge-slate'}`}>
                        {selectedSession.status.toUpperCase()}
                      </span>
                    </div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--ep-text-muted)' }}>Target Host Count:</span>
                    <div style={{ color: 'var(--ep-text-primary)', marginTop: '2px' }}>{selectedSession.deviceCount} endpoints</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--ep-text-muted)' }}>Security Anomaly Count:</span>
                    <div style={{ color: selectedSession.alertCount ? 'var(--ep-crimson)' : 'var(--ep-emerald)', marginTop: '2px' }}>
                      {selectedSession.alertCount || 0} alerts
                    </div>
                  </div>
                </div>
              </div>

              {/* Real-time Device Policy States */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--ep-text-primary)', margin: 0 }}>
                    Enrolled Endpoint Policy States
                  </h4>
                  <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)' }}>
                    {deviceCompliance.length} devices mapped
                  </span>
                </div>

                {loadingCompliance ? (
                  <div style={{ padding: '24px', textAlign: 'center', color: 'var(--ep-text-muted)', fontSize: '12px' }}>
                    <RefreshCw size={16} className="ep-spin" style={{ margin: '0 auto 8px', display: 'block' }} />
                    Auditing device policy states...
                  </div>
                ) : deviceCompliance.length === 0 ? (
                  <div style={{ padding: '24px', textAlign: 'center', color: 'var(--ep-text-muted)', fontSize: '12px', border: '1px dashed var(--ep-surface-border)', borderRadius: '6px' }}>
                    No endpoint state telemetry reported for this session.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {deviceCompliance.map((dev: any) => (
                      <div
                        key={dev.device_id}
                        className="ep-card"
                        style={{
                          padding: '12px 16px',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          fontSize: '12px',
                        }}
                      >
                        <div>
                          <div style={{ fontWeight: 600, color: 'var(--ep-text-primary)' }}>
                            {dev.hostname || dev.device_name || `Host-${dev.device_id.slice(0, 8)}`}
                          </div>
                          <div style={{ fontSize: '10px', fontFamily: 'monospace', color: 'var(--ep-text-muted)' }}>
                            {dev.hardware_uuid || dev.device_id}
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span
                            className={`ep-badge ${
                              dev.policy_status === 'applied' || dev.policy_status === 'enforced'
                                ? 'ep-badge-emerald'
                                : dev.policy_status === 'pending'
                                ? 'ep-badge-amber'
                                : 'ep-badge-crimson'
                            }`}
                          >
                            {dev.policy_status ? dev.policy_status.toUpperCase() : 'CONFORMING'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Drawer Footer */}
            <div style={{ padding: '16px 24px', borderTop: '1px solid var(--ep-surface-border)', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setSelectedSession(null)}
                className="ep-btn ep-btn-secondary"
              >
                Close Audit
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default EnterpriseSessions;
