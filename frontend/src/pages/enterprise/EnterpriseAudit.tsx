import React, { useState, useEffect, useMemo } from 'react';
import {
  FileText,
  Search,
  RefreshCw,
  Eye,
  X,
  User,
  Terminal,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import * as api from '@/services/api';

interface AuditRecord {
  log_id: string;
  user_id?: string | null;
  action: string;
  entity_type?: string | null;
  entity_id?: string | null;
  details?: Record<string, any> | null;
  ip_address?: string | null;
  created_at: string;
}

export function EnterpriseAudit() {
  const [logs, setLogs] = useState<AuditRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Search & Filter
  const [search, setSearch] = useState('');
  const [actionCategory, setActionCategory] = useState<'all' | 'auth' | 'policy' | 'device' | 'session'>('all');
  const [page, setPage] = useState(1);
  const pageSize = 25;

  // Inspector Drawer for Audit Record Details
  const [selectedRecord, setSelectedRecord] = useState<AuditRecord | null>(null);
  const [copiedJson, setCopiedJson] = useState(false);
  const [copiedActorId, setCopiedActorId] = useState<string | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getAuditLogs();
      setLogs(Array.isArray(data) ? data : []);
    } catch (err: any) {
      console.error('Failed to fetch audit logs:', err);
      setError(err?.message || 'Failed to retrieve audit trail');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleCopyJson = (obj: any) => {
    navigator.clipboard.writeText(JSON.stringify(obj, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const handleCopyActorId = (actorId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(actorId);
    setCopiedActorId(actorId);
    setTimeout(() => setCopiedActorId(null), 2000);
  };

  // Metrics
  const metrics = useMemo(() => {
    const total = logs.length;
    const uniqueActors = new Set(logs.map((l) => l.user_id || 'system')).size;
    const policyModifications = logs.filter(
      (l) => l.action.toLowerCase().includes('policy') || l.action.toLowerCase().includes('signing')
    ).length;
    const uniqueIps = new Set(logs.filter((l) => l.ip_address).map((l) => l.ip_address)).size;
    return { total, uniqueActors, policyModifications, uniqueIps };
  }, [logs]);

  // Filtered Logs
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const q = search.toLowerCase();
      const matchSearch =
        log.action.toLowerCase().includes(q) ||
        (log.user_id && log.user_id.toLowerCase().includes(q)) ||
        (log.entity_type && log.entity_type.toLowerCase().includes(q)) ||
        (log.entity_id && log.entity_id.toLowerCase().includes(q)) ||
        (log.ip_address && log.ip_address.toLowerCase().includes(q));

      let matchCat = true;
      const act = log.action.toLowerCase();
      if (actionCategory === 'auth') {
        matchCat = act.includes('login') || act.includes('auth') || act.includes('token') || act.includes('user');
      } else if (actionCategory === 'policy') {
        matchCat = act.includes('policy') || act.includes('vendor') || act.includes('signing') || act.includes('key');
      } else if (actionCategory === 'device') {
        matchCat = act.includes('device') || act.includes('hardware') || act.includes('endpoint');
      } else if (actionCategory === 'session') {
        matchCat = act.includes('session') || act.includes('exam') || act.includes('enforce');
      }

      return matchSearch && matchCat;
    });
  }, [logs, search, actionCategory]);

  // Reset page when filter changes
  useEffect(() => {
    setPage(1);
  }, [search, actionCategory]);

  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / pageSize));
  const paginatedLogs = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredLogs.slice(start, start + pageSize);
  }, [filteredLogs, page, pageSize]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
      {/* Modern Page Header */}
      <div className="ep-page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--ep-cyan)', letterSpacing: '0.1em' }}>
              GOVERNANCE & TRUST // AUDIT TRAIL
            </span>
            <span className="ep-badge ep-badge-cyan">APPEND-ONLY AUDIT TRAIL</span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#FFFFFF', margin: 0, letterSpacing: '-0.3px' }}>
            Audit Trail
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', margin: '4px 0 0 0' }}>
            Chronological, append-only record of administrative actions, key lifecycle modifications, and policy events
          </p>
        </div>

        <div className="ep-header-actions">
          <button
            onClick={fetchLogs}
            disabled={loading}
            className="ep-btn ep-btn-secondary"
            title="Refresh audit trail"
          >
            <RefreshCw size={14} className={loading ? 'ep-spin' : ''} />
            <span>{loading ? 'Refreshing...' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="ep-grid-4">
        <div className="ep-stat-card ep-stat-cyan">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Audit Entries
            </span>
            <FileText size={16} color="var(--ep-cyan)" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--ep-text-primary)' }}>
            {metrics.total}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-text-secondary)', marginTop: '4px' }}>
            Total verifiable events in trail
          </div>
        </div>

        <div className="ep-stat-card ep-stat-emerald">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Distinct Actors
            </span>
            <User size={16} color="var(--ep-emerald)" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--ep-text-primary)' }}>
            {metrics.uniqueActors}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-emerald)', marginTop: '4px' }}>
            Administrators & system workers
          </div>
        </div>

        <div className="ep-stat-card ep-stat-indigo">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Policy Modifications
            </span>
            <FileText size={16} color="var(--ep-indigo)" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--ep-text-primary)' }}>
            {metrics.policyModifications}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-indigo)', marginTop: '4px' }}>
            Key lifecycle & firewall updates
          </div>
        </div>

        <div className="ep-stat-card ep-stat-amber">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Origin Endpoints
            </span>
            <FileText size={16} color="var(--ep-amber)" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--ep-text-primary)' }}>
            {metrics.uniqueIps}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ep-text-muted)', marginTop: '4px' }}>
            Unique administrative ingress IPs
          </div>
        </div>
      </div>

      {/* Toolbar: Search and Filters */}
      <div className="ep-toolbar">
        <div style={{ position: 'relative', flex: 1, minWidth: '220px' }}>
          <Search size={14} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--ep-text-muted)' }} />
          <input
            type="text"
            placeholder="Search action, actor, entity, IP or log ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="ep-input"
            style={{ width: '100%', paddingLeft: '34px', fontSize: '13px', boxSizing: 'border-box' }}
          />
        </div>

        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {(['all', 'auth', 'policy', 'device', 'session'] as const).map((cat) => (
            <button
              key={cat}
              onClick={() => setActionCategory(cat)}
              className={`ep-btn ${actionCategory === cat ? 'ep-btn-primary' : 'ep-btn-secondary'}`}
              style={{ fontSize: '12px', textTransform: 'capitalize', padding: '6px 14px' }}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div style={{ padding: '12px 16px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', color: '#f87171', fontSize: '13px' }}>
          {error}
        </div>
      )}

      {/* Main Audit Table */}
      <div className="ep-table-container">
        <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
          <table className="ep-table" style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
            <thead style={{ position: 'sticky', top: 0, zIndex: 10, backgroundColor: 'var(--ep-surface-subtle)' }}>
              <tr>
                <th style={{ padding: '12px 16px' }}>Timestamp (UTC)</th>
                <th style={{ padding: '12px 16px' }}>Action</th>
                <th style={{ padding: '12px 16px' }}>Actor</th>
                <th style={{ padding: '12px 16px' }}>Target Entity</th>
                <th style={{ padding: '12px 16px' }}>Origin IP</th>
                <th style={{ padding: '12px 16px', textAlign: 'right' }}>Payload</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} style={{ padding: '40px', textAlign: 'center', color: 'var(--ep-text-muted)' }}>
                    <RefreshCw size={20} className="ep-spin" style={{ margin: '0 auto 8px', display: 'block' }} />
                    Retrieving audit trail records...
                  </td>
                </tr>
              ) : paginatedLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: '40px', textAlign: 'center', color: 'var(--ep-text-muted)' }}>
                    No audit trail records matching current filter.
                  </td>
                </tr>
              ) : (
                paginatedLogs.map((log) => {
                  const act = log.action.toUpperCase();
                  let badgeClass = 'ep-badge-slate';
                  if (act.includes('LOGIN') || act.includes('AUTH')) badgeClass = 'ep-badge-cyan';
                  else if (act.includes('ROTATE') || act.includes('REVOKE') || act.includes('KEY')) badgeClass = 'ep-badge-amber';
                  else if (act.includes('ACTIVATE') || act.includes('POLICY')) badgeClass = 'ep-badge-emerald';
                  else if (act.includes('DELETE')) badgeClass = 'ep-badge-crimson';

                  const isActorCopied = copiedActorId === log.user_id;

                  return (
                    <tr
                      key={log.log_id}
                      onClick={() => setSelectedRecord(log)}
                      style={{ cursor: 'pointer', transition: 'background 0.15s ease' }}
                    >
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontSize: '12px', color: 'var(--ep-text-secondary)', whiteSpace: 'nowrap' }}>
                        {log.created_at ? new Date(log.created_at).toISOString().replace('T', ' ').slice(0, 19) : 'N/A'}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span className={`ep-badge ${badgeClass}`} style={{ fontFamily: 'monospace', fontSize: '11px' }}>
                          {log.action}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <User size={13} color="var(--ep-text-muted)" style={{ flexShrink: 0 }} />
                          <span
                            style={{ fontSize: '12px', fontFamily: 'monospace', color: 'var(--ep-text-primary)' }}
                            title={log.user_id || 'System Process'}
                          >
                            {log.user_id ? log.user_id.slice(0, 8) + '...' : 'System Agent'}
                          </span>
                          {log.user_id && (
                            <button
                              onClick={(e) => handleCopyActorId(log.user_id!, e)}
                              style={{
                                background: 'transparent',
                                border: 'none',
                                color: isActorCopied ? 'var(--ep-emerald)' : 'var(--ep-text-muted)',
                                cursor: 'pointer',
                                padding: '2px',
                                display: 'flex',
                                alignItems: 'center',
                              }}
                              title={isActorCopied ? 'UUID Copied!' : `Copy UUID: ${log.user_id}`}
                            >
                              {isActorCopied ? <Check size={12} /> : <Copy size={12} />}
                            </button>
                          )}
                        </div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ fontSize: '12px', color: 'var(--ep-text-primary)' }}>
                          {log.entity_type || 'Platform'}
                        </div>
                        {log.entity_id && (
                          <div style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--ep-text-muted)' }}>
                            {log.entity_id}
                          </div>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontSize: '12px', color: 'var(--ep-text-secondary)' }}>
                        {log.ip_address || '—'}
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedRecord(log);
                          }}
                          className="ep-btn ep-btn-secondary"
                          style={{ padding: '4px 8px' }}
                          title="Inspect Audit Record"
                        >
                          <Eye size={13} />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {filteredLogs.length > pageSize && (
          <div
            style={{
              padding: '12px 16px',
              borderTop: '1px solid var(--ep-surface-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              backgroundColor: 'var(--ep-surface-subtle)',
              fontSize: '12px',
              color: 'var(--ep-text-secondary)',
            }}
          >
            <div>
              Showing {Math.min(filteredLogs.length, (page - 1) * pageSize + 1)} - {Math.min(filteredLogs.length, page * pageSize)} of {filteredLogs.length} records
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="ep-btn ep-btn-secondary"
                style={{ padding: '4px 10px', fontSize: '11px' }}
              >
                <ChevronLeft size={13} />
                <span>Prev</span>
              </button>
              <span style={{ fontFamily: 'monospace' }}>
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="ep-btn ep-btn-secondary"
                style={{ padding: '4px 10px', fontSize: '11px' }}
              >
                <span>Next</span>
                <ChevronRight size={13} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Inspector Drawer for Audit Record Details */}
      {selectedRecord && (
        <div
          className="ep-drawer-backdrop"
          onClick={() => setSelectedRecord(null)}
        >
          <div
            className="ep-drawer-panel"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--ep-surface-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--ep-cyan)', letterSpacing: '0.08em' }}>
                  AUDIT RECORD DETAILS
                </div>
                <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--ep-text-primary)', marginTop: '2px' }}>
                  {selectedRecord.action}
                </div>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                style={{ background: 'none', border: 'none', color: 'var(--ep-text-muted)', cursor: 'pointer', padding: '4px' }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Content */}
            <div style={{ padding: '24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="ep-card" style={{ padding: '16px' }}>
                <div style={{ fontSize: '11px', color: 'var(--ep-text-muted)', textTransform: 'uppercase', marginBottom: '12px' }}>
                  Metadata & Provenance
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '12px' }}>
                  <div>
                    <span style={{ color: 'var(--ep-text-muted)' }}>Log UUID:</span>
                    <div style={{ fontFamily: 'monospace', color: 'var(--ep-text-primary)', marginTop: '2px', wordBreak: 'break-all' }}>
                      {selectedRecord.log_id}
                    </div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--ep-text-muted)' }}>Created (UTC):</span>
                    <div style={{ fontFamily: 'monospace', color: 'var(--ep-text-primary)', marginTop: '2px' }}>
                      {selectedRecord.created_at ? new Date(selectedRecord.created_at).toISOString() : 'N/A'}
                    </div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--ep-text-muted)' }}>Actor ID (Full):</span>
                    <div style={{ fontFamily: 'monospace', color: 'var(--ep-text-primary)', marginTop: '2px', wordBreak: 'break-all' }}>
                      {selectedRecord.user_id || 'System Process'}
                    </div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--ep-text-muted)' }}>Origin Address:</span>
                    <div style={{ fontFamily: 'monospace', color: 'var(--ep-cyan)', marginTop: '2px' }}>
                      {selectedRecord.ip_address || 'Internal (Loopback)'}
                    </div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--ep-text-muted)' }}>Target Entity:</span>
                    <div style={{ color: 'var(--ep-text-primary)', marginTop: '2px' }}>
                      {selectedRecord.entity_type || 'None'}
                    </div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--ep-text-muted)' }}>Entity Identifier:</span>
                    <div style={{ fontFamily: 'monospace', color: 'var(--ep-text-secondary)', marginTop: '2px', wordBreak: 'break-all' }}>
                      {selectedRecord.entity_id || 'N/A'}
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--ep-text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Terminal size={14} color="var(--ep-cyan)" />
                    Structured Payload (JSON)
                  </div>
                  <button
                    onClick={() => handleCopyJson(selectedRecord.details || {})}
                    className="ep-btn ep-btn-secondary"
                    style={{ fontSize: '11px', padding: '3px 8px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                  >
                    {copiedJson ? <Check size={12} color="var(--ep-emerald)" /> : <Copy size={12} />}
                    {copiedJson ? 'Copied' : 'Copy'}
                  </button>
                </div>

                <pre
                  style={{
                    background: 'var(--ep-surface-subtle)',
                    padding: '16px',
                    borderRadius: '6px',
                    border: '1px solid var(--ep-surface-border)',
                    fontFamily: 'monospace',
                    fontSize: '12px',
                    color: 'var(--ep-cyan)',
                    overflowX: 'auto',
                    maxHeight: '360px',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    margin: 0,
                  }}
                >
                  {selectedRecord.details && Object.keys(selectedRecord.details).length > 0
                    ? JSON.stringify(selectedRecord.details, null, 2)
                    : '// No additional payload parameters stored with this record.'}
                </pre>
              </div>
            </div>

            {/* Footer */}
            <div style={{ padding: '16px 24px', borderTop: '1px solid var(--ep-surface-border)', display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
              <button onClick={() => setSelectedRecord(null)} className="ep-btn ep-btn-secondary">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default EnterpriseAudit;
