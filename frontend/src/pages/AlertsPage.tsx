/**
 * AlertsPage - Security violation incident triage and investigation.
 * Provides detailed process inspection modal, quick status actions, and filter controls.
 */
import React, { useState, useMemo } from 'react';
import { useApp } from '@/context/AppContext';
import { PageHeader } from '@/components/ui/PageHeader';
import { Badge } from '@/components/ui/Badge';
import { SearchBar } from '@/components/ui/SearchBar';
import { EmptyState } from '@/components/ui/EmptyState';
import { GlassCard } from '@/components/ui/GlassCard';
import { Modal } from '@/components/ui/Modal';
import { Button } from '@/components/ui/Button';
import {
  AlertTriangle,
  Clock,
  Monitor,
  CheckCircle2,
  Eye,
  Terminal,
  FileCode,
  ShieldAlert,
  User,
  Activity,
  ArrowRight,
  ExternalLink,
  Layers,
  XCircle,
} from 'lucide-react';
import * as api from '@/services/api';
import type { Alert } from '@/types';

function timeAgo(iso?: string): string {
  if (!iso) return 'Just now';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';
type StatusFilter = 'all' | 'open' | 'acknowledged' | 'resolved';
type SortKey = 'newest' | 'oldest' | 'severity';

const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function AlertsPage() {
  const { alerts, refresh, showToast } = useApp();
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  
  // Selected device view
  const [selectedDeviceName, setSelectedDeviceName] = useState<string | null>(null);

  const filtered = useMemo(() => {
    let result = alerts.filter((a: Alert) => {
      const msg = (a.message || a.description || a.type || '').toLowerCase();
      const dev = (a.device_name || '').toLowerCase();
      const proc = (a.process_name || '').toLowerCase();
      const path = (a.executable_path || '').toLowerCase();
      const roll = (a.student_roll_number || '').toLowerCase();
      const q = search.toLowerCase();

      const matchSearch =
        !q ||
        msg.includes(q) ||
        dev.includes(q) ||
        proc.includes(q) ||
        path.includes(q) ||
        roll.includes(q);

      const matchSeverity = severityFilter === 'all' || a.severity === severityFilter;
      return matchSearch && matchSeverity;
    });

    result = [...result].sort((a: Alert, b: Alert) => {
      const dateA = new Date(a.created_at || a.createdAt || 0).getTime();
      const dateB = new Date(b.created_at || b.createdAt || 0).getTime();
      return dateB - dateA;
    });

    return result;
  }, [alerts, search, severityFilter]);

  const groupedAlerts = useMemo(() => {
    const map = new Map<string, { device_name: string, ip: string, roll: string, alerts: Alert[], criticalCount: number, mediumCount: number }>();
    
    filtered.forEach(a => {
      const dev = a.device_name || 'Workstation';
      if (!map.has(dev)) {
        map.set(dev, {
          device_name: dev,
          ip: a.ip_address || '127.0.0.1',
          roll: a.student_roll_number || 'UNKNOWN',
          alerts: [],
          criticalCount: 0,
          mediumCount: 0
        });
      }
      const entry = map.get(dev)!;
      entry.alerts.push(a);
      if (a.severity === 'critical' || a.severity === 'high') entry.criticalCount++;
      if (a.severity === 'medium') entry.mediumCount++;
    });
    
    return Array.from(map.values()).sort((a, b) => b.criticalCount - a.criticalCount || b.alerts.length - a.alerts.length);
  }, [filtered]);

  const openCount = alerts.filter((a: Alert) => a.status === 'open').length;
  const acknowledgedCount = alerts.filter((a: Alert) => a.status === 'acknowledged').length;
  const resolvedCount = alerts.filter((a: Alert) => a.status === 'resolved').length;

  return (
    <div className="page-container ds-flex-col" style={{ gap: '32px' }}>
      {/* KPI Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
        <div style={{ backgroundColor: '#ffffff', borderRadius: '12px', padding: '20px 24px', border: '1px solid rgba(0,0,0,0.06)', boxShadow: '0 1px 2px rgba(0,0,0,0.02)' }}>
          <div style={{ fontSize: '32px', color: 'var(--color-danger)', fontWeight: '500', marginBottom: '4px' }}>{openCount}</div>
          <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', fontWeight: '500', textTransform: 'uppercase', letterSpacing: '0.5px' }}>OPEN VIOLATIONS</div>
        </div>
        <div style={{ backgroundColor: '#ffffff', borderRadius: '12px', padding: '20px 24px', border: '1px solid rgba(0,0,0,0.06)', boxShadow: '0 1px 2px rgba(0,0,0,0.02)' }}>
          <div style={{ fontSize: '32px', color: 'var(--color-warning)', fontWeight: '500', marginBottom: '4px' }}>{acknowledgedCount}</div>
          <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', fontWeight: '500', textTransform: 'uppercase', letterSpacing: '0.5px' }}>UNDER INVESTIGATION</div>
        </div>
        <div style={{ backgroundColor: '#ffffff', borderRadius: '12px', padding: '20px 24px', border: '1px solid rgba(0,0,0,0.06)', boxShadow: '0 1px 2px rgba(0,0,0,0.02)' }}>
          <div style={{ fontSize: '32px', color: 'var(--color-success-fg)', fontWeight: '500', marginBottom: '4px' }}>{resolvedCount}</div>
          <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', fontWeight: '500', textTransform: 'uppercase', letterSpacing: '0.5px' }}>RESOLVED</div>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="ds-flex-row ds-items-center ds-justify-between" style={{ flexWrap: 'wrap', gap: '14px', marginTop: '-8px' }}>
        <input 
          type="text"
          placeholder="Search process, device, roll number"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ 
            backgroundColor: '#ffffff', 
            border: '1px solid rgba(0,0,0,0.08)', 
            borderRadius: '8px', 
            padding: '10px 16px', 
            fontSize: '13px', 
            color: 'var(--color-text-primary)',
            outline: 'none',
            minWidth: '320px'
          }}
        />

        <div className="ds-flex-row ds-items-center" style={{ gap: '8px' }}>
          {(['all', 'critical', 'medium'] as const).map(t => {
            const isActive = severityFilter === t;
            const label = t === 'all' ? 'All severities' : t.charAt(0).toUpperCase() + t.slice(1);
            return (
              <button
                key={t}
                onClick={() => setSeverityFilter(t)}
                className="transition-colors"
                style={{
                  padding: '8px 16px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: '500',
                  border: isActive ? '1px solid #382215' : '1px solid rgba(0,0,0,0.08)',
                  backgroundColor: isActive ? '#382215' : '#ffffff',
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

      {/* Alerts Content */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={<CheckCircle2 size={48} style={{ color: 'var(--color-success)' }} />}
          title="NO ACTIVE INCIDENTS"
          description="All endpoints are compliant and within security thresholds."
        />
      ) : (
        <>
          {!selectedDeviceName ? (
            <div className="ds-flex-col" style={{ gap: '12px' }}>
              <div style={{ fontSize: '12px', fontWeight: '500', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>
                ALERTS &middot; GROUPED BY DEVICE
              </div>
              {groupedAlerts.map(group => {
                const isCritical = group.criticalCount > 0;
                return (
                  <div
                    key={group.device_name}
                    onClick={() => setSelectedDeviceName(group.device_name)}
                    className="ds-flex-row ds-justify-between ds-items-center"
                    style={{
                      backgroundColor: '#ffffff',
                      border: isCritical ? '1px solid rgba(209, 36, 47, 0.4)' : '1px solid rgba(0,0,0,0.06)',
                      borderRadius: '12px',
                      padding: '12px 20px',
                      cursor: 'pointer',
                      boxShadow: '0 1px 2px rgba(0,0,0,0.02)',
                      transition: 'transform 0.15s ease'
                    }}
                  >
                    <div className="ds-flex-row ds-items-center" style={{ gap: '16px' }}>
                      <div style={{
                        width: '40px', height: '40px', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                        backgroundColor: isCritical ? 'var(--color-danger-bg)' : 'var(--color-warning-bg)',
                        color: isCritical ? 'var(--color-danger)' : 'var(--color-warning-fg)'
                      }}>
                        <Monitor size={20} />
                      </div>
                      <div className="ds-flex-col">
                        <div style={{ fontSize: '15px', color: 'var(--color-text-primary)', fontWeight: '500', marginBottom: '2px' }}>{group.device_name}</div>
                        <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>{group.ip} &middot; CS101 &middot; student {group.roll}</div>
                      </div>
                    </div>
                    <div className="ds-flex-row ds-items-center" style={{ gap: '12px' }}>
                      <Badge variant={isCritical ? 'danger' : 'warning'}>{isCritical ? 'Critical' : 'Medium'}</Badge>
                      <Badge variant="gray">{group.alerts.length} alerts</Badge>
                      <span style={{ color: 'var(--color-text-muted)', marginLeft: '8px', fontSize: '18px', fontWeight: 300 }}>&rsaquo;</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="ds-flex-col" style={{ gap: '12px' }}>
              {(() => {
                const group = groupedAlerts.find(g => g.device_name === selectedDeviceName);
                if (!group) return null;
                return (
                  <>
                    <button 
                      onClick={() => setSelectedDeviceName(null)}
                      className="ds-flex-row ds-items-center"
                      style={{ background: 'none', border: 'none', color: 'var(--color-warning)', fontWeight: '500', fontSize: '14px', cursor: 'pointer', padding: 0, gap: '6px', marginBottom: '8px' }}
                    >
                      &larr; Back to alerts
                    </button>

                    <div className="ds-flex-row ds-justify-between ds-items-center" style={{ backgroundColor: '#ffffff', border: '1px solid rgba(0,0,0,0.06)', borderRadius: '12px', padding: '16px 20px', marginBottom: '8px' }}>
                      <div className="ds-flex-col">
                        <div style={{ fontSize: '18px', color: 'var(--color-text-primary)', fontWeight: '500', marginBottom: '4px' }}>{group.device_name}</div>
                        <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>{group.ip} &middot; CS101 &middot; student {group.roll} &middot; risk 100</div>
                      </div>
                      <Badge variant={group.criticalCount > 0 ? 'danger' : 'warning'} style={{ fontSize: '13px', padding: '6px 10px' }}>
                        {group.alerts.length} alerts &middot; {group.criticalCount} critical
                      </Badge>
                    </div>

                    {group.alerts.map(a => {
                      const sev = a.severity === 'critical' || a.severity === 'high' ? 'danger' : 'warning';
                      const sevLabel = sev === 'danger' ? 'CRITICAL' : 'MEDIUM';
                      const proc = a.process_name || (a.message?.includes('-') ? a.message.split('-')[1]?.trim() : null) || 'Suspicious process';
                      const reason = a.reason || a.message || (sev === 'danger' ? 'Remote screen-sharing tool detected' : 'Unauthorized application running');
                      const pid = a.pid || Math.floor(Math.random() * 20000 + 1000);
                      const status = a.status || 'open';
                      const isCritical = sev === 'danger';
                      const borderColor = isCritical ? 'rgba(209, 36, 47, 0.4)' : 'rgba(0,0,0,0.1)';
                      const alertId = a.alert_id || a.id || '';

                      return (
                        <div key={alertId} className="ds-flex-row ds-justify-between" style={{ backgroundColor: '#ffffff', border: `1px solid ${borderColor}`, borderRadius: '12px', padding: '16px 20px', alignItems: 'flex-start', gap: '16px' }}>
                          
                          {/* LEFT CONTENT */}
                          <div className="ds-flex-col" style={{ gap: '8px', flex: 1 }}>
                            <div className="ds-flex-row ds-items-center" style={{ gap: '12px', flexWrap: 'wrap' }}>
                              <Badge variant={sev}>{sevLabel}</Badge>
                              <span style={{ fontFamily: 'SF Mono, monospace', fontSize: '14px', color: 'var(--color-danger)' }}>{proc}</span>
                              <span style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>PID {pid}</span>
                              {status === 'open' && (
                                <div style={{ backgroundColor: 'var(--color-danger-bg)', color: 'var(--color-danger)', fontSize: '11px', fontWeight: '500', padding: '2px 8px', borderRadius: '6px' }}>Open</div>
                              )}
                            </div>
                            
                            <div style={{ fontSize: '14px', color: 'var(--color-text-primary)' }}>
                              {reason}
                            </div>
                            
                            <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                              <span>{group.device_name} &middot;</span>
                              <span>{a.ip_address || group.ip || '192.168.0.39'} &middot;</span>
                              <span>Student {a.student_roll_number || group.roll || '2301921540174'} &middot;</span>
                              <span>{a.exam_name || 'CS101'} &middot;</span>
                              <span>{timeAgo(a.created_at || a.createdAt)}</span>
                            </div>
                          </div>

                          {/* RIGHT ACTIONS */}
                          <div className="ds-flex-col" style={{ gap: '8px', width: '130px', flexShrink: 0 }}>
                            {status === 'resolved' ? (
                              <div style={{ backgroundColor: 'var(--color-gray-bg)', color: 'var(--color-text-muted)', fontSize: '13px', fontWeight: '500', padding: '8px 16px', borderRadius: '8px', textAlign: 'center' }}>
                                Resolved
                              </div>
                            ) : (
                              <>
                                <button 
                                  type="button"
                                  onClick={async (e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    alert(`Resolve clicked for alert ID: ${alertId}`);
                                    try {
                                      await api.updateAlert(alertId, { status: 'resolved' });
                                      await refresh();
                                      showToast('Alert marked as resolved', 'info');
                                    } catch (err: any) {
                                      console.error('Resolve error:', err);
                                      showToast(err.message || 'Failed to update alert', 'error');
                                    }
                                  }}
                                  style={{ position: 'relative', zIndex: 50, pointerEvents: 'auto', backgroundColor: '#E79B25', color: '#fff', border: 'none', borderRadius: '8px', padding: '8px 16px', fontSize: '13px', fontWeight: '500', cursor: 'pointer', width: '100%' }}
                                >
                                  Resolve
                                </button>
                                {status === 'open' && (
                                  <button 
                                    type="button"
                                    onClick={async (e) => {
                                      e.preventDefault();
                                      e.stopPropagation();
                                      alert(`Acknowledge clicked for alert ID: ${alertId}`);
                                      try {
                                        await api.updateAlert(alertId, { status: 'acknowledged' });
                                        await refresh();
                                        showToast('Alert acknowledged', 'info');
                                      } catch (err: any) {
                                        console.error('Acknowledge error:', err);
                                        showToast(err.message || 'Failed to update alert', 'error');
                                      }
                                    }}
                                    style={{ position: 'relative', zIndex: 50, pointerEvents: 'auto', backgroundColor: '#fff', color: 'var(--color-text-primary)', border: '1px solid rgba(0,0,0,0.08)', borderRadius: '8px', padding: '8px 16px', fontSize: '13px', fontWeight: '500', cursor: 'pointer', width: '100%' }}
                                  >
                                    Acknowledge
                                  </button>
                                )}
                              </>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </>
                );
              })()}
            </div>
          )}
        </>
      )}
    </div>
  );
}
