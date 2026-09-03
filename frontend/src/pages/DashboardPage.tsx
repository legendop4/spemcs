import { useNavigate } from 'react-router-dom';
import { useApp } from '@/context/AppContext';
import { StatCard } from '@/components/ui/StatCard';
import { SectionCard } from '@/components/ui/SectionCard';
import { ListRow } from '@/components/ui/ListRow';
import { Badge } from '@/components/ui/Badge';
import {
  ShieldCheck,
  AlertTriangle,
  Monitor,
  Users,
  Activity,
  Wifi,
  Terminal,
} from 'lucide-react';
import React from 'react';

export function DashboardPage() {
  const { dashboardSummary, exams, alerts, devices, loading, wsConnected } = useApp();
  const navigate = useNavigate();

  const summary = dashboardSummary;
  const activeExams = exams.filter((e: any) => e.status === 'active');
  const recentAlerts = alerts.slice(0, 5);
  const onlineDevices = devices.filter((d: any) => d.status === 'online');

  if (loading && !summary) {
    return (
      <div className="flex items-center justify-center h-64">
        <div style={{ color: 'var(--color-text-muted)' }}>Loading security posture...</div>
      </div>
    );
  }

  return (
    <div className="ds-flex-col" style={{ gap: 'var(--space-6)', width: '100%', maxWidth: '1280px', margin: '0 auto', padding: '0 16px' }}>
      {/* Hero Header */}
      <div 
        className="ds-flex-col"
        style={{
          backgroundColor: '#382215', // Dark espresso brown
          borderRadius: '16px',
          padding: '32px 40px',
          color: '#ffffff'
        }}
      >
        <div style={{ fontSize: '12px', fontWeight: '600', color: '#D89400', letterSpacing: '1px', textTransform: 'uppercase', marginBottom: '8px' }}>
          CAMPUS SECURITY SHIELD
        </div>
        <h1 style={{ fontSize: '28px', fontWeight: '500', color: '#ffffff', marginBottom: '8px', letterSpacing: '-0.5px' }}>
          Exam proctoring command center
        </h1>
        <p style={{ fontSize: '15px', color: '#D2BDA3', marginBottom: '24px' }}>
          Real-time telemetry across {Array.from(new Set(devices.map((d: any) => d.building))).length || 3} labs, {summary?.total_exams || 24} configured exams
        </p>
        
        <div className="ds-flex-row ds-items-center" style={{ gap: '12px' }}>
          <div 
            className="ds-flex-row ds-items-center"
            style={{
              gap: '6px', padding: '6px 14px', borderRadius: '6px',
              fontSize: '13px', fontWeight: '500',
              backgroundColor: wsConnected ? 'rgba(216, 148, 0, 0.15)' : 'rgba(209, 36, 47, 0.15)',
              color: wsConnected ? '#D89400' : '#D1242F'
            }}
          >
            <Wifi size={14} />
            {wsConnected ? 'Live telemetry' : 'Disconnected'}
          </div>
          <div 
            className="ds-flex-row ds-items-center" 
            style={{
              gap: '6px', padding: '6px 14px', borderRadius: '6px',
              fontSize: '13px', fontWeight: '500',
              backgroundColor: 'rgba(255, 255, 255, 0.1)', color: '#D2BDA3'
            }}
          >
            {summary?.devices_online || 0} endpoints online
          </div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="ds-grid-stats">
        <StatCard 
          label="Total Workstations" 
          value={(summary?.total_devices || 0).toString().padStart(2, '0')} 
          sublabel={`${summary?.devices_online || 0} active endpoints`} 
          icon={Monitor} 
          accent="accent" 
        />
        <StatCard 
          label="Active Exams" 
          value={(summary?.active_exams || 0).toString().padStart(2, '0')} 
          sublabel={`${summary?.total_exams || 0} configured total`} 
          icon={ShieldCheck} 
          accent="success" 
        />
        <StatCard 
          label="Security Alerts" 
          value={(summary?.open_alerts || 0).toString().padStart(2, '0')} 
          sublabel="Pending investigation" 
          icon={AlertTriangle} 
          accent={(summary?.open_alerts || 0) > 0 ? 'danger' : 'info'} 
        />
        <StatCard 
          label="Exam Sessions" 
          value={(summary?.active_sessions || 0).toString().padStart(2, '0')} 
          sublabel="Students monitored" 
          icon={Users} 
          accent="info" 
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 'var(--space-6)' }}>
        {/* Active Exams */}
        <SectionCard 
          title="Active Proctored Exams" 
          count={activeExams.length}
          viewAllLink="/exam-shield"
        >
          {activeExams.length === 0 ? (
            <div className="ds-flex-col ds-items-center ds-justify-center" style={{ padding: 'var(--space-7) 0' }}>
              <ShieldCheck size={32} style={{ margin: '0 auto var(--space-3)', opacity: 0.3, color: 'var(--color-text-muted)' }} />
              <p style={{ color: 'var(--color-text-muted)', fontSize: 'var(--text-body-sm)' }}>No exams currently in active state.</p>
            </div>
          ) : (
            <div className="ds-flex-col">
              {activeExams.map((exam: any) => (
                <ListRow
                  key={exam.exam_id}
                  title={exam.exam_name}
                  metadata={[
                    `${exam.device_count || 0} devices`,
                    <span key="alerts" style={{ color: (exam.alert_count || 0) > 0 ? 'var(--color-danger)' : 'inherit' }}>
                      {exam.alert_count || 0} alerts
                    </span>
                  ]}
                  badge={<Badge variant="success" dot>Active</Badge>}
                  onClick={() => navigate(`/exam-shield/monitor/${exam.exam_id}`)}
                />
              ))}
            </div>
          )}
        </SectionCard>

        {/* Recent Alerts */}
        <SectionCard 
          title="Recent Security Violations" 
          count={recentAlerts.length}
          viewAllLink="/alerts"
        >
          {recentAlerts.length === 0 ? (
            <div className="ds-flex-col ds-items-center ds-justify-center" style={{ padding: 'var(--space-7) 0' }}>
              <AlertTriangle size={32} style={{ margin: '0 auto var(--space-3)', opacity: 0.3, color: 'var(--color-text-muted)' }} />
              <p style={{ color: 'var(--color-text-muted)', fontSize: 'var(--text-body-sm)' }}>No security alerts recorded.</p>
            </div>
          ) : (
            <div className="ds-flex-col">
              {recentAlerts.map((alert: any) => {
                const proc = alert.process_name || (alert.message?.includes('-') ? alert.message.split('-')[1]?.trim() : alert.message);
                
                // Map severity to our semantic token colors
                let severityVariant: 'danger' | 'warning' | 'info' | 'gray' = 'danger';
                if (alert.severity === 'medium') severityVariant = 'warning';
                else if (alert.severity === 'low') severityVariant = 'info';

                return (
                  <ListRow
                    key={alert.alert_id || alert.id}
                    title={
                      <div className="ds-flex-row ds-items-center" style={{ gap: 'var(--space-2)' }}>
                        <Terminal size={14} style={{ color: 'var(--color-danger)' }} />
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-danger)' }}>{proc}</span>
                      </div>
                    }
                    metadata={[
                      alert.device_name || 'Workstation',
                      alert.created_at ? new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Just now'
                    ]}
                    badge={<Badge variant={severityVariant}>{alert.severity || 'high'}</Badge>}
                    onClick={() => navigate('/alerts')}
                  />
                );
              })}
            </div>
          )}
        </SectionCard>
      </div>

      {/* Labs Online Strip */}
      {onlineDevices.length > 0 && (
        <SectionCard 
          title="Labs online" 
        >
          <div className="ds-flex-row ds-items-center" style={{ gap: '12px', flexWrap: 'wrap', padding: '16px 20px' }}>
            {Array.from(new Set(onlineDevices.map((d: any) => d.building))).map((building: any, idx: number) => {
              const devicesInBuilding = devices.filter((d: any) => d.building === building);
              const onlineInBuilding = devicesInBuilding.filter((d: any) => d.status === 'online');
              
              return (
                <div
                  key={building || idx}
                  className="ds-flex-row ds-items-center"
                  style={{ 
                    padding: '6px 14px',
                    borderRadius: '24px',
                    backgroundColor: '#F7F4EF',
                    color: 'var(--color-text-primary)',
                    fontSize: '13px',
                    fontWeight: '500',
                    gap: '8px'
                  }}
                >
                  <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'var(--color-success)', flexShrink: 0 }} />
                  <span>
                    {building || 'Unknown Lab'} &middot; {onlineInBuilding.length}/{devicesInBuilding.length} online
                  </span>
                </div>
              );
            })}
          </div>
        </SectionCard>
      )}
    </div>
  );
}
