/**
 * LiveMonitorPage - Real-time exam monitoring with device tile grid.
 * Subscribes to exam room via WebSocket for live updates.
 */
import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, RefreshCw, Users, AlertTriangle, Monitor, Filter, Clock, ExternalLink } from 'lucide-react';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { StatCard } from '@/components/ui/StatCard';
import { DeviceTile } from '@/components/ui/DeviceTile';
import { Skeleton } from '@/components/ui/Skeleton';
import { wsClient } from '@/services/websocket';
import * as api from '@/services/api';

interface ExamDevice {
  device_id: string;
  device_name: string;
  hardware_uuid: string;
  device_status: string;
  exam_device_status: string;
  building_name?: string;
  lab_name?: string;
  pc_number?: string;
}

interface LiveAlert {
  alert_id: string;
  device_id: string;
  device_name: string;
  severity: string;
  message: string;
  event_type: string;
  student_roll_number?: string;
  timestamp: string;
}

interface SessionInfo {
  session_id: string;
  device_id: string;
  student_roll_number: string;
  status: string;
}

export default function LiveMonitorPage() {
  const { id: examId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [exam, setExam] = useState<any>(null);
  const [devices, setDevices] = useState<ExamDevice[]>([]);
  const [alerts, setAlerts] = useState<LiveAlert[]>([]);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('all');

  // Fetch initial data
  const loadData = useCallback(async () => {
    if (!examId) return;
    try {
      setLoading(true);
      const [examData, devData, alertData, sessionData] = await Promise.all([
        api.getExam(examId),
        api.getExamDevices(examId),
        api.getExamAlerts(examId),
        api.getExamSessions(examId),
      ]);
      setExam(examData);
      setDevices(devData);
      setAlerts(alertData);
      setSessions(sessionData);
    } catch (err) {
      console.error('Failed to load exam data:', err);
    } finally {
      setLoading(false);
    }
  }, [examId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Subscribe to exam WebSocket room
  useEffect(() => {
    if (!examId) return;

    if (!wsClient.isConnected) {
      wsClient.connect();
    }
    wsClient.subscribeExam(examId);

    const offAlert = wsClient.on('VIOLATION_ALERT', (msg) => {
      if (msg.payload?.exam_id === examId) {
        setAlerts(prev => [msg.payload, ...prev]);
      }
    });

    const offSession = wsClient.on('SESSION_STARTED', (msg) => {
      if (msg.payload?.exam_id === examId) {
        setSessions(prev => [msg.payload, ...prev]);
      }
    });

    const offDevice = wsClient.on('DEVICE_STATUS_CHANGE', (msg) => {
      setDevices(prev => prev.map(d =>
        d.hardware_uuid === msg.payload?.hardware_uuid
          ? { ...d, device_status: msg.payload.status }
          : d
      ));
    });

    return () => {
      offAlert();
      offSession();
      offDevice();
      wsClient.unsubscribeExam(examId);
    };
  }, [examId]);

  // Build device status map
  const getDeviceStatus = (device: ExamDevice): 'violation' | 'monitoring' | 'offline' | 'pending' | 'compliant' => {
    const hasAlert = alerts.some(a => a.device_id === device.device_id);
    if (hasAlert) return 'violation';
    if (device.device_status === 'offline') return 'offline';
    if (device.exam_device_status === 'monitoring') return 'monitoring';
    if (device.exam_device_status === 'compliant') return 'compliant';
    return 'pending';
  };

  const getDeviceSession = (deviceId: string) =>
    sessions.find(s => s.device_id === deviceId && s.status === 'active');

  const getDeviceLatestAlert = (deviceId: string) =>
    alerts.find(a => a.device_id === deviceId);

  // Filter devices
  const filteredDevices = filter === 'all'
    ? devices
    : devices.filter(d => getDeviceStatus(d) === filter);

  // Stats
  const violationCount = devices.filter(d => alerts.some(a => a.device_id === d.device_id)).length;
  const onlineCount = devices.filter(d => d.device_status === 'online').length;
  const sessionCount = sessions.filter(s => s.status === 'active').length;

  if (loading) {
    return (
      <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <Skeleton className="h-8 w-64" />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '16px' }}>
          {[...Array(8)].map((_, i) => <Skeleton key={i} className="h-40" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Button variant="secondary" size="sm" onClick={() => navigate('/exam-shield')}>
            <ArrowLeft size={16} /> Back
          </Button>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text)' }}>
                {exam?.exam_name || 'Live Exam Proctoring'}
              </h1>
              <Badge variant={exam?.status === 'active' ? 'green' : 'gray'} dot={true}>
                {exam?.status?.toUpperCase() || 'UNKNOWN'}
              </Badge>
            </div>
            {exam?.exam_link && (
              <span style={{ fontSize: '12px', color: 'var(--accent)', display: 'inline-flex', alignItems: 'center', gap: '4px', marginTop: '2px' }}>
                <ExternalLink size={12} /> {exam.exam_link}
              </span>
            )}
          </div>
        </div>
        <Button variant="secondary" size="sm" onClick={loadData}>
          <RefreshCw size={14} /> Refresh Grid
        </Button>
      </div>

      {/* KPI Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
        <StatCard icon={Monitor} title="Total Assigned" value={devices.length} color="blue" />
        <StatCard icon={Users} title="Active Students" value={sessionCount} color="green" />
        <StatCard icon={AlertTriangle} title="Security Violations" value={violationCount} color="red" />
        <StatCard icon={Monitor} title="Online Devices" value={onlineCount} color="amber" />
      </div>

      {/* Filter Tabs */}
      <div className="filter-chips">
        {['all', 'violation', 'monitoring', 'pending', 'offline'].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`filter-chip ${filter === f ? 'active' : ''}`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
      </div>

      {/* Device Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '16px' }}>
        {filteredDevices.map(device => {
          const session = getDeviceSession(device.device_id);
          const latestAlert = getDeviceLatestAlert(device.device_id);
          return (
            <DeviceTile
              key={device.device_id}
              deviceName={device.device_name}
              deviceId={device.device_id}
              hardwareUuid={device.hardware_uuid}
              studentRollNumber={session?.student_roll_number}
              status={getDeviceStatus(device)}
              latestAlert={latestAlert ? {
                type: latestAlert.event_type || 'Alert',
                message: latestAlert.message,
                timestamp: latestAlert.timestamp,
                severity: latestAlert.severity,
              } : undefined}
            />
          );
        })}
      </div>

      {filteredDevices.length === 0 && (
        <div style={{ textAlign: 'center', padding: '48px 20px', color: 'var(--text-3)' }}>
          <Monitor size={40} style={{ margin: '0 auto 12px', opacity: 0.4 }} />
          <p style={{ fontSize: '14px' }}>No devices currently match the "{filter}" filter.</p>
        </div>
      )}
    </div>
  );
}
