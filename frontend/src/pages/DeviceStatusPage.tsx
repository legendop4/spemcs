import React, { useState, useEffect, useMemo } from 'react';
import { Monitor, Wifi, WifiOff, Search } from 'lucide-react';
import * as api from '@/services/api';
import { wsClient } from '@/services/websocket';
import { EmptyState } from '@/components/ui/EmptyState';

interface DeviceInfo {
  device_id: string;
  device_name: string;
  hardware_uuid: string | null;
  building_name: string | null;
  lab_name: string | null;
  pc_number: string | null;
  registered_ip: string | null;
  status: string;
  last_seen: string | null;
  created_at: string;
  risk_score?: number;
}

function timeAgo(dateString: string | null) {
  if (!dateString) return 'Never';
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffDays > 0) return date.toLocaleDateString();
  if (diffHours > 0) return `${diffHours}h ago`;
  if (diffMins > 0) return `${diffMins}m ago`;
  return 'Just now';
}

export default function DeviceStatusPage() {
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'online' | 'offline'>('all');
  const [search, setSearch] = useState('');

  useEffect(() => {
    loadDevices();
  }, []);

  useEffect(() => {
    if (!wsClient.isConnected) wsClient.connect();
    const off = wsClient.on('DEVICE_STATUS_CHANGE', (msg) => {
      setDevices(prev => prev.map(d =>
        d.hardware_uuid === msg.payload?.hardware_uuid || d.device_name === msg.payload?.device_name
          ? { ...d, status: msg.payload.status, last_seen: msg.payload.timestamp }
          : d
      ));
    });
    return off;
  }, []);

  const loadDevices = async () => {
    try {
      setLoading(true);
      const data = await api.getDevices();
      setDevices(data);
    } catch (err) {
      console.error('Failed to load devices:', err);
    } finally {
      setLoading(false);
    }
  };

  const filtered = devices
    .filter(d => {
      if (filter === 'online') return d.status === 'online';
      if (filter === 'offline') return d.status === 'offline';
      return true;
    })
    .filter(d => {
      if (!search) return true;
      const q = search.toLowerCase();
      return (
        d.device_name.toLowerCase().includes(q) ||
        (d.building_name || '').toLowerCase().includes(q) ||
        (d.lab_name || '').toLowerCase().includes(q) ||
        (d.hardware_uuid || '').toLowerCase().includes(q) ||
        (d.registered_ip || '').toLowerCase().includes(q) ||
        (d.pc_number || '').toLowerCase().includes(q)
      );
    });

  const onlineCount = devices.filter(d => d.status === 'online').length;
  const offlineCount = devices.filter(d => d.status === 'offline').length;

  const groupedByLab = useMemo(() => {
    const groups: Record<string, DeviceInfo[]> = {};
    filtered.forEach(d => {
      const labName = d.lab_name || 'General';
      if (!groups[labName]) groups[labName] = [];
      groups[labName].push(d);
    });
    return groups;
  }, [filtered]);

  return (
    <div className="page-container" style={{ padding: '32px', backgroundColor: 'var(--color-bg)', minHeight: '100%', fontFamily: 'Inter, system-ui, sans-serif' }}>
      
      {/* SUMMARY CARDS */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px', marginBottom: '24px' }}>
        <div style={{ backgroundColor: '#ffffff', borderRadius: '12px', padding: '24px', border: '1px solid rgba(0,0,0,0.06)', display: 'flex', flexDirection: 'column' }}>
          <div style={{ width: '40px', height: '40px', backgroundColor: 'var(--color-warning-bg)', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
            <Monitor size={20} style={{ color: 'var(--color-warning)' }} />
          </div>
          <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', fontWeight: 600, letterSpacing: '0.5px' }}>TOTAL ENDPOINTS</div>
          <div style={{ fontSize: '32px', fontWeight: 500, color: 'var(--color-text-primary)' }}>{devices.length.toString().padStart(2, '0')}</div>
        </div>

        <div style={{ backgroundColor: '#ffffff', borderRadius: '12px', padding: '24px', border: '1px solid rgba(0,0,0,0.06)', display: 'flex', flexDirection: 'column' }}>
          <div style={{ width: '40px', height: '40px', backgroundColor: 'var(--color-success-bg)', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
            <Wifi size={20} style={{ color: 'var(--color-success)' }} />
          </div>
          <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', fontWeight: 600, letterSpacing: '0.5px' }}>ONLINE ACTIVE</div>
          <div style={{ fontSize: '32px', fontWeight: 500, color: 'var(--color-text-primary)' }}>{onlineCount.toString().padStart(2, '0')}</div>
        </div>

        <div style={{ backgroundColor: '#ffffff', borderRadius: '12px', padding: '24px', border: '1px solid rgba(0,0,0,0.06)', display: 'flex', flexDirection: 'column' }}>
          <div style={{ width: '40px', height: '40px', backgroundColor: 'var(--color-danger-bg)', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
            <WifiOff size={20} style={{ color: 'var(--color-danger)' }} />
          </div>
          <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', fontWeight: 600, letterSpacing: '0.5px' }}>OFFLINE / IDLE</div>
          <div style={{ fontSize: '32px', fontWeight: 500, color: 'var(--color-text-primary)' }}>{offlineCount.toString().padStart(2, '0')}</div>
        </div>
      </div>

      {/* FILTER AND SEARCH */}
      <div className="ds-flex-row ds-justify-between ds-items-center" style={{ marginBottom: '32px', flexWrap: 'wrap', gap: '16px' }}>
        <div className="ds-flex-row ds-items-center" style={{ gap: '8px' }}>
          <button 
            onClick={() => setFilter('all')}
            style={{ backgroundColor: filter === 'all' ? 'var(--color-text-primary)' : '#ffffff', color: filter === 'all' ? '#ffffff' : 'var(--color-text-muted)', border: filter === 'all' ? '1px solid transparent' : '1px solid rgba(0,0,0,0.08)', borderRadius: '24px', padding: '8px 16px', fontSize: '13px', fontWeight: 500, cursor: 'pointer', transition: 'all 0.2s' }}
          >
            All ({devices.length})
          </button>
          <button 
            onClick={() => setFilter('online')}
            style={{ backgroundColor: filter === 'online' ? 'var(--color-text-primary)' : '#ffffff', color: filter === 'online' ? '#ffffff' : 'var(--color-text-muted)', border: filter === 'online' ? '1px solid transparent' : '1px solid rgba(0,0,0,0.08)', borderRadius: '24px', padding: '8px 16px', fontSize: '13px', fontWeight: 500, cursor: 'pointer', transition: 'all 0.2s' }}
          >
            Online ({onlineCount})
          </button>
          <button 
            onClick={() => setFilter('offline')}
            style={{ backgroundColor: filter === 'offline' ? 'var(--color-text-primary)' : '#ffffff', color: filter === 'offline' ? '#ffffff' : 'var(--color-text-muted)', border: filter === 'offline' ? '1px solid transparent' : '1px solid rgba(0,0,0,0.08)', borderRadius: '24px', padding: '8px 16px', fontSize: '13px', fontWeight: 500, cursor: 'pointer', transition: 'all 0.2s' }}
          >
            Offline ({offlineCount})
          </button>
        </div>
        <div style={{ position: 'relative' }}>
          <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
          <input 
            type="text" 
            placeholder="Search by device, IP, lab" 
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ width: '320px', padding: '10px 16px 10px 36px', borderRadius: '8px', border: '1px solid rgba(0,0,0,0.08)', backgroundColor: '#ffffff', fontSize: '14px', outline: 'none' }} 
          />
        </div>
      </div>

      {/* DEVICE LIST */}
      {loading ? (
        <div style={{ color: 'var(--color-text-muted)' }}>Loading endpoints...</div>
      ) : filtered.length === 0 ? (
        <EmptyState icon={<Monitor size={48} />} title="No Endpoints Found" description="No devices match your current filters." />
      ) : (
        <div className="ds-flex-col" style={{ gap: '32px' }}>
          {Object.entries(groupedByLab).map(([labName, devs]) => (
            <div key={labName} className="ds-flex-col">
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '16px' }}>
                {labName} &middot; {devs.length} ENDPOINT{devs.length !== 1 && 'S'}
              </div>
              
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '20px' }}>
                {devs.map(d => {
                  const isOnline = d.status === 'online';
                  const risk = d.risk_score || 0;
                  
                  let riskBg = 'var(--color-success-bg)';
                  let riskColor = 'var(--color-success)';
                  if (risk >= 60) {
                    riskBg = 'var(--color-danger-bg)';
                    riskColor = 'var(--color-danger)';
                  } else if (risk >= 20) {
                    riskBg = 'var(--color-warning-bg)';
                    riskColor = 'var(--color-warning)';
                  }

                  const borderStyle = risk >= 60 ? '1px solid var(--color-danger)' : '1px solid rgba(0,0,0,0.06)';

                  return (
                    <div key={d.device_id} style={{ backgroundColor: '#ffffff', borderRadius: '12px', padding: '20px', border: borderStyle, display: 'flex', flexDirection: 'column', transition: 'transform 0.2s, box-shadow 0.2s', cursor: 'pointer' }} className="hover:shadow-md hover:-translate-y-1">
                      <div className="ds-flex-row ds-justify-between ds-items-start">
                        <div className="ds-flex-col" style={{ gap: '4px' }}>
                          <div style={{ fontSize: '18px', fontWeight: 500, color: 'var(--color-text-primary)' }}>
                            {d.pc_number || d.device_name}
                          </div>
                          <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>
                            {d.registered_ip || '127.0.0.1'}
                          </div>
                        </div>
                        <div style={{ backgroundColor: isOnline ? 'var(--color-success-bg)' : 'var(--color-gray-bg)', color: isOnline ? 'var(--color-success)' : 'var(--color-text-muted)', padding: '4px 8px', borderRadius: '6px', fontSize: '11px', fontWeight: 500 }}>
                          {isOnline ? 'Online' : 'Offline'}
                        </div>
                      </div>

                      <div style={{ marginTop: '16px' }}>
                        <span style={{ backgroundColor: riskBg, color: riskColor, padding: '4px 10px', borderRadius: '12px', fontSize: '12px', fontWeight: 500 }}>
                          Risk {risk}
                        </span>
                      </div>

                      <div style={{ borderTop: '1px solid rgba(0,0,0,0.06)', marginTop: '20px', paddingTop: '16px', fontSize: '12px', color: 'var(--color-text-muted)' }}>
                        {d.device_name} &middot; {timeAgo(d.last_seen)}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
