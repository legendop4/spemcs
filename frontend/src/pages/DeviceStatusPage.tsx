import React, { useState, useEffect, useMemo, type FormEvent } from 'react';
import { Monitor, Wifi, WifiOff, Search, Plus, Edit2, Trash2, Eye, Shield, Laptop, RefreshCw } from 'lucide-react';
import * as api from '@/services/api';
import { wsClient } from '@/services/websocket';
import { EmptyState } from '@/components/ui/EmptyState';
import { Button } from '@/components/ui/Button';
import { Modal } from '@/components/ui/Modal';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { useApp } from '@/context/AppContext';

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
  const { showToast, currentUser } = useApp();
  const isAdmin = currentUser?.role === 'admin';

  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'online' | 'offline'>('all');
  const [search, setSearch] = useState('');

  // Device Modal (Create / Edit)
  const [deviceModalOpen, setDeviceModalOpen] = useState(false);
  const [editingDevice, setEditingDevice] = useState<DeviceInfo | null>(null);
  const [deviceForm, setDeviceForm] = useState({
    device_name: '',
    hardware_uuid: '',
    registered_ip: '127.0.0.1',
    building_name: 'Lab201',
    lab_name: 'NetworkLab',
    pc_number: 'PC-01',
  });
  const [savingDevice, setSavingDevice] = useState(false);

  // Device Details Modal
  const [detailsModalOpen, setDetailsModalOpen] = useState(false);
  const [inspectedDevice, setInspectedDevice] = useState<DeviceInfo | null>(null);
  const [detailedStatus, setDetailedStatus] = useState<any | null>(null);
  const [loadingDetailedStatus, setLoadingDetailedStatus] = useState(false);

  // Delete Confirm
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deviceToDelete, setDeviceToDelete] = useState<DeviceInfo | null>(null);
  const [deletingDevice, setDeletingDevice] = useState(false);

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
      setDevices(data || []);
    } catch (err) {
      console.error('Failed to load devices:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleOpenCreate = () => {
    setEditingDevice(null);
    setDeviceForm({
      device_name: '',
      hardware_uuid: '',
      registered_ip: '127.0.0.1',
      building_name: 'Lab201',
      lab_name: 'NetworkLab',
      pc_number: 'PC-01',
    });
    setDeviceModalOpen(true);
  };

  const handleOpenEdit = (d: DeviceInfo, e: React.MouseEvent) => {
    e.stopPropagation();
    setEditingDevice(d);
    setDeviceForm({
      device_name: d.device_name,
      hardware_uuid: d.hardware_uuid || '',
      registered_ip: d.registered_ip || '127.0.0.1',
      building_name: d.building_name || '',
      lab_name: d.lab_name || '',
      pc_number: d.pc_number || '',
    });
    setDeviceModalOpen(true);
  };

  const handleOpenDetails = async (d: DeviceInfo) => {
    setInspectedDevice(d);
    setDetailsModalOpen(true);
    try {
      setLoadingDetailedStatus(true);
      const statusData = await api.getDeviceStatus(d.device_id);
      setDetailedStatus(statusData);
    } catch {
      setDetailedStatus(null);
    } finally {
      setLoadingDetailedStatus(false);
    }
  };

  const handleSaveDevice = async (e: FormEvent) => {
    e.preventDefault();
    if (!deviceForm.device_name.trim()) {
      showToast('Device name is required', 'error');
      return;
    }

    try {
      setSavingDevice(true);
      if (editingDevice) {
        await api.updateDevice(editingDevice.device_id, {
          device_name: deviceForm.device_name.trim(),
          hardware_uuid: deviceForm.hardware_uuid.trim() || null,
          registered_ip: deviceForm.registered_ip.trim() || null,
          building_name: deviceForm.building_name.trim() || null,
          lab_name: deviceForm.lab_name.trim() || null,
          pc_number: deviceForm.pc_number.trim() || null,
        });
        showToast(`Workstation '${deviceForm.device_name}' updated`, 'info');
      } else {
        await api.createDevice({
          device_name: deviceForm.device_name.trim(),
          hardware_uuid: deviceForm.hardware_uuid.trim() || null,
          registered_ip: deviceForm.registered_ip.trim() || null,
          building_name: deviceForm.building_name.trim() || null,
          lab_name: deviceForm.lab_name.trim() || null,
          pc_number: deviceForm.pc_number.trim() || null,
        });
        showToast(`Workstation '${deviceForm.device_name}' registered`, 'info');
      }
      setDeviceModalOpen(false);
      loadDevices();
    } catch (err: any) {
      showToast(err.message || 'Failed to save workstation', 'error');
    } finally {
      setSavingDevice(false);
    }
  };

  const handleDeleteDevice = async () => {
    if (!deviceToDelete) return;
    try {
      setDeletingDevice(true);
      await api.deleteDevice(deviceToDelete.device_id);
      showToast(`Workstation '${deviceToDelete.device_name}' deleted`, 'info');
      setDeleteConfirmOpen(false);
      setDeviceToDelete(null);
      loadDevices();
    } catch (err: any) {
      showToast(err.message || 'Failed to delete workstation', 'error');
    } finally {
      setDeletingDevice(false);
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
      
      {/* Header */}
      <div className="ds-flex-row ds-justify-between ds-items-center" style={{ marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-warning)', letterSpacing: '0.5px', textTransform: 'uppercase' }}>
            WORKSTATION FLEET
          </div>
          <h1 style={{ fontSize: '24px', fontWeight: 500, color: 'var(--color-text-primary)', margin: '4px 0 0 0' }}>
            Workstations & Endpoints
          </h1>
          <p style={{ fontSize: '14px', color: 'var(--color-text-muted)', margin: '4px 0 0 0' }}>
            Live status, hardware identifiers, and active exam enforcement across candidate seats.
          </p>
        </div>
        {isAdmin && (
          <Button variant="primary" onClick={handleOpenCreate} icon={<Plus size={16} />}>
            Register Workstation
          </Button>
        )}
      </div>

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
              
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '20px' }}>
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
                    <div
                      key={d.device_id}
                      onClick={() => handleOpenDetails(d)}
                      style={{
                        backgroundColor: '#ffffff',
                        borderRadius: '12px',
                        padding: '20px',
                        border: borderStyle,
                        display: 'flex',
                        flexDirection: 'column',
                        transition: 'transform 0.2s, box-shadow 0.2s',
                        cursor: 'pointer',
                      }}
                      className="hover:shadow-md hover:-translate-y-1"
                    >
                      <div className="ds-flex-row ds-justify-between ds-items-start">
                        <div className="ds-flex-col" style={{ gap: '4px' }}>
                          <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
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

                      <div className="ds-flex-row ds-items-center" style={{ gap: '8px', marginTop: '16px' }}>
                        <span style={{ backgroundColor: riskBg, color: riskColor, padding: '4px 10px', borderRadius: '12px', fontSize: '12px', fontWeight: 500 }}>
                          Risk {risk}
                        </span>
                        {d.hardware_uuid && (
                          <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'monospace' }}>
                            {d.hardware_uuid.length > 16 ? d.hardware_uuid.slice(0, 16) + '...' : d.hardware_uuid}
                          </span>
                        )}
                      </div>

                      <div className="ds-flex-row ds-justify-between ds-items-center" style={{ borderTop: '1px solid rgba(0,0,0,0.06)', marginTop: '20px', paddingTop: '14px', fontSize: '12px', color: 'var(--color-text-muted)' }}>
                        <div>
                          {timeAgo(d.last_seen)}
                        </div>
                        {isAdmin && (
                          <div className="ds-flex-row" style={{ gap: '6px' }} onClick={e => e.stopPropagation()}>
                            <button
                              title="Edit Workstation"
                              onClick={(e) => handleOpenEdit(d, e)}
                              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px', color: 'var(--color-text-primary)' }}
                            >
                              <Edit2 size={14} />
                            </button>
                            <button
                              title="Delete Workstation"
                              onClick={(e) => { e.stopPropagation(); setDeviceToDelete(d); setDeleteConfirmOpen(true); }}
                              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px', color: 'var(--color-danger)' }}
                            >
                              <Trash2 size={14} />
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create / Edit Workstation Modal */}
      <Modal
        open={deviceModalOpen}
        onClose={() => setDeviceModalOpen(false)}
        title={editingDevice ? `Edit Workstation: ${editingDevice.device_name}` : "Register Workstation"}
      >
        <form onSubmit={handleSaveDevice} className="ds-flex-col" style={{ gap: '16px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
              Device Name *
            </label>
            <input
              type="text"
              placeholder="e.g. Lab201-NetworkLab-PC2558"
              value={deviceForm.device_name}
              onChange={(e) => setDeviceForm({ ...deviceForm, device_name: e.target.value })}
              required
              style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
              Hardware UUID
            </label>
            <input
              type="text"
              placeholder="WMI UUID from endpoint"
              value={deviceForm.hardware_uuid}
              onChange={(e) => setDeviceForm({ ...deviceForm, hardware_uuid: e.target.value })}
              style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                IP Address
              </label>
              <input
                type="text"
                placeholder="e.g. 192.168.11.50"
                value={deviceForm.registered_ip}
                onChange={(e) => setDeviceForm({ ...deviceForm, registered_ip: e.target.value })}
                style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                PC Number / Label
              </label>
              <input
                type="text"
                placeholder="e.g. PC-2558"
                value={deviceForm.pc_number}
                onChange={(e) => setDeviceForm({ ...deviceForm, pc_number: e.target.value })}
                style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                Building
              </label>
              <input
                type="text"
                placeholder="e.g. Lab201"
                value={deviceForm.building_name}
                onChange={(e) => setDeviceForm({ ...deviceForm, building_name: e.target.value })}
                style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                Lab Name
              </label>
              <input
                type="text"
                placeholder="e.g. NetworkLab"
                value={deviceForm.lab_name}
                onChange={(e) => setDeviceForm({ ...deviceForm, lab_name: e.target.value })}
                style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
              />
            </div>
          </div>

          <div className="ds-flex-row ds-justify-end" style={{ gap: '10px', marginTop: '16px' }}>
            <Button variant="outline" type="button" onClick={() => setDeviceModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" disabled={savingDevice}>
              {savingDevice ? 'Saving...' : editingDevice ? 'Update Workstation' : 'Register Workstation'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Workstation Details Modal */}
      <Modal
        open={detailsModalOpen}
        onClose={() => setDetailsModalOpen(false)}
        title={inspectedDevice?.pc_number || inspectedDevice?.device_name || 'Workstation Details'}
      >
        <div className="ds-flex-col" style={{ gap: '16px' }}>
          {inspectedDevice && (
            <div className="ds-flex-col" style={{ gap: '12px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div style={{ backgroundColor: 'var(--color-bg)', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>DEVICE ID</div>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-primary)', wordBreak: 'break-all' }}>
                    {inspectedDevice.device_id}
                  </div>
                </div>

                <div style={{ backgroundColor: 'var(--color-bg)', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>HARDWARE UUID</div>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-primary)', wordBreak: 'break-all' }}>
                    {inspectedDevice.hardware_uuid || 'N/A'}
                  </div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
                <div style={{ backgroundColor: 'var(--color-bg)', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>REGISTERED IP</div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    {inspectedDevice.registered_ip || '127.0.0.1'}
                  </div>
                </div>

                <div style={{ backgroundColor: 'var(--color-bg)', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>BUILDING / LAB</div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    {inspectedDevice.building_name || 'Lab'} : {inspectedDevice.lab_name || 'General'}
                  </div>
                </div>

                <div style={{ backgroundColor: 'var(--color-bg)', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>STATUS</div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: inspectedDevice.status === 'online' ? 'var(--color-success)' : 'var(--color-danger)' }}>
                    {inspectedDevice.status.toUpperCase()}
                  </div>
                </div>
              </div>

              {loadingDetailedStatus ? (
                <div style={{ color: 'var(--color-text-muted)', padding: '12px' }}>Loading active exam status...</div>
              ) : detailedStatus?.active_exam ? (
                <div style={{ backgroundColor: 'var(--color-warning-bg)', border: '1px solid rgba(216, 148, 0, 0.2)', padding: '16px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-warning)' }}>ACTIVE EXAM ASSIGNMENT</div>
                  <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)', marginTop: '4px' }}>
                    {detailedStatus.active_exam.exam_name}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
                    Status: {detailedStatus.active_exam.status} &middot; Exam ID: {detailedStatus.active_exam.exam_id}
                  </div>
                </div>
              ) : (
                <div style={{ padding: '12px', backgroundColor: 'var(--color-bg)', borderRadius: '8px', fontSize: '13px', color: 'var(--color-text-muted)' }}>
                  No active examination currently assigned to this workstation.
                </div>
              )}
            </div>
          )}

          <div className="ds-flex-row ds-justify-end" style={{ marginTop: '8px' }}>
            <Button variant="outline" onClick={() => setDetailsModalOpen(false)}>
              Close
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={deleteConfirmOpen}
        onClose={() => setDeleteConfirmOpen(false)}
        onConfirm={handleDeleteDevice}
        title="Delete Workstation"
        message={`Are you sure you want to delete workstation '${deviceToDelete?.device_name}'?`}
        confirmLabel={deletingDevice ? "Deleting..." : "Delete Workstation"}
        variant="danger"
      />
    </div>
  );
}
