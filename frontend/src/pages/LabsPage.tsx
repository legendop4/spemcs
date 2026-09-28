import React, { useState, useEffect, type FormEvent } from 'react';
import { useApp } from '@/context/AppContext';
import { PageHeader } from '@/components/ui/PageHeader';
import { Button } from '@/components/ui/Button';
import { Modal } from '@/components/ui/Modal';
import { EmptyState } from '@/components/ui/EmptyState';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import {
  Building2,
  Plus,
  Monitor,
  CheckCircle2,
  XCircle,
  Edit2,
  Trash2,
  UserCheck,
  Shield,
  Search,
  Wifi,
  WifiOff,
} from 'lucide-react';
import * as api from '@/services/api';

interface LabItem {
  lab_id: string;
  building_id: string;
  lab_name: string;
  description?: string | null;
  capacity: number;
  spemcs_enabled: boolean;
  status: string;
  created_at?: string | null;
}

interface DeviceItem {
  device_id: string;
  device_name: string;
  hardware_uuid?: string | null;
  building_name?: string | null;
  lab_name?: string | null;
  pc_number?: string | null;
  registered_ip?: string | null;
  status: string;
  last_seen?: string | null;
}

export function LabsPage() {
  const { showToast, currentUser } = useApp();
  const isAdmin = currentUser?.role === 'admin';

  const [labs, setLabs] = useState<LabItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  // Create / Edit Lab Modal
  const [labModalOpen, setLabModalOpen] = useState(false);
  const [editingLab, setEditingLab] = useState<LabItem | null>(null);
  const [labForm, setLabForm] = useState({
    building_id: '',
    lab_name: '',
    description: '',
    capacity: 30,
    spemcs_enabled: true,
  });
  const [savingLab, setSavingLab] = useState(false);

  // View Devices Modal
  const [viewDevicesModalOpen, setViewDevicesModalOpen] = useState(false);
  const [selectedLab, setSelectedLab] = useState<LabItem | null>(null);
  const [labDevices, setLabDevices] = useState<DeviceItem[]>([]);
  const [loadingLabDevices, setLoadingLabDevices] = useState(false);

  // Assign Devices Modal
  const [assignModalOpen, setAssignModalOpen] = useState(false);
  const [allDevices, setAllDevices] = useState<DeviceItem[]>([]);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<Set<string>>(new Set());
  const [deviceSearch, setDeviceSearch] = useState('');
  const [savingAssignments, setSavingAssignments] = useState(false);

  // Delete Confirm Dialog
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [labToDelete, setLabToDelete] = useState<LabItem | null>(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    loadLabs();
  }, []);

  const loadLabs = async () => {
    try {
      setLoading(true);
      const data = await api.getLabs();
      setLabs(data || []);
    } catch (err: any) {
      showToast(err.message || 'Failed to load labs', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenCreate = () => {
    setEditingLab(null);
    setLabForm({
      building_id: '',
      lab_name: '',
      description: '',
      capacity: 30,
      spemcs_enabled: true,
    });
    setLabModalOpen(true);
  };

  const handleOpenEdit = (lab: LabItem) => {
    setEditingLab(lab);
    setLabForm({
      building_id: lab.building_id,
      lab_name: lab.lab_name,
      description: lab.description || '',
      capacity: lab.capacity,
      spemcs_enabled: lab.spemcs_enabled,
    });
    setLabModalOpen(true);
  };

  const handleSaveLab = async (e: FormEvent) => {
    e.preventDefault();
    if (!labForm.building_id.trim() || !labForm.lab_name.trim()) {
      showToast('Building ID and Lab Name are required', 'error');
      return;
    }

    try {
      setSavingLab(true);
      if (editingLab) {
        await api.updateLab(editingLab.lab_id, {
          building_id: labForm.building_id.trim(),
          lab_name: labForm.lab_name.trim(),
          description: labForm.description.trim() || null,
          capacity: Number(labForm.capacity),
          spemcs_enabled: labForm.spemcs_enabled,
        });
        showToast(`Lab '${labForm.lab_name}' updated successfully`, 'info');
      } else {
        await api.createLab({
          building_id: labForm.building_id.trim(),
          lab_name: labForm.lab_name.trim(),
          description: labForm.description.trim() || null,
          capacity: Number(labForm.capacity),
          spemcs_enabled: labForm.spemcs_enabled,
        });
        showToast(`Lab '${labForm.lab_name}' created successfully`, 'info');
      }
      setLabModalOpen(false);
      loadLabs();
    } catch (err: any) {
      showToast(err.message || 'Failed to save lab', 'error');
    } finally {
      setSavingLab(false);
    }
  };

  const handleToggleSpemcs = async (lab: LabItem) => {
    try {
      const nextState = !lab.spemcs_enabled;
      await api.setLabSpemcs(lab.lab_id, nextState);
      setLabs(prev => prev.map(l => l.lab_id === lab.lab_id ? { ...l, spemcs_enabled: nextState } : l));
      showToast(`SPEMCS enforcement ${nextState ? 'enabled' : 'disabled'} for ${lab.lab_name}`, 'info');
    } catch (err: any) {
      showToast(err.message || 'Failed to update lab enforcement state', 'error');
    }
  };

  const handleOpenViewDevices = async (lab: LabItem) => {
    setSelectedLab(lab);
    setViewDevicesModalOpen(true);
    try {
      setLoadingLabDevices(true);
      const devices = await api.getLabDevices(lab.lab_id);
      setLabDevices(devices || []);
    } catch (err: any) {
      showToast(err.message || 'Failed to load workstations for lab', 'error');
    } finally {
      setLoadingLabDevices(false);
    }
  };

  const handleOpenAssignDevices = async (lab: LabItem) => {
    setSelectedLab(lab);
    setDeviceSearch('');
    setAssignModalOpen(true);
    try {
      const [allDevs, currentLabDevs] = await Promise.all([
        api.getDevices(),
        api.getLabDevices(lab.lab_id),
      ]);
      setAllDevices(allDevs || []);
      const currentIds = new Set<string>((currentLabDevs || []).map((d: any) => String(d.device_id)));
      setSelectedDeviceIds(currentIds);
    } catch (err: any) {
      showToast(err.message || 'Failed to load workstations', 'error');
    }
  };

  const handleToggleSelectDevice = (deviceId: string) => {
    setSelectedDeviceIds(prev => {
      const next = new Set(prev);
      if (next.has(deviceId)) {
        next.delete(deviceId);
      } else {
        next.add(deviceId);
      }
      return next;
    });
  };

  const handleSaveAssignments = async () => {
    if (!selectedLab) return;
    try {
      setSavingAssignments(true);
      await api.assignLabDevices(selectedLab.lab_id, Array.from(selectedDeviceIds));
      showToast(`Updated workstation assignments for ${selectedLab.lab_name}`, 'info');
      setAssignModalOpen(false);
      loadLabs();
      if (viewDevicesModalOpen) {
        handleOpenViewDevices(selectedLab);
      }
    } catch (err: any) {
      showToast(err.message || 'Failed to save workstation assignments', 'error');
    } finally {
      setSavingAssignments(false);
    }
  };

  const handleRemoveDevice = async (deviceId: string) => {
    if (!selectedLab) return;
    try {
      await api.removeLabDevice(selectedLab.lab_id, deviceId);
      setLabDevices(prev => prev.filter(d => d.device_id !== deviceId));
      showToast('Workstation removed from lab', 'info');
      loadLabs();
    } catch (err: any) {
      showToast(err.message || 'Failed to remove workstation', 'error');
    }
  };

  const handleDeleteLab = async () => {
    if (!labToDelete) return;
    try {
      setDeleting(true);
      await api.deleteLab(labToDelete.lab_id);
      showToast(`Lab '${labToDelete.lab_name}' deleted successfully`, 'info');
      setDeleteConfirmOpen(false);
      setLabToDelete(null);
      loadLabs();
    } catch (err: any) {
      showToast(err.message || 'Failed to delete lab', 'error');
    } finally {
      setDeleting(false);
    }
  };

  const filteredLabs = labs.filter(lab => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      lab.lab_name.toLowerCase().includes(q) ||
      lab.building_id.toLowerCase().includes(q) ||
      (lab.description || '').toLowerCase().includes(q)
    );
  });

  return (
    <div className="page-container" style={{ padding: '32px', backgroundColor: 'var(--color-bg)', minHeight: '100%', fontFamily: 'Inter, system-ui, sans-serif' }}>
      
      {/* Header */}
      <div className="ds-flex-row ds-justify-between ds-items-center" style={{ marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-warning)', letterSpacing: '0.5px', textTransform: 'uppercase' }}>
            INFRASTRUCTURE CONFIGURATION
          </div>
          <h1 style={{ fontSize: '24px', fontWeight: 500, color: 'var(--color-text-primary)', margin: '4px 0 0 0' }}>
            Computer Labs & Rooms
          </h1>
          <p style={{ fontSize: '14px', color: 'var(--color-text-muted)', margin: '4px 0 0 0' }}>
            Manage exam locations, enforce lockdown policies, and assign workstations to rooms.
          </p>
        </div>
        {isAdmin && (
          <Button variant="primary" onClick={handleOpenCreate} icon={<Plus size={16} />}>
            Create Lab
          </Button>
        )}
      </div>

      {/* Search Bar */}
      <div style={{ marginBottom: '24px', position: 'relative', maxWidth: '400px' }}>
        <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
        <input
          type="text"
          placeholder="Search labs by name, building, description..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: '100%', padding: '10px 16px 10px 36px', borderRadius: '8px', border: '1px solid rgba(0,0,0,0.08)', backgroundColor: '#ffffff', fontSize: '14px', outline: 'none' }}
        />
      </div>

      {/* Labs List */}
      {loading ? (
        <div style={{ color: 'var(--color-text-muted)', padding: '24px' }}>Loading labs and rooms...</div>
      ) : filteredLabs.length === 0 ? (
        <EmptyState
          icon={<Building2 size={48} />}
          title="No Labs Configured"
          description={search ? "No labs match your search query." : "No examination computer labs have been registered yet. Click 'Create Lab' to register a new lab."}
          action={isAdmin && !search ? (
            <Button variant="primary" onClick={handleOpenCreate} icon={<Plus size={16} />}>
              Create Lab
            </Button>
          ) : undefined}
        />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '20px' }}>
          {filteredLabs.map((lab) => (
            <div
              key={lab.lab_id}
              style={{
                backgroundColor: '#ffffff',
                borderRadius: '12px',
                border: '1px solid rgba(0,0,0,0.06)',
                padding: '24px',
                display: 'flex',
                flexDirection: 'column',
                boxShadow: '0 1px 3px rgba(0,0,0,0.02)',
              }}
            >
              <div className="ds-flex-row ds-justify-between ds-items-start" style={{ marginBottom: '12px' }}>
                <div>
                  <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    {lab.building_id}
                  </div>
                  <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    {lab.lab_name}
                  </div>
                </div>
                <div
                  style={{
                    backgroundColor: lab.spemcs_enabled ? 'var(--color-success-bg)' : 'var(--color-gray-bg)',
                    color: lab.spemcs_enabled ? 'var(--color-success)' : 'var(--color-text-muted)',
                    padding: '4px 10px',
                    borderRadius: '16px',
                    fontSize: '11px',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  <Shield size={12} />
                  {lab.spemcs_enabled ? 'Enforced' : 'Unmonitored'}
                </div>
              </div>

              {lab.description && (
                <div style={{ fontSize: '13px', color: 'var(--color-text-muted)', marginBottom: '16px', lineHeight: '1.4' }}>
                  {lab.description}
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', padding: '12px', backgroundColor: 'var(--color-bg)', borderRadius: '8px', marginBottom: '20px' }}>
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>SEAT CAPACITY</div>
                  <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>{lab.capacity} seats</div>
                </div>
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>STATUS</div>
                  <div style={{ fontSize: '16px', fontWeight: 600, color: lab.status === 'active' ? 'var(--color-success)' : 'var(--color-text-muted)', textTransform: 'capitalize' }}>
                    {lab.status}
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="ds-flex-row ds-justify-between ds-items-center" style={{ marginTop: 'auto', paddingTop: '16px', borderTop: '1px solid rgba(0,0,0,0.06)', flexWrap: 'wrap', gap: '8px' }}>
                <div className="ds-flex-row" style={{ gap: '8px' }}>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleOpenViewDevices(lab)}
                    icon={<Monitor size={14} />}
                  >
                    View Seats
                  </Button>
                  {isAdmin && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleOpenAssignDevices(lab)}
                      icon={<UserCheck size={14} />}
                    >
                      Assign Seats
                    </Button>
                  )}
                </div>

                <div className="ds-flex-row" style={{ gap: '6px' }}>
                  {isAdmin && (
                    <>
                      <button
                        title={lab.spemcs_enabled ? "Disable SPEMCS Enforcement" : "Enable SPEMCS Enforcement"}
                        onClick={() => handleToggleSpemcs(lab)}
                        style={{
                          background: 'none',
                          border: 'none',
                          cursor: 'pointer',
                          padding: '6px',
                          borderRadius: '6px',
                          color: lab.spemcs_enabled ? 'var(--color-success)' : 'var(--color-text-muted)',
                        }}
                      >
                        {lab.spemcs_enabled ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                      </button>
                      <button
                        title="Edit Lab"
                        onClick={() => handleOpenEdit(lab)}
                        style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '6px', borderRadius: '6px', color: 'var(--color-text-primary)' }}
                      >
                        <Edit2 size={16} />
                      </button>
                      <button
                        title="Delete Lab"
                        onClick={() => { setLabToDelete(lab); setDeleteConfirmOpen(true); }}
                        style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '6px', borderRadius: '6px', color: 'var(--color-danger)' }}
                      >
                        <Trash2 size={16} />
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create / Edit Lab Modal */}
      <Modal
        open={labModalOpen}
        onClose={() => setLabModalOpen(false)}
        title={editingLab ? `Edit Lab: ${editingLab.lab_name}` : "Create New Computer Lab"}
      >
        <form onSubmit={handleSaveLab} className="ds-flex-col" style={{ gap: '16px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
              Building / Complex ID *
            </label>
            <input
              type="text"
              placeholder="e.g. Lab201, TechTower, EngineeringBlock"
              value={labForm.building_id}
              onChange={(e) => setLabForm({ ...labForm, building_id: e.target.value })}
              required
              style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
              Lab Name *
            </label>
            <input
              type="text"
              placeholder="e.g. NetworkLab, AILab, SoftwareLab-1"
              value={labForm.lab_name}
              onChange={(e) => setLabForm({ ...labForm, lab_name: e.target.value })}
              required
              style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
              Seat Capacity
            </label>
            <input
              type="number"
              min="1"
              max="1000"
              value={labForm.capacity}
              onChange={(e) => setLabForm({ ...labForm, capacity: parseInt(e.target.value) || 30 })}
              style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
              Description
            </label>
            <textarea
              placeholder="e.g. Primary network examination lab with dual-NIC workstations"
              value={labForm.description}
              onChange={(e) => setLabForm({ ...labForm, description: e.target.value })}
              rows={3}
              style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none', resize: 'vertical' }}
            />
          </div>

          <div className="ds-flex-row ds-items-center" style={{ gap: '10px', marginTop: '4px' }}>
            <input
              type="checkbox"
              id="spemcs_enabled"
              checked={labForm.spemcs_enabled}
              onChange={(e) => setLabForm({ ...labForm, spemcs_enabled: e.target.checked })}
              style={{ width: '16px', height: '16px', cursor: 'pointer' }}
            />
            <label htmlFor="spemcs_enabled" style={{ fontSize: '13px', color: 'var(--color-text-primary)', cursor: 'pointer' }}>
              Enable SPEMCS enforcement monitoring for this lab
            </label>
          </div>

          <div className="ds-flex-row ds-justify-end" style={{ gap: '10px', marginTop: '16px' }}>
            <Button variant="outline" type="button" onClick={() => setLabModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" disabled={savingLab}>
              {savingLab ? 'Saving...' : editingLab ? 'Update Lab' : 'Create Lab'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* View Workstations Modal */}
      <Modal
        open={viewDevicesModalOpen}
        onClose={() => setViewDevicesModalOpen(false)}
        title={`Workstations in ${selectedLab?.lab_name || 'Lab'}`}
      >
        <div className="ds-flex-col" style={{ gap: '16px', maxHeight: '500px', overflowY: 'auto' }}>
          {loadingLabDevices ? (
            <div style={{ color: 'var(--color-text-muted)', padding: '16px' }}>Loading workstations...</div>
          ) : labDevices.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '32px 16px', color: 'var(--color-text-muted)' }}>
              No workstations are currently assigned to this lab. Click "Assign Seats" to allocate workstations.
            </div>
          ) : (
            <div className="ds-flex-col" style={{ gap: '8px' }}>
              {labDevices.map((dev) => (
                <div
                  key={dev.device_id}
                  className="ds-flex-row ds-justify-between ds-items-center"
                  style={{
                    padding: '12px 16px',
                    backgroundColor: '#ffffff',
                    border: '1px solid rgba(0,0,0,0.06)',
                    borderRadius: '8px',
                  }}
                >
                  <div className="ds-flex-col">
                    <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                      {dev.pc_number || dev.device_name}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                      IP: {dev.registered_ip || '127.0.0.1'} &middot; HW: {dev.hardware_uuid || 'N/A'}
                    </div>
                  </div>

                  <div className="ds-flex-row ds-items-center" style={{ gap: '12px' }}>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        fontSize: '11px',
                        fontWeight: 600,
                        color: dev.status === 'online' ? 'var(--color-success)' : 'var(--color-danger)',
                      }}
                    >
                      {dev.status === 'online' ? <Wifi size={14} /> : <WifiOff size={14} />}
                      {dev.status === 'online' ? 'Online' : 'Offline'}
                    </div>

                    {isAdmin && (
                      <button
                        title="Remove workstation from lab"
                        onClick={() => handleRemoveDevice(dev.device_id)}
                        style={{
                          background: 'none',
                          border: 'none',
                          cursor: 'pointer',
                          color: 'var(--color-danger)',
                          padding: '4px',
                        }}
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="ds-flex-row ds-justify-end" style={{ gap: '8px', marginTop: '12px' }}>
            <Button variant="outline" onClick={() => setViewDevicesModalOpen(false)}>
              Close
            </Button>
            {isAdmin && selectedLab && (
              <Button
                variant="primary"
                onClick={() => {
                  setViewDevicesModalOpen(false);
                  handleOpenAssignDevices(selectedLab);
                }}
              >
                Manage Seats
              </Button>
            )}
          </div>
        </div>
      </Modal>

      {/* Assign Workstations Modal */}
      <Modal
        open={assignModalOpen}
        onClose={() => setAssignModalOpen(false)}
        title={`Assign Workstations to ${selectedLab?.lab_name}`}
      >
        <div className="ds-flex-col" style={{ gap: '16px', maxHeight: '550px' }}>
          <div style={{ position: 'relative' }}>
            <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
            <input
              type="text"
              placeholder="Search devices to assign..."
              value={deviceSearch}
              onChange={(e) => setDeviceSearch(e.target.value)}
              style={{ width: '100%', padding: '8px 12px 8px 36px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '13px', outline: 'none' }}
            />
          </div>

          <div style={{ overflowY: 'auto', maxHeight: '350px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {allDevices
              .filter(d => {
                if (!deviceSearch) return true;
                const q = deviceSearch.toLowerCase();
                return (
                  d.device_name.toLowerCase().includes(q) ||
                  (d.pc_number || '').toLowerCase().includes(q) ||
                  (d.registered_ip || '').toLowerCase().includes(q) ||
                  (d.hardware_uuid || '').toLowerCase().includes(q)
                );
              })
              .map((d) => {
                const isSelected = selectedDeviceIds.has(d.device_id);
                return (
                  <div
                    key={d.device_id}
                    onClick={() => handleToggleSelectDevice(d.device_id)}
                    style={{
                      padding: '10px 14px',
                      borderRadius: '6px',
                      border: isSelected ? '1px solid var(--color-warning)' : '1px solid rgba(0,0,0,0.06)',
                      backgroundColor: isSelected ? 'rgba(216, 148, 0, 0.05)' : '#ffffff',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      cursor: 'pointer',
                    }}
                  >
                    <div className="ds-flex-row ds-items-center" style={{ gap: '12px' }}>
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => handleToggleSelectDevice(d.device_id)}
                        style={{ cursor: 'pointer' }}
                      />
                      <div>
                        <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                          {d.pc_number || d.device_name}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                          IP: {d.registered_ip || '127.0.0.1'} {d.lab_name ? `(Currently: ${d.lab_name})` : '(Unassigned)'}
                        </div>
                      </div>
                    </div>

                    <div style={{ fontSize: '11px', color: d.status === 'online' ? 'var(--color-success)' : 'var(--color-text-muted)' }}>
                      {d.status}
                    </div>
                  </div>
                );
              })}
          </div>

          <div className="ds-flex-row ds-justify-between ds-items-center" style={{ marginTop: '12px' }}>
            <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
              {selectedDeviceIds.size} seat(s) selected
            </div>
            <div className="ds-flex-row" style={{ gap: '8px' }}>
              <Button variant="outline" onClick={() => setAssignModalOpen(false)}>
                Cancel
              </Button>
              <Button variant="primary" onClick={handleSaveAssignments} disabled={savingAssignments}>
                {savingAssignments ? 'Saving...' : 'Save Assignments'}
              </Button>
            </div>
          </div>
        </div>
      </Modal>

      {/* Delete Lab Confirmation Dialog */}
      <ConfirmDialog
        open={deleteConfirmOpen}
        onClose={() => setDeleteConfirmOpen(false)}
        onConfirm={handleDeleteLab}
        title="Delete Computer Lab"
        message={`Are you sure you want to delete lab '${labToDelete?.lab_name}'? Workstation assignments to this lab will be unlinked.`}
        confirmLabel={deleting ? "Deleting..." : "Delete Lab"}
        variant="danger"
      />
    </div>
  );
}

export default LabsPage;
