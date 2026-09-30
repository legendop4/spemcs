import React, { useState, useEffect } from 'react';
import { useApp } from '@/context/AppContext';
import { Modal } from '@/components/ui/Modal';
import { Button } from '@/components/ui/Button';
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  Server,
  Building2,
  Monitor,
  Key,
  Send,
  Play,
  Wifi,
  WifiOff,
  RefreshCw,
} from 'lucide-react';
import * as api from '@/services/api';

interface ExamWizardModalProps {
  open: boolean;
  onClose: () => void;
  onExamActivated?: (examId: string) => void;
}

export function ExamWizardModal({ open, onClose, onExamActivated }: ExamWizardModalProps) {
  const { showToast, refresh } = useApp();

  const [step, setStep] = useState<number>(1);

  // Step 1: Info
  const [examName, setExamName] = useState('');
  const [examLink, setExamLink] = useState('');
  const [approvedBrowser, setApprovedBrowser] = useState('chrome');

  // Step 2: Lab
  const [labs, setLabs] = useState<any[]>([]);
  const [selectedLabId, setSelectedLabId] = useState<string>('');
  const [loadingLabs, setLoadingLabs] = useState(false);

  // Step 3: Devices / Seats
  const [availableDevices, setAvailableDevices] = useState<any[]>([]);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<Set<string>>(new Set());
  const [loadingDevices, setLoadingDevices] = useState(false);

  // Step 4: Policy & Vendor
  const [networkEnforcement, setNetworkEnforcement] = useState(true);
  const [vendors, setVendors] = useState<any[]>([]);
  const [selectedVendorId, setSelectedVendorId] = useState<string>('');

  // Step 5: Created Exam & Policy
  const [createdExamId, setCreatedExamId] = useState<string | null>(null);
  const [creatingExam, setCreatingExam] = useState(false);
  const [compiledPolicy, setCompiledPolicy] = useState<any | null>(null);
  const [compiling, setCompiling] = useState(false);

  // Step 6: Distribution
  const [distributionProgress, setDistributionProgress] = useState<{ total: number; sent: number; failed: number } | null>(null);
  const [distributing, setDistributing] = useState(false);

  // Step 7: Readiness
  const [readiness, setReadiness] = useState<any | null>(null);
  const [checkingReadiness, setCheckingReadiness] = useState(false);

  // Step 8: Activation
  const [activating, setActivating] = useState(false);
  const [activationResult, setActivationResult] = useState<any | null>(null);

  useEffect(() => {
    if (open) {
      setStep(1);
      setExamName(`Exam-${new Date().toISOString().slice(5, 10)}-${Math.floor(100 + Math.random() * 900)}`);
      setExamLink('https://exam.institution.edu');
      setApprovedBrowser('chrome');
      setNetworkEnforcement(true);
      setCreatedExamId(null);
      setCompiledPolicy(null);
      setReadiness(null);
      setActivationResult(null);

      // Load labs and vendors
      setLoadingLabs(true);
      Promise.all([api.getLabs(), api.getPolicyVendors(), api.getDevices()])
        .then(([labsData, vendorsData, devicesData]) => {
          setLabs(labsData || []);
          if (labsData && labsData.length > 0) {
            setSelectedLabId(labsData[0].lab_id);
          }
          setVendors(vendorsData || []);
          if (vendorsData && vendorsData.length > 0) {
            setSelectedVendorId(vendorsData[0].vendor_id);
          }
          setAvailableDevices(devicesData || []);
        })
        .finally(() => setLoadingLabs(false));
    }
  }, [open]);

  // When lab selection changes, filter devices in that lab
  useEffect(() => {
    if (selectedLabId) {
      setLoadingDevices(true);
      api.getLabDevices(selectedLabId)
        .then((devices: any[]) => {
          if (devices && devices.length > 0) {
            setAvailableDevices(devices);
            // Default selection: strictly only online devices (preserve operator safety)
            const onlineDevs = devices.filter((d: any) => d.status === 'online' || d.device_status === 'online');
            setSelectedDeviceIds(new Set(onlineDevs.map((d: any) => d.device_id)));
          } else {
            // Fallback to all devices
            api.getDevices().then(all => {
              setAvailableDevices(all || []);
              const onlineDevs = (all || []).filter((d: any) => d.status === 'online' || d.device_status === 'online');
              setSelectedDeviceIds(new Set(onlineDevs.map((d: any) => d.device_id)));
            });
          }
        })
        .catch(() => {
          api.getDevices().then(all => setAvailableDevices(all || []));
        })
        .finally(() => setLoadingDevices(false));
    }
  }, [selectedLabId]);

  const handleToggleDevice = (id: string) => {
    setSelectedDeviceIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleSelectOnlineOnly = () => {
    const onlineDevs = availableDevices.filter((d: any) => d.status === 'online' || d.device_status === 'online');
    setSelectedDeviceIds(new Set(onlineDevs.map((d: any) => d.device_id)));
  };

  const handleSelectAllDevices = () => {
    if (selectedDeviceIds.size === availableDevices.length) {
      setSelectedDeviceIds(new Set());
    } else {
      setSelectedDeviceIds(new Set(availableDevices.map(d => d.device_id)));
    }
  };

  // Step 4 -> 5: Create Exam and Compile Policy
  const handleCreateAndCompile = async () => {
    try {
      setCreatingExam(true);
      setCompiling(true);

      // 1. Create exam
      const newExam = await api.createExam({
        exam_name: examName.trim(),
        exam_link: examLink.trim() || null,
        approved_browser: approvedBrowser,
        device_ids: Array.from(selectedDeviceIds),
        network_enforcement: networkEnforcement,
        vendor_profile_id: networkEnforcement && selectedVendorId ? selectedVendorId : null,
      });

      const examId = newExam.exam_id;
      setCreatedExamId(examId);

      // 2. Compile policy if network enforcement enabled
      if (networkEnforcement) {
        let policy: any;
        try {
          policy = await api.getExamPolicy(examId);
        } catch {
          policy = await api.compileExamPolicy(examId, {
            version: 1,
            vendor_profile_id: selectedVendorId || undefined,
          });
        }
        setCompiledPolicy(policy);
      }

      setStep(5);
    } catch (err: any) {
      showToast(err.message || 'Failed creating exam or compiling policy', 'error');
    } finally {
      setCreatingExam(false);
      setCompiling(false);
    }
  };

  // Step 6: Distribute
  const handleDistributePolicy = async () => {
    if (!createdExamId) return;
    try {
      setDistributing(true);
      const devices = await api.getExamDevices(createdExamId);
      const onlineDevs = devices.filter((d: any) => d.device_status === 'online');

      let sent = 0;
      let failed = 0;
      for (const dev of onlineDevs) {
        try {
          await api.distributeExamPolicy(createdExamId, dev.hardware_uuid || dev.device_name);
          sent++;
        } catch {
          failed++;
        }
      }
      setDistributionProgress({ total: onlineDevs.length, sent, failed });
      showToast(`Policy distributed to ${sent}/${onlineDevs.length} workstation(s)`, 'info');

      // Proceed to Step 7
      setStep(7);
      handleCheckReadiness(createdExamId);
    } catch (err: any) {
      showToast(err.message || 'Distribution failed', 'error');
    } finally {
      setDistributing(false);
    }
  };

  // Step 7: Check Readiness
  const handleCheckReadiness = async (examId?: string) => {
    const id = examId || createdExamId;
    if (!id) return;
    try {
      setCheckingReadiness(true);
      const res = await api.getExamEnforcementReadiness(id);
      setReadiness(res);
    } catch (err: any) {
      showToast(err.message || 'Failed checking readiness', 'error');
    } finally {
      setCheckingReadiness(false);
    }
  };

  // Step 8: Activate
  const handleActivateExam = async () => {
    if (!createdExamId) return;
    try {
      setActivating(true);
      const res = await api.activateExam(createdExamId);
      setActivationResult(res);
      showToast('Exam successfully activated and locked down!', 'info');
      refresh();
      if (onExamActivated) {
        onExamActivated(createdExamId);
      }
      setStep(8);
    } catch (err: any) {
      showToast(err.message || 'Activation failed', 'error');
    } finally {
      setActivating(false);
    }
  };

  return (
    <Modal open={open} onClose={onClose} title="Exam Setup & Activation Wizard">
      <div className="ds-flex-col" style={{ gap: '20px', minWidth: '550px', maxWidth: '680px' }}>
        
        {/* Step Indicator */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(8, 1fr)', gap: '4px', borderBottom: '1px solid rgba(0,0,0,0.08)', paddingBottom: '16px' }}>
          {[
            'Details', 'Lab', 'Seats', 'Policy', 'Compile', 'Distribute', 'Readiness', 'Activate'
          ].map((name, idx) => {
            const stepNum = idx + 1;
            const isCurrent = step === stepNum;
            const isCompleted = step > stepNum;
            return (
              <div key={name} style={{ textAlign: 'center' }}>
                <div
                  style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    backgroundColor: isCompleted ? 'var(--color-success)' : isCurrent ? 'var(--color-warning)' : 'var(--color-bg)',
                    color: isCompleted || isCurrent ? '#ffffff' : 'var(--color-text-muted)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '11px',
                    fontWeight: 600,
                    margin: '0 auto 4px auto',
                  }}
                >
                  {isCompleted ? '✓' : stepNum}
                </div>
                <div style={{ fontSize: '10px', color: isCurrent ? 'var(--color-text-primary)' : 'var(--color-text-muted)', fontWeight: isCurrent ? 600 : 400 }}>
                  {name}
                </div>
              </div>
            );
          })}
        </div>

        {/* STEP 1: EXAM DETAILS */}
        {step === 1 && (
          <div className="ds-flex-col" style={{ gap: '16px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Step 1: Examination Details
            </h3>

            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                Exam Title *
              </label>
              <input
                type="text"
                value={examName}
                onChange={(e) => setExamName(e.target.value)}
                placeholder="e.g. CS101-Midterm-Fall2026"
                style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                Exam Portal URL
              </label>
              <input
                type="text"
                value={examLink}
                onChange={(e) => setExamLink(e.target.value)}
                placeholder="https://exam.institution.edu"
                style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                Approved Browser
              </label>
              <select
                value={approvedBrowser}
                onChange={(e) => setApprovedBrowser(e.target.value)}
                style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
              >
                <option value="chrome">Google Chrome (Strict Outbound Process Lockdown)</option>
                <option value="msedge">Microsoft Edge</option>
                <option value="firefox">Mozilla Firefox</option>
              </select>
            </div>

            <div className="ds-flex-row ds-justify-end" style={{ marginTop: '16px' }}>
              <Button
                variant="primary"
                onClick={() => setStep(2)}
                disabled={!examName.trim()}
                icon={<ArrowRight size={16} />}
              >
                Next: Select Lab
              </Button>
            </div>
          </div>
        )}

        {/* STEP 2: SELECT LAB */}
        {step === 2 && (
          <div className="ds-flex-col" style={{ gap: '16px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Step 2: Select Examination Lab
            </h3>
            <p style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>
              Choose the physical computer lab where the examination will take place.
            </p>

            {loadingLabs ? (
              <div style={{ color: 'var(--color-text-muted)' }}>Loading configured labs...</div>
            ) : labs.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', backgroundColor: 'var(--color-bg)', borderRadius: '8px' }}>
                No computer labs configured. You can proceed with all available estate workstations.
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                {labs.map(lab => {
                  const isSelected = selectedLabId === lab.lab_id;
                  return (
                    <div
                      key={lab.lab_id}
                      onClick={() => setSelectedLabId(lab.lab_id)}
                      style={{
                        padding: '16px',
                        borderRadius: '8px',
                        border: isSelected ? '2px solid var(--color-warning)' : '1px solid rgba(0,0,0,0.08)',
                        backgroundColor: isSelected ? 'rgba(216, 148, 0, 0.05)' : '#ffffff',
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>
                        {lab.building_id}
                      </div>
                      <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                        {lab.lab_name}
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', marginTop: '4px' }}>
                        Capacity: {lab.capacity} seats &middot; {lab.spemcs_enabled ? 'Enforced' : 'Unmonitored'}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            <div className="ds-flex-row ds-justify-between" style={{ marginTop: '16px' }}>
              <Button variant="outline" onClick={() => setStep(1)} icon={<ArrowLeft size={16} />}>
                Back
              </Button>
              <Button variant="primary" onClick={() => setStep(3)} icon={<ArrowRight size={16} />}>
                Next: Select Seats
              </Button>
            </div>
          </div>
        )}

        {/* STEP 3: SELECT SEATS */}
        {step === 3 && (
          <div className="ds-flex-col" style={{ gap: '16px' }}>
            <div className="ds-flex-row ds-justify-between ds-items-center">
              <div>
                <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  Step 3: Workstations & Seats Selection
                </h3>
                <p style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>
                  {selectedDeviceIds.size} of {availableDevices.length} workstation(s) selected
                </p>
              </div>
              <div className="ds-flex-row ds-items-center" style={{ gap: '8px' }}>
                <Button variant="outline" size="sm" onClick={handleSelectOnlineOnly}>
                  Select Online Only
                </Button>
                <Button variant="outline" size="sm" onClick={handleSelectAllDevices}>
                  {selectedDeviceIds.size === availableDevices.length ? 'Deselect All' : 'Select All'}
                </Button>
              </div>
            </div>

            {loadingDevices ? (
              <div style={{ color: 'var(--color-text-muted)' }}>Loading workstations...</div>
            ) : availableDevices.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', backgroundColor: 'var(--color-bg)', borderRadius: '8px' }}>
                No workstations found in this lab.
              </div>
            ) : (
              <div style={{ maxHeight: '280px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {availableDevices.map(d => {
                  const isSelected = selectedDeviceIds.has(d.device_id);
                  const isOnline = d.status === 'online' || d.device_status === 'online';
                  return (
                    <div
                      key={d.device_id}
                      onClick={() => handleToggleDevice(d.device_id)}
                      style={{
                        padding: '10px 14px',
                        borderRadius: '6px',
                        border: isSelected ? '1px solid var(--color-warning)' : '1px solid rgba(0,0,0,0.06)',
                        backgroundColor: isSelected ? 'rgba(216, 148, 0, 0.05)' : (!isOnline ? '#fbfbfb' : '#ffffff'),
                        opacity: !isOnline && !isSelected ? 0.75 : 1,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        cursor: 'pointer',
                      }}
                    >
                      <div className="ds-flex-row ds-items-center" style={{ gap: '10px' }}>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => handleToggleDevice(d.device_id)}
                        />
                        <div>
                          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                            {d.pc_number || d.device_name}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                            IP: {d.registered_ip || '127.0.0.1'} &middot; HW: {d.hardware_uuid || 'N/A'}
                          </div>
                        </div>
                      </div>

                      <div className="ds-flex-row ds-items-center" style={{ gap: '8px' }}>
                        {isSelected && !isOnline && (
                          <span style={{ fontSize: '10px', fontWeight: 600, color: 'var(--color-danger)', backgroundColor: 'var(--color-danger-bg, #fde8e8)', padding: '2px 6px', borderRadius: '4px' }}>
                            Offline (Blocks Launch)
                          </span>
                        )}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: isOnline ? 'var(--color-success)' : 'var(--color-text-muted)' }}>
                          {isOnline ? <Wifi size={12} /> : <WifiOff size={12} />}
                          {isOnline ? 'Online' : 'Offline'}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            <div className="ds-flex-row ds-justify-between" style={{ marginTop: '16px' }}>
              <Button variant="outline" onClick={() => setStep(2)} icon={<ArrowLeft size={16} />}>
                Back
              </Button>
              <Button
                variant="primary"
                onClick={() => setStep(4)}
                disabled={selectedDeviceIds.size === 0}
                icon={<ArrowRight size={16} />}
              >
                Next: Policy Configuration
              </Button>
            </div>
          </div>
        )}

        {/* STEP 4: POLICY CONFIGURATION */}
        {step === 4 && (
          <div className="ds-flex-col" style={{ gap: '16px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Step 4: Network Enforcement Policy
            </h3>

            <div style={{ backgroundColor: 'var(--color-bg)', padding: '16px', borderRadius: '8px' }}>
              <div className="ds-flex-row ds-items-center" style={{ gap: '12px' }}>
                <input
                  type="checkbox"
                  id="lockdown_toggle"
                  checked={networkEnforcement}
                  onChange={(e) => setNetworkEnforcement(e.target.checked)}
                  style={{ width: '18px', height: '18px', cursor: 'pointer' }}
                />
                <div>
                  <label htmlFor="lockdown_toggle" style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text-primary)', cursor: 'pointer' }}>
                    Enforce Windows Firewall Network Lockdown
                  </label>
                  <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                    Restricts outbound workstation traffic strictly to the selected testing vendor's endpoints.
                  </div>
                </div>
              </div>
            </div>

            {networkEnforcement && (
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                  Testing Vendor Profile *
                </label>
                <select
                  value={selectedVendorId}
                  onChange={(e) => setSelectedVendorId(e.target.value)}
                  style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
                >
                  <option value="">-- Choose Vendor Profile --</option>
                  {vendors.map(v => (
                    <option key={v.vendor_id} value={v.vendor_id}>
                      {v.vendor_name} ({v.required_domains.join(', ')})
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div className="ds-flex-row ds-justify-between" style={{ marginTop: '16px' }}>
              <Button variant="outline" onClick={() => setStep(3)} icon={<ArrowLeft size={16} />}>
                Back
              </Button>
              <Button
                variant="primary"
                onClick={handleCreateAndCompile}
                disabled={creatingExam || (networkEnforcement && !selectedVendorId)}
                icon={<Key size={16} />}
              >
                {creatingExam ? 'Creating & Compiling...' : 'Create Exam & Compile Policy'}
              </Button>
            </div>
          </div>
        )}

        {/* STEP 5: COMPILE + SIGN RESULT */}
        {step === 5 && (
          <div className="ds-flex-col" style={{ gap: '16px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Step 5: Cryptographic Compilation & Signing
            </h3>

            <div style={{ backgroundColor: 'var(--color-success-bg)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(13, 110, 253, 0.2)' }}>
              <div className="ds-flex-row ds-items-center" style={{ gap: '8px', color: 'var(--color-success)', fontWeight: 600 }}>
                <CheckCircle2 size={18} />
                Signed with Central RSA-PSS Key (SHA-256)
              </div>
              <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', marginTop: '4px' }}>
                Exam ID: {createdExamId} &middot; Policy Version: {compiledPolicy?.version || 1}
              </div>
            </div>

            <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>
              The signed policy bundle has been sealed. The next step is distributing the cryptographic policy to all online assigned workstations before activating the proctoring session.
            </div>

            <div className="ds-flex-row ds-justify-end" style={{ marginTop: '16px' }}>
              <Button
                variant="primary"
                onClick={handleDistributePolicy}
                disabled={distributing}
                icon={<Send size={16} />}
              >
                {distributing ? 'Distributing Policy...' : 'Distribute Policy to Workstations'}
              </Button>
            </div>
          </div>
        )}

        {/* STEP 6: DISTRIBUTION RESULT */}
        {step === 6 && (
          <div className="ds-flex-col" style={{ gap: '16px', textAlign: 'center', padding: '24px' }}>
            <Send size={40} style={{ color: 'var(--color-warning)', margin: '0 auto' }} />
            <div style={{ fontSize: '16px', fontWeight: 600 }}>Distributing Signed Policy...</div>
            <div style={{ color: 'var(--color-text-muted)', fontSize: '13px' }}>
              Transmitting signed JSON envelope via WebSocket to assigned workstations.
            </div>
          </div>
        )}

        {/* STEP 7: READINESS CHECK */}
        {step === 7 && (
          <div className="ds-flex-col" style={{ gap: '16px' }}>
            <div className="ds-flex-row ds-justify-between ds-items-center">
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                Step 7: Pre-Activation Readiness Gate
              </h3>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleCheckReadiness()}
                icon={<RefreshCw size={14} className={checkingReadiness ? 'animate-spin' : ''} />}
              >
                Re-check Gate
              </Button>
            </div>

            {checkingReadiness ? (
              <div style={{ color: 'var(--color-text-muted)', padding: '20px', textAlign: 'center' }}>
                Evaluating workstation enforcement state...
              </div>
            ) : readiness ? (() => {
              const assignedCount = readiness.devices_assigned ?? readiness.total_assigned_devices ?? selectedDeviceIds.size;
              const armedCount = readiness.devices_armed ?? readiness.enforcing_count ?? 0;
              const isReadyToActivate = Boolean(readiness.ready && assignedCount > 0 && armedCount === assignedCount);

              return (
                <div className="ds-flex-col" style={{ gap: '12px' }}>
                  <div
                    style={{
                      padding: '16px',
                      borderRadius: '8px',
                      backgroundColor: isReadyToActivate ? 'var(--color-success-bg)' : 'var(--color-danger-bg)',
                      border: isReadyToActivate ? '1px solid var(--color-success)' : '1px solid var(--color-danger)',
                    }}
                  >
                    <div className="ds-flex-row ds-items-center" style={{ gap: '8px' }}>
                      {isReadyToActivate ? (
                        <CheckCircle2 size={18} style={{ color: 'var(--color-success)' }} />
                      ) : (
                        <XCircle size={18} style={{ color: 'var(--color-danger)' }} />
                      )}
                      <span style={{ fontWeight: 600, color: isReadyToActivate ? 'var(--color-success)' : 'var(--color-danger)' }}>
                        {isReadyToActivate ? 'Exam Ready for Activation' : 'Activation Blocked by Safety Invariants'}
                      </span>
                    </div>

                    {readiness.problems && readiness.problems.length > 0 && (
                      <div style={{ marginTop: '12px', fontSize: '13px', color: 'var(--color-danger)' }}>
                        <strong>Blocking problems:</strong>
                        <ul style={{ margin: '6px 0 0 16px', padding: 0 }}>
                          {readiness.problems.map((p: any, i: number) => (
                            <li key={i}>{p.message || p.code}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {readiness.unarmed_devices && readiness.unarmed_devices.length > 0 && (
                      <div style={{ marginTop: '10px', fontSize: '12px', color: 'var(--color-text-muted)' }}>
                        <strong style={{ color: 'var(--color-danger)' }}>Seats not ready ({readiness.unarmed_devices.length}):</strong>
                        <ul style={{ margin: '4px 0 0 16px', padding: 0 }}>
                          {readiness.unarmed_devices.map((d: any, idx: number) => (
                            <li key={idx}>
                              <strong>{d.device_name || d.hardware_uuid}</strong> — status: <code>{d.status || d.policy_status || 'UNKNOWN'}</code>
                              {d.last_error ? ` (${d.last_error})` : ''}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>

                  <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                    Targeted seats: {assignedCount} &middot; Armed seats: {armedCount}
                  </div>
                </div>
              );
            })() : null}

            <div className="ds-flex-row ds-justify-end" style={{ marginTop: '16px' }}>
              <Button
                variant="primary"
                onClick={handleActivateExam}
                disabled={
                  activating ||
                  !readiness?.ready ||
                  (readiness?.devices_armed ?? readiness?.enforcing_count ?? 0) !== (readiness?.devices_assigned ?? readiness?.total_assigned_devices ?? selectedDeviceIds.size) ||
                  (readiness?.devices_assigned ?? readiness?.total_assigned_devices ?? selectedDeviceIds.size) === 0
                }
                icon={<Play size={16} />}
              >
                {activating ? 'Launching Exam Mode...' : 'Activate & Launch Exam'}
              </Button>
            </div>
          </div>
        )}

        {/* STEP 8: ACTIVATED! */}
        {step === 8 && (
          <div className="ds-flex-col" style={{ gap: '16px', textAlign: 'center', padding: '24px' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '50%', backgroundColor: 'var(--color-success-bg)', color: 'var(--color-success)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto' }}>
              <ShieldCheck size={28} />
            </div>

            <h3 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Exam Mode Active!
            </h3>

            <p style={{ fontSize: '14px', color: 'var(--color-text-muted)', maxWidth: '440px', margin: '0 auto' }}>
              Workstations have entered exam mode. The student pre-compliance and authentication UI is now presenting on candidate screens.
            </p>

            <div className="ds-flex-row ds-justify-center" style={{ gap: '12px', marginTop: '16px' }}>
              <Button variant="outline" onClick={onClose}>
                Back to Dashboard
              </Button>
              {createdExamId && (
                <Button
                  variant="primary"
                  onClick={() => {
                    onClose();
                    window.location.href = `/exam-shield/monitor/${createdExamId}`;
                  }}
                >
                  Open Live Proctor Monitor
                </Button>
              )}
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}

export default ExamWizardModal;
