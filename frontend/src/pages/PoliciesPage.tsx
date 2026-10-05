import React, { useState, useEffect, type FormEvent } from 'react';
import { useApp } from '@/context/AppContext';
import { PageHeader } from '@/components/ui/PageHeader';
import { Button } from '@/components/ui/Button';
import { Modal } from '@/components/ui/Modal';
import { EmptyState } from '@/components/ui/EmptyState';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import {
  FileCode,
  Plus,
  Shield,
  Key,
  Server,
  Globe,
  Network,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Trash2,
  Edit2,
  Send,
  Eye,
  Sliders,
  Laptop,
} from 'lucide-react';
import * as api from '@/services/api';

interface VendorProfile {
  vendor_id: string;
  vendor_name: string;
  required_domains: string[];
  approved_ip_ranges: string[];
  required_tcp_ports: number[];
  required_udp_ports: number[];
  created_at?: string | null;
}

interface DevicePolicyState {
  id: string;
  exam_id: string;
  device_id: string;
  policy_id: string;
  status: string;
  armed: boolean;
  rules_installed: number;
  last_error?: string | null;
  applied_at?: string | null;
  updated_at?: string | null;
  device_name?: string | null;
  hardware_uuid?: string | null;
}

export function PoliciesPage() {
  const { exams, showToast, currentUser } = useApp();
  const isAdmin = currentUser?.role === 'admin';

  const [activeTab, setActiveTab] = useState<'vendors' | 'builder' | 'states'>('vendors');

  // --- Vendors State ---
  const [vendors, setVendors] = useState<VendorProfile[]>([]);
  const [loadingVendors, setLoadingVendors] = useState(true);
  const [vendorModalOpen, setVendorModalOpen] = useState(false);
  const [editingVendor, setEditingVendor] = useState<VendorProfile | null>(null);
  const [vendorForm, setVendorForm] = useState({
    vendor_name: '',
    required_domains: '',
    approved_ip_ranges: '',
    required_tcp_ports: '443',
    required_udp_ports: '',
  });
  const [savingVendor, setSavingVendor] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [vendorToDelete, setVendorToDelete] = useState<VendorProfile | null>(null);
  const [deletingVendor, setDeletingVendor] = useState(false);

  // --- Policy Builder State ---
  const [selectedExamId, setSelectedExamId] = useState<string>('');
  const [selectedVendorId, setSelectedVendorId] = useState<string>('');
  const [approvedBrowser, setApprovedBrowser] = useState<string>('chrome');
  const [policyVersion, setPolicyVersion] = useState<number>(1);
  const [validHours, setValidHours] = useState<number>(8);
  const [compiling, setCompiling] = useState(false);
  const [compiledPolicy, setCompiledPolicy] = useState<any | null>(null);
  const [loadingPolicy, setLoadingPolicy] = useState(false);

  // --- Device Enforcement States ---
  const [stateExamId, setStateExamId] = useState<string>('');
  const [deviceStates, setDeviceStates] = useState<DevicePolicyState[]>([]);
  const [loadingStates, setLoadingStates] = useState(false);
  const [distributingUuid, setDistributingUuid] = useState<string | null>(null);

  useEffect(() => {
    loadVendors();
  }, []);

  useEffect(() => {
    if (exams.length > 0 && !selectedExamId) {
      setSelectedExamId(exams[0].exam_id);
      setStateExamId(exams[0].exam_id);
    }
  }, [exams]);

  useEffect(() => {
    if (selectedExamId) {
      loadCompiledPolicy(selectedExamId);
    }
  }, [selectedExamId]);

  useEffect(() => {
    if (stateExamId) {
      loadDeviceStates(stateExamId);
    }
  }, [stateExamId]);

  const loadVendors = async () => {
    try {
      setLoadingVendors(true);
      const data = await api.getPolicyVendors();
      setVendors(data || []);
      if (data && data.length > 0 && !selectedVendorId) {
        setSelectedVendorId(data[0].vendor_id);
      }
    } catch (err: any) {
      showToast(err.message || 'Failed to load vendor profiles', 'error');
    } finally {
      setLoadingVendors(false);
    }
  };

  const loadCompiledPolicy = async (examId: string) => {
    try {
      setLoadingPolicy(true);
      const policy = await api.getExamPolicy(examId);
      setCompiledPolicy(policy);
    } catch {
      setCompiledPolicy(null);
    } finally {
      setLoadingPolicy(false);
    }
  };

  const loadDeviceStates = async (examId: string) => {
    try {
      setLoadingStates(true);
      const states = await api.getExamDevicePolicyStates(examId);
      setDeviceStates(states || []);
    } catch (err: any) {
      setDeviceStates([]);
    } finally {
      setLoadingStates(false);
    }
  };

  // --- Vendor Actions ---
  const handleOpenCreateVendor = () => {
    setEditingVendor(null);
    setVendorForm({
      vendor_name: '',
      required_domains: 'exam.vendor.com, cdn.vendor.com',
      approved_ip_ranges: '192.168.1.0/24',
      required_tcp_ports: '80, 443',
      required_udp_ports: '',
    });
    setVendorModalOpen(true);
  };

  const handleOpenEditVendor = (v: VendorProfile) => {
    setEditingVendor(v);
    setVendorForm({
      vendor_name: v.vendor_name,
      required_domains: v.required_domains.join(', '),
      approved_ip_ranges: v.approved_ip_ranges.join(', '),
      required_tcp_ports: v.required_tcp_ports.join(', '),
      required_udp_ports: v.required_udp_ports.join(', '),
    });
    setVendorModalOpen(true);
  };

  const handleSaveVendor = async (e: FormEvent) => {
    e.preventDefault();
    if (!vendorForm.vendor_name.trim()) {
      showToast('Vendor name is required', 'error');
      return;
    }

    const domains = vendorForm.required_domains
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    const ipRanges = vendorForm.approved_ip_ranges
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    const tcpPorts = vendorForm.required_tcp_ports
      .split(',')
      .map(s => parseInt(s.trim()))
      .filter(n => !isNaN(n));
    const udpPorts = vendorForm.required_udp_ports
      .split(',')
      .map(s => parseInt(s.trim()))
      .filter(n => !isNaN(n));

    if (domains.length === 0) {
      showToast('At least one required domain must be specified', 'error');
      return;
    }

    try {
      setSavingVendor(true);
      const payload = {
        vendor_name: vendorForm.vendor_name.trim(),
        required_domains: domains,
        approved_ip_ranges: ipRanges,
        required_tcp_ports: tcpPorts.length > 0 ? tcpPorts : [443],
        required_udp_ports: udpPorts,
      };

      if (editingVendor) {
        await api.updatePolicyVendor(editingVendor.vendor_id, payload);
        showToast(`Vendor profile '${payload.vendor_name}' updated`, 'info');
      } else {
        await api.createPolicyVendor(payload);
        showToast(`Vendor profile '${payload.vendor_name}' created`, 'info');
      }
      setVendorModalOpen(false);
      loadVendors();
    } catch (err: any) {
      showToast(err.message || 'Failed to save vendor profile', 'error');
    } finally {
      setSavingVendor(false);
    }
  };

  const handleDeleteVendor = async () => {
    if (!vendorToDelete) return;
    try {
      setDeletingVendor(true);
      await api.deletePolicyVendor(vendorToDelete.vendor_id);
      showToast(`Vendor profile '${vendorToDelete.vendor_name}' deleted`, 'info');
      setDeleteConfirmOpen(false);
      setVendorToDelete(null);
      loadVendors();
    } catch (err: any) {
      showToast(err.message || 'Failed to delete vendor profile', 'error');
    } finally {
      setDeletingVendor(false);
    }
  };

  // --- Policy Builder Actions ---
  const handleCompilePolicy = async () => {
    if (!selectedExamId) {
      showToast('Please select an exam first', 'error');
      return;
    }
    try {
      setCompiling(true);
      const now = new Date();
      const exp = new Date(now.getTime() + validHours * 3600 * 1000);

      const policy = await api.compileExamPolicy(selectedExamId, {
        version: policyVersion,
        vendor_profile_id: selectedVendorId || undefined,
        not_before: now.toISOString(),
        expires_at: exp.toISOString(),
      });
      setCompiledPolicy(policy);
      showToast('Policy successfully compiled and cryptographically signed (RSA-PSS SHA256)!', 'info');
      if (stateExamId === selectedExamId) {
        loadDeviceStates(selectedExamId);
      }
    } catch (err: any) {
      showToast(err.message || 'Policy compilation failed', 'error');
    } finally {
      setCompiling(false);
    }
  };

  const handleDistributeToDevice = async (hardwareUuid: string) => {
    if (!stateExamId) return;
    try {
      setDistributingUuid(hardwareUuid);
      await api.distributeExamPolicy(stateExamId, hardwareUuid);
      showToast(`Policy distributed to endpoint ${hardwareUuid}`, 'info');
      setTimeout(() => loadDeviceStates(stateExamId), 1000);
    } catch (err: any) {
      showToast(err.message || `Failed to distribute policy: ${err}`, 'error');
    } finally {
      setDistributingUuid(null);
    }
  };

  return (
    <div className="page-container" style={{ padding: '32px', backgroundColor: 'var(--color-bg)', minHeight: '100%', fontFamily: 'Inter, system-ui, sans-serif' }}>
      
      {/* Header */}
      <div className="ds-flex-row ds-justify-between ds-items-center" style={{ marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-warning)', letterSpacing: '0.5px', textTransform: 'uppercase' }}>
            FIREWALL POLICY ENGINE
          </div>
          <h1 style={{ fontSize: '24px', fontWeight: 500, color: 'var(--color-text-primary)', margin: '4px 0 0 0' }}>
            Policy & Vendor Management
          </h1>
          <p style={{ fontSize: '14px', color: 'var(--color-text-muted)', margin: '4px 0 0 0' }}>
            Configure examination vendors, compile RSA-PSS signed firewall rules, and audit per-seat enforcement.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="ds-flex-row" style={{ gap: '8px', borderBottom: '1px solid rgba(0,0,0,0.08)', marginBottom: '24px' }}>
        <button
          onClick={() => setActiveTab('vendors')}
          style={{
            padding: '10px 18px',
            fontSize: '14px',
            fontWeight: 500,
            border: 'none',
            borderBottom: activeTab === 'vendors' ? '2px solid var(--color-warning)' : '2px solid transparent',
            backgroundColor: 'transparent',
            color: activeTab === 'vendors' ? 'var(--color-text-primary)' : 'var(--color-text-muted)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Server size={16} />
          Vendor Profiles ({vendors.length})
        </button>

        <button
          onClick={() => setActiveTab('builder')}
          style={{
            padding: '10px 18px',
            fontSize: '14px',
            fontWeight: 500,
            border: 'none',
            borderBottom: activeTab === 'builder' ? '2px solid var(--color-warning)' : '2px solid transparent',
            backgroundColor: 'transparent',
            color: activeTab === 'builder' ? 'var(--color-text-primary)' : 'var(--color-text-muted)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Sliders size={16} />
          Policy Builder & Inspector
        </button>

        <button
          onClick={() => setActiveTab('states')}
          style={{
            padding: '10px 18px',
            fontSize: '14px',
            fontWeight: 500,
            border: 'none',
            borderBottom: activeTab === 'states' ? '2px solid var(--color-warning)' : '2px solid transparent',
            backgroundColor: 'transparent',
            color: activeTab === 'states' ? 'var(--color-text-primary)' : 'var(--color-text-muted)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Laptop size={16} />
          Workstation Enforcement Status
        </button>
      </div>

      {/* TAB 1: VENDOR PROFILES */}
      {activeTab === 'vendors' && (
        <div className="ds-flex-col" style={{ gap: '20px' }}>
          <div className="ds-flex-row ds-justify-between ds-items-center">
            <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Authorized Testing Vendors
            </div>
            {isAdmin && (
              <Button variant="primary" onClick={handleOpenCreateVendor} icon={<Plus size={16} />}>
                Create Vendor Profile
              </Button>
            )}
          </div>

          {loadingVendors ? (
            <div style={{ color: 'var(--color-text-muted)' }}>Loading vendor profiles...</div>
          ) : vendors.length === 0 ? (
            <EmptyState
              icon={<Server size={48} />}
              title="No Vendor Profiles Configured"
              description="Create a vendor profile to whitelist the test provider's hostnames, IP ranges, and required ports."
              action={isAdmin ? (
                <Button variant="primary" onClick={handleOpenCreateVendor} icon={<Plus size={16} />}>
                  Create Vendor Profile
                </Button>
              ) : undefined}
            />
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '20px' }}>
              {vendors.map(v => (
                <div
                  key={v.vendor_id}
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
                  <div className="ds-flex-row ds-justify-between ds-items-start" style={{ marginBottom: '16px' }}>
                    <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                      {v.vendor_name}
                    </div>
                    {isAdmin && (
                      <div className="ds-flex-row" style={{ gap: '4px' }}>
                        <button
                          onClick={() => handleOpenEditVendor(v)}
                          title="Edit Vendor Profile"
                          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px', color: 'var(--color-text-primary)' }}
                        >
                          <Edit2 size={16} />
                        </button>
                        <button
                          onClick={() => { setVendorToDelete(v); setDeleteConfirmOpen(true); }}
                          title="Delete Vendor Profile"
                          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px', color: 'var(--color-danger)' }}
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="ds-flex-col" style={{ gap: '12px', fontSize: '13px' }}>
                    <div>
                      <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: '4px' }}>
                        REQUIRED DOMAINS
                      </div>
                      <div className="ds-flex-row" style={{ gap: '4px', flexWrap: 'wrap' }}>
                        {v.required_domains.map(d => (
                          <span key={d} style={{ backgroundColor: 'var(--color-bg)', padding: '2px 8px', borderRadius: '4px', fontSize: '12px', color: 'var(--color-text-primary)' }}>
                            {d}
                          </span>
                        ))}
                      </div>
                    </div>

                    {v.approved_ip_ranges.length > 0 && (
                      <div>
                        <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: '4px' }}>
                          APPROVED IP RANGES
                        </div>
                        <div className="ds-flex-row" style={{ gap: '4px', flexWrap: 'wrap' }}>
                          {v.approved_ip_ranges.map(ip => (
                            <span key={ip} style={{ backgroundColor: 'var(--color-bg)', padding: '2px 8px', borderRadius: '4px', fontSize: '12px', color: 'var(--color-text-primary)' }}>
                              {ip}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    <div>
                      <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: '4px' }}>
                        ALLOWED PORTS
                      </div>
                      <div style={{ color: 'var(--color-text-primary)' }}>
                        TCP: {v.required_tcp_ports.join(', ')} {v.required_udp_ports.length > 0 ? `| UDP: ${v.required_udp_ports.join(', ')}` : ''}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: POLICY BUILDER & INSPECTOR */}
      {activeTab === 'builder' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(340px, 1fr) 2fr', gap: '24px' }}>
          
          {/* Form Side */}
          <div style={{ backgroundColor: '#ffffff', borderRadius: '12px', padding: '24px', border: '1px solid rgba(0,0,0,0.06)' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
              Policy Compiler Options
            </h2>

            <div className="ds-flex-col" style={{ gap: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                  Target Examination *
                </label>
                <select
                  value={selectedExamId}
                  onChange={(e) => setSelectedExamId(e.target.value)}
                  style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
                >
                  {exams.map((ex: any) => (
                    <option key={ex.exam_id} value={ex.exam_id}>
                      {ex.exam_name} ({ex.status})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                  Vendor Profile *
                </label>
                <select
                  value={selectedVendorId}
                  onChange={(e) => setSelectedVendorId(e.target.value)}
                  style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
                >
                  <option value="">-- Select Vendor Profile --</option>
                  {vendors.map(v => (
                    <option key={v.vendor_id} value={v.vendor_id}>
                      {v.vendor_name} ({v.required_domains.length} domains)
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                  Approved Browser
                </label>
                <select
                  value={approvedBrowser}
                  onChange={(e) => setApprovedBrowser(e.target.value)}
                  style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
                >
                  <option value="chrome">Google Chrome (Strict Outbound Lockdown)</option>
                  <option value="msedge">Microsoft Edge</option>
                  <option value="firefox">Mozilla Firefox</option>
                </select>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                    Policy Version
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={policyVersion}
                    onChange={(e) => setPolicyVersion(parseInt(e.target.value) || 1)}
                    style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                    Validity (Hours)
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="72"
                    value={validHours}
                    onChange={(e) => setValidHours(parseInt(e.target.value) || 8)}
                    style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
                  />
                </div>
              </div>

              <div style={{ paddingTop: '8px' }}>
                <Button
                  variant="primary"
                  onClick={handleCompilePolicy}
                  disabled={compiling || !selectedExamId}
                  style={{ width: '100%' }}
                  icon={<Key size={16} />}
                >
                  {compiling ? 'Compiling & Signing...' : 'Compile & Sign Policy (RSA-PSS)'}
                </Button>
              </div>

              <div style={{ backgroundColor: 'var(--color-bg)', padding: '12px', borderRadius: '8px', fontSize: '12px', color: 'var(--color-text-muted)' }}>
                <strong>Cryptographic Guarantee:</strong> Policies are signed with the Central Server's active RSA-2048 private key using PSS padding with SHA-256 digest. Workstations verify the signature before applying any firewall lockdown.
              </div>
            </div>
          </div>

          {/* Inspector Side */}
          <div style={{ backgroundColor: '#ffffff', borderRadius: '12px', padding: '24px', border: '1px solid rgba(0,0,0,0.06)', display: 'flex', flexDirection: 'column' }}>
            <div className="ds-flex-row ds-justify-between ds-items-center" style={{ marginBottom: '16px' }}>
              <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                Compiled Policy Inspector
              </h2>
              {compiledPolicy && (
                <div style={{ backgroundColor: 'var(--color-success-bg)', color: 'var(--color-success)', padding: '4px 10px', borderRadius: '16px', fontSize: '11px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <CheckCircle2 size={12} />
                  Signed (v{compiledPolicy.version})
                </div>
              )}
            </div>

            {loadingPolicy ? (
              <div style={{ color: 'var(--color-text-muted)', padding: '24px' }}>Loading policy...</div>
            ) : compiledPolicy ? (
              <div className="ds-flex-col" style={{ gap: '16px', flex: 1 }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '12px' }}>
                  <div style={{ backgroundColor: 'var(--color-bg)', padding: '12px', borderRadius: '8px' }}>
                    <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>POLICY ID</div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-primary)', wordBreak: 'break-all' }}>
                      {compiledPolicy.policy_id}
                    </div>
                  </div>
                  <div style={{ backgroundColor: 'var(--color-bg)', padding: '12px', borderRadius: '8px' }}>
                    <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>VALID UNTIL</div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                      {compiledPolicy.expires_at ? new Date(compiledPolicy.expires_at).toLocaleTimeString() : 'N/A'}
                    </div>
                  </div>
                  <div style={{ backgroundColor: 'var(--color-bg)', padding: '12px', borderRadius: '8px' }}>
                    <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>KEY ID</div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                      {compiledPolicy.key_id}
                    </div>
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: '6px' }}>
                    SIGNATURE (BASE64)
                  </div>
                  <div style={{ backgroundColor: '#1e1e1e', color: '#8cdcfe', padding: '12px', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace', wordBreak: 'break-all', maxHeight: '80px', overflowY: 'auto' }}>
                    {compiledPolicy.signature}
                  </div>
                </div>

                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: '6px' }}>
                    RESOLVED DESTINATIONS & RULES
                  </div>
                  <pre style={{ backgroundColor: '#1e1e1e', color: '#ce9178', padding: '16px', borderRadius: '6px', fontSize: '12px', fontFamily: 'monospace', overflowY: 'auto', maxHeight: '250px' }}>
                    {JSON.stringify(compiledPolicy.rules || compiledPolicy, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '48px 16px', color: 'var(--color-text-muted)' }}>
                No policy compiled for the selected exam yet. Select options on the left and click "Compile & Sign Policy".
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: WORKSTATION ENFORCEMENT STATUS */}
      {activeTab === 'states' && (
        <div className="ds-flex-col" style={{ gap: '20px' }}>
          <div className="ds-flex-row ds-justify-between ds-items-center" style={{ flexWrap: 'wrap', gap: '12px' }}>
            <div className="ds-flex-row ds-items-center" style={{ gap: '12px' }}>
              <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--color-text-primary)' }}>Exam:</span>
              <select
                value={stateExamId}
                onChange={(e) => setStateExamId(e.target.value)}
                style={{ padding: '8px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
              >
                {exams.map((ex: any) => (
                  <option key={ex.exam_id} value={ex.exam_id}>
                    {ex.exam_name} ({ex.status})
                  </option>
                ))}
              </select>
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={() => loadDeviceStates(stateExamId)}
              icon={<RefreshCw size={14} className={loadingStates ? 'animate-spin' : ''} />}
            >
              Refresh States
            </Button>
          </div>

          {loadingStates ? (
            <div style={{ color: 'var(--color-text-muted)', padding: '24px' }}>Loading device enforcement states...</div>
          ) : deviceStates.length === 0 ? (
            <EmptyState
              icon={<Laptop size={48} />}
              title="No Enforcement States Recorded"
              description="No workstations have received or acknowledged a signed policy for this exam yet."
            />
          ) : (
            <div style={{ backgroundColor: '#ffffff', borderRadius: '12px', border: '1px solid rgba(0,0,0,0.06)', overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(0,0,0,0.08)', backgroundColor: 'var(--color-bg)' }}>
                    <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--color-text-muted)' }}>WORKSTATION</th>
                    <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--color-text-muted)' }}>ENFORCEMENT STATE</th>
                    <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--color-text-muted)' }}>RULES INSTALLED</th>
                    <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--color-text-muted)' }}>DETAILS / ERROR</th>
                    <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--color-text-muted)' }}>LAST UPDATED</th>
                    <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--color-text-muted)', textAlign: 'right' }}>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {deviceStates.map((ds) => {
                    const isApplied = ds.status === 'APPLIED';
                    const isFailed = ds.status === 'FAILED';
                    const isApplying = ds.status === 'APPLYING';

                    let badgeBg = 'var(--color-gray-bg)';
                    let badgeColor = 'var(--color-text-muted)';
                    if (isApplied) {
                      badgeBg = 'var(--color-success-bg)';
                      badgeColor = 'var(--color-success)';
                    } else if (isFailed) {
                      badgeBg = 'var(--color-danger-bg)';
                      badgeColor = 'var(--color-danger)';
                    } else if (isApplying) {
                      badgeBg = 'var(--color-warning-bg)';
                      badgeColor = 'var(--color-warning)';
                    }

                    return (
                      <tr key={ds.id} style={{ borderBottom: '1px solid rgba(0,0,0,0.04)' }}>
                        <td style={{ padding: '14px 16px' }}>
                          <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                            {ds.device_name || ds.hardware_uuid || 'Unknown Workstation'}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                            {ds.hardware_uuid}
                          </div>
                        </td>
                        <td style={{ padding: '14px 16px' }}>
                          <span style={{ backgroundColor: badgeBg, color: badgeColor, padding: '4px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 600 }}>
                            {ds.status}
                          </span>
                        </td>
                        <td style={{ padding: '14px 16px', color: 'var(--color-text-primary)' }}>
                          {ds.rules_installed || 0} firewall rules
                        </td>
                        <td style={{ padding: '14px 16px', color: isFailed ? 'var(--color-danger)' : 'var(--color-text-muted)', maxWidth: '240px', wordBreak: 'break-word' }}>
                          {ds.last_error || (isApplied ? 'Enforcement active' : 'Distribution in progress')}
                        </td>
                        <td style={{ padding: '14px 16px', color: 'var(--color-text-muted)', fontSize: '12px' }}>
                          {ds.updated_at ? new Date(ds.updated_at).toLocaleTimeString() : 'N/A'}
                        </td>
                        <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                          {ds.hardware_uuid && (
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={distributingUuid === ds.hardware_uuid}
                              onClick={() => handleDistributeToDevice(ds.hardware_uuid!)}
                              icon={<Send size={12} />}
                            >
                              {distributingUuid === ds.hardware_uuid ? 'Sending...' : 'Push Policy'}
                            </Button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Create / Edit Vendor Modal */}
      <Modal
        open={vendorModalOpen}
        onClose={() => setVendorModalOpen(false)}
        title={editingVendor ? `Edit Vendor: ${editingVendor.vendor_name}` : "Create Vendor Profile"}
      >
        <form onSubmit={handleSaveVendor} className="ds-flex-col" style={{ gap: '16px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
              Vendor Profile Name *
            </label>
            <input
              type="text"
              placeholder="e.g. PearsonVUE, CodeSignal, HackerRank, Moodle"
              value={vendorForm.vendor_name}
              onChange={(e) => setVendorForm({ ...vendorForm, vendor_name: e.target.value })}
              required
              style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
              Required Domains (comma-separated) *
            </label>
            <textarea
              placeholder="e.g. exam.example.com, cdn.example.com, api.example.com"
              value={vendorForm.required_domains}
              onChange={(e) => setVendorForm({ ...vendorForm, required_domains: e.target.value })}
              required
              rows={3}
              style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
              Approved IP Ranges (optional, CIDR format)
            </label>
            <input
              type="text"
              placeholder="e.g. 192.168.1.0/24, 10.0.0.0/16"
              value={vendorForm.approved_ip_ranges}
              onChange={(e) => setVendorForm({ ...vendorForm, approved_ip_ranges: e.target.value })}
              style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                Required TCP Ports
              </label>
              <input
                type="text"
                placeholder="e.g. 80, 443"
                value={vendorForm.required_tcp_ports}
                onChange={(e) => setVendorForm({ ...vendorForm, required_tcp_ports: e.target.value })}
                style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                Required UDP Ports
              </label>
              <input
                type="text"
                placeholder="e.g. 53 (usually empty)"
                value={vendorForm.required_udp_ports}
                onChange={(e) => setVendorForm({ ...vendorForm, required_udp_ports: e.target.value })}
                style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.12)', fontSize: '14px', outline: 'none' }}
              />
            </div>
          </div>

          <div className="ds-flex-row ds-justify-end" style={{ gap: '10px', marginTop: '16px' }}>
            <Button variant="outline" type="button" onClick={() => setVendorModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" disabled={savingVendor}>
              {savingVendor ? 'Saving...' : editingVendor ? 'Update Profile' : 'Create Profile'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Delete Vendor Confirmation Dialog */}
      <ConfirmDialog
        open={deleteConfirmOpen}
        onClose={() => setDeleteConfirmOpen(false)}
        onConfirm={handleDeleteVendor}
        title="Delete Vendor Profile"
        message={`Are you sure you want to delete vendor profile '${vendorToDelete?.vendor_name}'?`}
        confirmLabel={deletingVendor ? "Deleting..." : "Delete Vendor"}
        variant="danger"
      />
    </div>
  );
}

export default PoliciesPage;
