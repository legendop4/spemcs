import { useState, useEffect, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '@/context/AppContext';
import { PageHeader } from '@/components/ui/PageHeader';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Modal } from '@/components/ui/Modal';
import { Skeleton } from '@/components/ui/Skeleton';
import { EmptyState } from '@/components/ui/EmptyState';
import { DeviceTree, type TreeNode } from '@/components/ui/DeviceTree';
import {
  ShieldCheck,
  Plus,
  Play,
  Trash2,
  Eye,
  Lock,
  AlertTriangle,
  CheckCircle2,
  Cpu,
} from 'lucide-react';
import * as api from '@/services/api';

export function ExamShieldPage() {
  const { exams, createExam, activateExam, deactivateExam, deleteExam, loading, showToast } = useApp();
  const navigate = useNavigate();

  // Device tree for exam creation
  const [deviceTree, setDeviceTree] = useState<TreeNode[]>([]);
  const [treeLoading, setTreeLoading] = useState(false);

  // Vendor profiles
  const [vendors, setVendors] = useState<any[]>([]);

  // Policy states per exam
  const [policyMap, setPolicyMap] = useState<Record<string, { compiled: boolean; policy?: any; loading?: boolean }>>({});
  const [compilingId, setCompilingId] = useState<string | null>(null);

  // Launch progression states
  const [launchingId, setLaunchingId] = useState<string | null>(null);
  const [launchStatus, setLaunchStatus] = useState<Record<string, string>>({});

  // Create exam modal
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [examForm, setExamForm] = useState({
    exam_name: '',
    exam_link: '',
    approved_browser: 'chrome',
    network_enforcement: false,
    vendor_profile_id: '',
  });
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<Set<string>>(new Set());
  const [creating, setCreating] = useState(false);
  const [deactivatingId, setDeactivatingId] = useState<string | null>(null);

  // Load vendors on mount
  useEffect(() => {
    api.getPolicyVendors()
      .then(data => setVendors(data || []))
      .catch(err => console.error('Failed to load vendor profiles:', err));
  }, []);

  // Fetch policy states for network-enforced exams
  useEffect(() => {
    exams.forEach((exam: any) => {
      if (exam.network_enforcement && !policyMap[exam.exam_id]) {
        api.getExamPolicy(exam.exam_id)
          .then(policy => {
            setPolicyMap(prev => ({ ...prev, [exam.exam_id]: { compiled: true, policy } }));
          })
          .catch(() => {
            setPolicyMap(prev => ({ ...prev, [exam.exam_id]: { compiled: false } }));
          });
      }
    });
  }, [exams]);

  // Load device tree when modal opens
  useEffect(() => {
    if (createModalOpen) {
      setTreeLoading(true);
      api.getDeviceTree()
        .then(data => setDeviceTree(data))
        .catch(err => console.error('Failed to load device tree:', err))
        .finally(() => setTreeLoading(false));
    }
  }, [createModalOpen]);

  const handleCreateExam = async (e: FormEvent) => {
    e.preventDefault();
    if (!examForm.exam_name.trim()) {
      showToast('Exam name is required', 'error');
      return;
    }
    if (examForm.network_enforcement && !examForm.vendor_profile_id) {
      showToast('A vendor profile is required when Network Lockdown is enabled', 'error');
      return;
    }

    try {
      setCreating(true);
      await createExam({
        exam_name: examForm.exam_name,
        exam_link: examForm.exam_link || null,
        approved_browser: examForm.approved_browser,
        device_ids: Array.from(selectedDeviceIds),
        network_enforcement: examForm.network_enforcement,
        vendor_profile_id: examForm.network_enforcement ? examForm.vendor_profile_id : null,
      });
      setCreateModalOpen(false);
      setExamForm({
        exam_name: '',
        exam_link: '',
        approved_browser: 'chrome',
        network_enforcement: false,
        vendor_profile_id: '',
      });
      setSelectedDeviceIds(new Set());
      showToast('Exam created successfully', 'info');
    } catch (err: any) {
      showToast(err.message || 'Failed to create exam', 'error');
    } finally {
      setCreating(false);
    }
  };

  const handleCompilePolicy = async (examId: string) => {
    try {
      setCompilingId(examId);
      const policy = await api.compileExamPolicy(examId);
      setPolicyMap(prev => ({ ...prev, [examId]: { compiled: true, policy } }));
      showToast('Network policy compiled and signed with Ed25519 successfully', 'info');
    } catch (err: any) {
      showToast(`Policy compilation failed: ${err.message || err}`, 'error');
    } finally {
      setCompilingId(null);
    }
  };

  const handleActivate = async (examId: string) => {
    const exam = exams.find((e: any) => e.exam_id === examId);
    if (!exam) return;

    try {
      setLaunchingId(examId);

      if (exam.network_enforcement) {
        // Step 1: Check or compile policy
        let policy = policyMap[examId]?.policy;
        if (!policy) {
          try {
            setLaunchStatus(prev => ({ ...prev, [examId]: 'Compiling policy...' }));
            policy = await api.compileExamPolicy(examId);
            setPolicyMap(prev => ({ ...prev, [examId]: { compiled: true, policy } }));
          } catch (compErr: any) {
            showToast(`Policy compilation failed: ${compErr.message || compErr}. Launch blocked.`, 'error');
            setLaunchStatus(prev => ({ ...prev, [examId]: 'Compilation Failed — Launch Blocked' }));
            return; // STOP! DO NOT ACTIVATE EXAM!
          }
        }

        // Step 2: Retrieve assigned devices
        setLaunchStatus(prev => ({ ...prev, [examId]: 'Checking assigned devices...' }));
        const assignedDevices = await api.getExamDevices(examId);
        const onlineDevices = assignedDevices.filter((d: any) => d.device_status === 'online');

        // Step 3: Distribute policy to online devices
        const distResults: { uuid: string; success: boolean; error?: string }[] = [];
        for (const dev of onlineDevices) {
          try {
            setLaunchStatus(prev => ({ ...prev, [examId]: `Distributing policy to ${dev.device_name || dev.hardware_uuid}...` }));
            await api.distributeExamPolicy(examId, dev.hardware_uuid);
            distResults.push({ uuid: dev.hardware_uuid, success: true });
          } catch (distErr: any) {
            distResults.push({ uuid: dev.hardware_uuid, success: false, error: distErr.message });
          }
        }

        const failedCount = distResults.filter(r => !r.success).length;
        const successCount = distResults.filter(r => r.success).length;

        if (onlineDevices.length > 0 && failedCount > 0) {
          showToast(`Policy distributed to ${successCount}/${onlineDevices.length} devices (${failedCount} failed)`, 'error');
        } else if (successCount > 0) {
          showToast(`Policy distributed to ${successCount} online device(s)`, 'info');
        }
      }

      // Step 4: Activate exam (sends LAUNCH_EXAM_MODE)
      setLaunchStatus(prev => ({ ...prev, [examId]: 'Activating proctoring session...' }));
      await activateExam(examId);
      showToast('Exam activated — instructions sent to devices', 'info');
    } catch (err: any) {
      showToast(err.message || 'Failed to activate exam', 'error');
    } finally {
      setLaunchingId(null);
      setLaunchStatus(prev => {
        const next = { ...prev };
        delete next[examId];
        return next;
      });
    }
  };

  const handleDeactivate = async (examId: string) => {
    setDeactivatingId(examId);
    try {
      await deactivateExam(examId);
      showToast('Exam stopped', 'info');
    } catch (err: any) {
      showToast(err.message || 'Failed to deactivate exam', 'error');
    } finally {
      setDeactivatingId(null);
    }
  };

  const handleDelete = async (examId: string) => {
    if (!confirm('Are you sure you want to delete this exam?')) return;
    try {
      await deleteExam(examId);
      showToast('Exam deleted', 'info');
    } catch (err: any) {
      showToast(err.message || 'Failed to delete exam', 'error');
    }
  };

  const renderPolicyBadge = (exam: any) => {
    if (!exam.network_enforcement) {
      return (
        <span style={{ fontSize: '12px', color: 'var(--color-text-muted)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
          <ShieldCheck size={13} /> Lockdown: OFF
        </span>
      );
    }

    const state = policyMap[exam.exam_id];
    if (state?.compiled) {
      return (
        <span style={{ fontSize: '12px', color: 'var(--color-success-fg)', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
          <CheckCircle2 size={13} /> Policy: Ready (v{state.policy?.version || 1})
        </span>
      );
    }

    return (
      <span style={{ fontSize: '12px', color: '#D89400', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
        <AlertTriangle size={13} /> Policy: Not Compiled
      </span>
    );
  };

  // Separate exams by status
  const activeExams = exams.filter((e: any) => e.status === 'active');
  const pendingExams = exams.filter((e: any) => e.status === 'pending');
  const completedExams = exams.filter((e: any) => e.status === 'stopped' || e.status === 'completed');

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <PageHeader title="EXAM SHIELD" description="Configure secure exam policies, launch proctoring sessions, and assign endpoints.">
        <Button onClick={() => setCreateModalOpen(true)}>
          <Plus size={16} /> New Exam
        </Button>
      </PageHeader>

      {loading ? (
        <div className="ds-flex-col" style={{ gap: '16px' }}>
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
      ) : exams.length === 0 ? (
        <EmptyState
          icon={<ShieldCheck size={48} />}
          title="No Exams Configured"
          description="Create your first proctored exam to enforce secure browser locking and process monitoring."
        />
      ) : (
        <div className="ds-flex-col">
          {/* Active Exams */}
          {activeExams.length > 0 && (
            <div className="ds-flex-col" style={{ marginBottom: '32px' }}>
              <div className="ds-flex-row ds-items-center" style={{ gap: '8px', marginBottom: '16px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--color-success-fg)' }} />
                <h2 style={{ fontSize: '13px', color: 'var(--color-success-fg)', fontWeight: '500', letterSpacing: '0.5px' }}>
                  ACTIVE ({activeExams.length})
                </h2>
              </div>

              <div className="ds-flex-col" style={{ gap: '12px' }}>
                {activeExams.map((exam: any) => (
                  <div
                    key={exam.exam_id}
                    className="ds-flex-row ds-justify-between ds-items-center"
                    style={{
                      backgroundColor: '#ffffff',
                      border: '1px solid rgba(0,0,0,0.06)',
                      borderRadius: '12px',
                      padding: '16px 20px',
                      boxShadow: '0 1px 2px rgba(0,0,0,0.02)'
                    }}
                  >
                    <div className="ds-flex-col" style={{ gap: '6px' }}>
                      <div className="ds-flex-row ds-items-center" style={{ gap: '12px' }}>
                        <span style={{ fontSize: '15px', color: 'var(--color-text-primary)', fontWeight: 600 }}>{exam.exam_name}</span>
                        <Badge variant="success">Active</Badge>
                        {renderPolicyBadge(exam)}
                      </div>
                      <div className="ds-flex-row ds-items-center" style={{ gap: '6px', fontSize: '13px', color: 'var(--color-text-muted)', flexWrap: 'wrap' }}>
                        {exam.device_count || 1} devices &middot;
                        started {new Date(exam.started_at || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} &middot;
                        <span style={{ color: (exam.alert_count || 0) > 0 ? 'var(--color-danger)' : 'inherit' }}>
                          {exam.alert_count || 0} alerts
                        </span>
                      </div>
                    </div>
                    <div className="ds-flex-row ds-items-center" style={{ gap: '12px', flexShrink: 0 }}>
                      <Button size="sm" variant="primary" onClick={() => navigate(`/exam-shield/monitor/${exam.exam_id}`)}>
                        <Eye size={14} /> Live monitor
                      </Button>
                      <Button size="sm" variant="outline-danger" as="any" disabled={deactivatingId === exam.exam_id} onClick={() => handleDeactivate(exam.exam_id)}>
                        {deactivatingId === exam.exam_id ? 'Stopping...' : 'Stop'}
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Pending Exams */}
          {pendingExams.length > 0 && (
            <div className="ds-flex-col" style={{ marginBottom: '32px' }}>
              <div className="ds-flex-row ds-justify-between ds-items-center" style={{ marginBottom: '16px' }}>
                <h2 style={{ fontSize: '13px', color: '#D89400', fontWeight: '500', letterSpacing: '0.5px', textTransform: 'uppercase' }}>
                  PENDING ({pendingExams.length})
                </h2>
              </div>

              <div className="ds-flex-col" style={{ gap: '12px' }}>
                {pendingExams.map((exam: any) => {
                  const hasLockdown = Boolean(exam.network_enforcement);
                  const isCompiled = policyMap[exam.exam_id]?.compiled;
                  const isCompiling = compilingId === exam.exam_id;
                  const isLaunching = launchingId === exam.exam_id;
                  const statusText = launchStatus[exam.exam_id];

                  return (
                    <div
                      key={exam.exam_id}
                      className="ds-flex-row ds-justify-between ds-items-center"
                      style={{
                        backgroundColor: '#ffffff',
                        border: '1px solid rgba(0,0,0,0.06)',
                        borderRadius: '12px',
                        padding: '16px 20px',
                        boxShadow: '0 1px 2px rgba(0,0,0,0.02)'
                      }}
                    >
                      <div className="ds-flex-col" style={{ gap: '6px' }}>
                        <div className="ds-flex-row ds-items-center" style={{ gap: '12px', flexWrap: 'wrap' }}>
                          <span style={{ fontSize: '15px', color: 'var(--color-text-primary)', fontWeight: 600 }}>
                            {exam.exam_name}
                          </span>
                          {renderPolicyBadge(exam)}
                        </div>
                        <div className="ds-flex-row ds-items-center" style={{ gap: '6px', fontSize: '13px', color: 'var(--color-text-muted)' }}>
                          {exam.device_count || 0} devices assigned &middot; created {new Date(exam.created_at).toLocaleDateString()}
                          {statusText && (
                            <span style={{ color: 'var(--color-warning)', fontWeight: 500 }}>
                              &middot; {statusText}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="ds-flex-row ds-items-center" style={{ gap: '10px', flexShrink: 0 }}>
                        {hasLockdown && !isCompiled && (
                          <Button
                            size="sm"
                            variant="secondary"
                            disabled={isCompiling || isLaunching}
                            onClick={() => handleCompilePolicy(exam.exam_id)}
                            style={{ fontSize: '12px', fontWeight: 600 }}
                          >
                            <Lock size={13} /> {isCompiling ? 'Signing...' : 'Compile & Sign Policy'}
                          </Button>
                        )}
                        <Button
                          size="sm"
                          variant="primary"
                          disabled={isLaunching || isCompiling}
                          onClick={() => handleActivate(exam.exam_id)}
                        >
                          <Play size={14} /> {isLaunching ? 'Launching...' : 'Launch'}
                        </Button>
                        <Button size="sm" variant="secondary" onClick={() => handleDelete(exam.exam_id)} style={{ padding: '6px 10px' }}>
                          <Trash2 size={14} style={{ color: 'var(--color-text-muted)' }} />
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Completed/Stopped Exams */}
          {completedExams.length > 0 && (
            <div className="ds-flex-col" style={{ marginBottom: '32px' }}>
              <div className="ds-flex-row ds-items-center" style={{ gap: '8px', marginBottom: '16px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--color-text-muted)' }} />
                <h2 style={{ fontSize: '13px', color: 'var(--color-text-muted)', fontWeight: '500', letterSpacing: '0.5px' }}>
                  CONCLUDED ({completedExams.length})
                </h2>
              </div>

              <div className="ds-flex-col" style={{ gap: '12px' }}>
                {completedExams.map((exam: any) => (
                  <div
                    key={exam.exam_id}
                    className="ds-flex-row ds-justify-between ds-items-center"
                    style={{
                      backgroundColor: '#ffffff',
                      border: '1px solid rgba(0,0,0,0.06)',
                      borderRadius: '12px',
                      padding: '16px 20px',
                      opacity: 0.7
                    }}
                  >
                    <div className="ds-flex-col" style={{ gap: '4px' }}>
                      <div className="ds-flex-row ds-items-center" style={{ gap: '12px' }}>
                        <span style={{ fontSize: '15px', color: 'var(--color-text-primary)' }}>{exam.exam_name}</span>
                        <Badge variant="gray">Completed</Badge>
                        {renderPolicyBadge(exam)}
                      </div>
                      <div className="ds-flex-row ds-items-center" style={{ gap: '6px', fontSize: '13px', color: 'var(--color-text-muted)', flexWrap: 'wrap' }}>
                        {exam.device_count || 0} devices &middot; {exam.alert_count || 0} alerts &middot; {exam.session_count || 0} sessions
                      </div>
                    </div>

                    <div className="ds-flex-row ds-items-center" style={{ gap: '12px', flexShrink: 0 }}>
                      <Button size="sm" variant="secondary" onClick={() => navigate('/reports')}>
                        View Report
                      </Button>
                      <Button size="sm" variant="secondary" onClick={() => handleDelete(exam.exam_id)} style={{ padding: '6px 10px' }}>
                        <Trash2 size={14} style={{ color: 'var(--color-danger)' }} />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Create Exam Modal */}
      <Modal
        open={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
        title="Create new proctored exam"
        size="md"
        footer={
          <div className="ds-flex-row ds-items-center" style={{ gap: '12px', justifyContent: 'flex-end' }}>
            <Button
              variant="secondary"
              onClick={() => setCreateModalOpen(false)}
              style={{ backgroundColor: '#ffffff', border: '1px solid rgba(0,0,0,0.1)', color: 'var(--color-text-primary)', padding: '10px 24px', borderRadius: '8px', fontWeight: 500 }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleCreateExam as any}
              disabled={creating}
              style={{ backgroundColor: 'var(--color-warning)', border: 'none', color: '#ffffff', padding: '10px 24px', borderRadius: '8px', fontWeight: 600 }}
            >
              {creating ? 'Creating...' : 'Create and assign'}
            </Button>
          </div>
        }
      >
        <form onSubmit={handleCreateExam} className="ds-flex-col" style={{ gap: '24px' }}>
          <div className="ds-flex-col" style={{ gap: '8px' }}>
            <label style={{ fontSize: '11px', fontWeight: 700, color: '#A89F91', letterSpacing: '0.5px' }}>EXAM NAME</label>
            <input
              value={examForm.exam_name}
              onChange={(e) => setExamForm({ ...examForm, exam_name: e.target.value })}
              placeholder="e.g. Midterm exam - Computer architecture, Section A"
              required
              style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid rgba(0,0,0,0.06)', backgroundColor: 'var(--color-bg)', fontSize: '14px', outline: 'none', color: 'var(--color-text-primary)' }}
            />
          </div>
          <div className="ds-flex-row" style={{ gap: '16px' }}>
            <div className="ds-flex-col" style={{ gap: '8px', flex: 1 }}>
              <label style={{ fontSize: '11px', fontWeight: 700, color: '#A89F91', letterSpacing: '0.5px' }}>ALLOWED EXAM PORTAL URL</label>
              <input
                value={examForm.exam_link}
                onChange={(e) => setExamForm({ ...examForm, exam_link: e.target.value })}
                placeholder="https://exam.university.edu"
                style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid rgba(0,0,0,0.06)', backgroundColor: 'var(--color-bg)', fontSize: '14px', outline: 'none', color: 'var(--color-text-primary)' }}
              />
            </div>
            <div className="ds-flex-col" style={{ gap: '8px', flex: 1 }}>
              <label style={{ fontSize: '11px', fontWeight: 700, color: '#A89F91', letterSpacing: '0.5px' }}>MANDATED BROWSER</label>
              <select
                value={examForm.approved_browser}
                onChange={(e) => setExamForm({ ...examForm, approved_browser: e.target.value })}
                style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid rgba(0,0,0,0.06)', backgroundColor: 'var(--color-bg)', fontSize: '14px', outline: 'none', color: 'var(--color-text-primary)', appearance: 'none', backgroundImage: 'url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'16\' height=\'16\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%23A89F91\' stroke-width=\'2\' stroke-linecap=\'round\' stroke-linejoin=\'round\'%3E%3Cpath d=\'m6 9 6 6 6-6\'/%3E%3C/svg%3E")', backgroundRepeat: 'no-repeat', backgroundPosition: 'right 12px center' }}
              >
                <option value="chrome">Google Chrome</option>
                <option value="firefox">Mozilla Firefox</option>
                <option value="edge">Microsoft Edge</option>
              </select>
            </div>
          </div>

          {/* Network Lockdown Toggle */}
          <div className="ds-flex-col" style={{ gap: '8px' }}>
            <div className="ds-flex-row ds-items-center ds-justify-between" style={{ padding: '14px 16px', backgroundColor: 'var(--color-bg)', borderRadius: '8px', border: '1px solid rgba(0,0,0,0.06)' }}>
              <div className="ds-flex-col" style={{ gap: '2px' }}>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text-primary)', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                  <Lock size={14} style={{ color: examForm.network_enforcement ? 'var(--color-warning)' : 'var(--color-text-muted)' }} />
                  Enable Network Lockdown
                </span>
                <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                  Restricts outbound network traffic at the Windows Firewall layer to the authorized exam vendor portal
                </span>
              </div>
              <label style={{ display: 'inline-flex', alignItems: 'center', cursor: 'pointer', gap: '8px' }}>
                <input
                  type="checkbox"
                  checked={examForm.network_enforcement}
                  onChange={(e) => setExamForm({ ...examForm, network_enforcement: e.target.checked })}
                  style={{ width: '18px', height: '18px', cursor: 'pointer', accentColor: 'var(--color-warning)' }}
                />
                <span style={{ fontSize: '12px', fontWeight: 700, color: examForm.network_enforcement ? 'var(--color-warning-fg)' : 'var(--color-text-muted)', minWidth: '28px' }}>
                  {examForm.network_enforcement ? 'ON' : 'OFF'}
                </span>
              </label>
            </div>
          </div>

          {/* Vendor Profile Selection (Required when Network Lockdown is ON) */}
          {examForm.network_enforcement && (
            <div className="ds-flex-col" style={{ gap: '8px' }}>
              <label style={{ fontSize: '11px', fontWeight: 700, color: '#A89F91', letterSpacing: '0.5px' }}>
                VENDOR PROFILE <span style={{ color: 'var(--color-danger)' }}>*</span>
              </label>
              <select
                value={examForm.vendor_profile_id}
                onChange={(e) => setExamForm({ ...examForm, vendor_profile_id: e.target.value })}
                required
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  borderRadius: '8px',
                  border: '1px solid rgba(0,0,0,0.06)',
                  backgroundColor: 'var(--color-bg)',
                  fontSize: '14px',
                  outline: 'none',
                  color: 'var(--color-text-primary)',
                  appearance: 'none',
                  backgroundImage: 'url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'16\' height=\'16\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%23A89F91\' stroke-width=\'2\' stroke-linecap=\'round\' stroke-linejoin=\'round\'%3E%3Cpath d=\'m6 9 6 6 6-6\'/%3E%3C/svg%3E")',
                  backgroundRepeat: 'no-repeat',
                  backgroundPosition: 'right 12px center'
                }}
              >
                <option value="">-- Select Vendor Profile --</option>
                {vendors.map((v: any) => (
                  <option key={v.vendor_id} value={v.vendor_id}>
                    {v.vendor_name} ({v.required_domains?.join(', ') || 'Standard portal'})
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="ds-flex-col" style={{ gap: '12px' }}>
            <div className="ds-flex-row ds-justify-between ds-items-center">
              <label style={{ fontSize: '11px', fontWeight: 700, color: '#A89F91', letterSpacing: '0.5px' }}>TARGET WORKSTATION LAB ASSIGNMENT</label>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-warning)' }}>
                {selectedDeviceIds.size} of {deviceTree.reduce((acc, n) => acc + (n.children ? n.children.reduce((cAcc, c) => cAcc + (c.children ? c.children.length : 1), 0) : 1), 0)} selected
              </div>
            </div>
            {treeLoading ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <Skeleton className="h-8" />
                <Skeleton className="h-8" />
              </div>
            ) : (
              <DeviceTree
                nodes={deviceTree}
                selectedDeviceIds={selectedDeviceIds}
                onSelectionChange={setSelectedDeviceIds}
              />
            )}
          </div>
        </form>
      </Modal>
    </div>
  );
}
