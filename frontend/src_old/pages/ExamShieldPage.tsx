import { useState, useEffect, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '@/context/AppContext';
import { PageHeader } from '@/components/ui/PageHeader';
import { Button } from '@/components/ui/Button';
import { GlassCard } from '@/components/ui/GlassCard';
import { Badge } from '@/components/ui/Badge';
import { Modal } from '@/components/ui/Modal';
import { Skeleton } from '@/components/ui/Skeleton';
import { EmptyState } from '@/components/ui/EmptyState';
import { DeviceTree, type TreeNode } from '@/components/ui/DeviceTree';
import {
  ShieldCheck,
  Plus,
  Play,
  Square,
  Trash2,
  Monitor,
  AlertTriangle,
  Users,
  Eye,
  ExternalLink,
  Clock,
} from 'lucide-react';
import * as api from '@/services/api';

export function ExamShieldPage() {
  const { exams, refresh, createExam, activateExam, deactivateExam, deleteExam, loading, showToast } = useApp();
  const navigate = useNavigate();

  // Device tree for exam creation
  const [deviceTree, setDeviceTree] = useState<TreeNode[]>([]);
  const [treeLoading, setTreeLoading] = useState(false);

  // Create exam modal
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [examForm, setExamForm] = useState({
    exam_name: '',
    exam_link: '',
    approved_browser: 'chrome',
  });
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<Set<string>>(new Set());
  const [creating, setCreating] = useState(false);
  const [deactivatingId, setDeactivatingId] = useState<string | null>(null);

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
    try {
      setCreating(true);
      await createExam({
        exam_name: examForm.exam_name,
        exam_link: examForm.exam_link || null,
        approved_browser: examForm.approved_browser,
        device_ids: Array.from(selectedDeviceIds),
      });
      setCreateModalOpen(false);
      setExamForm({ exam_name: '', exam_link: '', approved_browser: 'chrome' });
      setSelectedDeviceIds(new Set());
      showToast('Exam created successfully', 'info');
    } catch (err) {
      showToast('Failed to create exam', 'error');
    } finally {
      setCreating(false);
    }
  };

  const handleActivate = async (examId: string) => {
    try {
      await activateExam(examId);
      showToast('Exam activated - instructions sent to devices', 'info');
    } catch (err: any) {
      showToast(err.message || 'Failed to activate exam', 'error');
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

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active': return <Badge variant="green" dot={true}>Active</Badge>;
      case 'stopped': return <Badge variant="red">Stopped</Badge>;
      case 'completed': return <Badge variant="gray">Completed</Badge>;
      default: return <Badge variant="amber">Pending</Badge>;
    }
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
                    <div className="ds-flex-col" style={{ gap: '4px' }}>
                      <div className="ds-flex-row ds-items-center" style={{ gap: '12px' }}>
                        <span style={{ fontSize: '15px', color: 'var(--color-text-primary)' }}>{exam.exam_name}</span>
                        <Badge variant="success">Active</Badge>
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
                <input 
                  type="text"
                  placeholder="Search by section, lab, or date"
                  style={{ 
                    backgroundColor: '#ffffff', 
                    border: '1px solid rgba(0,0,0,0.08)', 
                    borderRadius: '8px', 
                    padding: '8px 16px', 
                    fontSize: '13px', 
                    color: 'var(--color-text-primary)',
                    outline: 'none',
                    minWidth: '240px'
                  }}
                />
              </div>
              
              <div className="ds-flex-col" style={{ gap: '12px' }}>
                {pendingExams.map((exam: any) => (
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
                    <div className="ds-flex-col" style={{ gap: '4px' }}>
                      <div style={{ fontSize: '15px', color: 'var(--color-text-primary)' }}>
                        {exam.exam_name}
                      </div>
                      <div className="ds-flex-row ds-items-center" style={{ gap: '6px', fontSize: '13px', color: 'var(--color-text-muted)' }}>
                        {exam.device_count || 0} devices assigned &middot; created {new Date(exam.created_at).toLocaleDateString()}
                      </div>
                    </div>
                    
                    <div className="ds-flex-row ds-items-center" style={{ gap: '12px', flexShrink: 0 }}>
                      <Button size="sm" variant="primary" onClick={() => handleActivate(exam.exam_id)}>
                        <Play size={14} /> Launch
                      </Button>
                      <Button size="sm" variant="secondary" onClick={() => handleDelete(exam.exam_id)} style={{ padding: '6px 10px' }}>
                        <Trash2 size={14} style={{ color: 'var(--color-text-muted)' }} />
                      </Button>
                    </div>
                  </div>
                ))}
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
                {creating ? 'Deploying...' : 'Create and assign'}
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
