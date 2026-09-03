import React, { useState, useEffect } from 'react';
import { FileText, RefreshCw, BarChart3, AlertTriangle, Monitor, Activity } from 'lucide-react';
import { GlassCard } from '@/components/ui/GlassCard';
import { Modal } from '@/components/ui/Modal';
import { Timeline, TimelineEvent } from '@/components/ui/Timeline';
import * as api from '@/services/api';

interface ReportInfo {
  report_id: string;
  exam_id: string;
  generated_at: string;
  summary: any;
  report_data: any;
  alert_count: number;
  event_count: number;
}

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportInfo[]>([]);
  const [exams, setExams] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedReport, setSelectedReport] = useState<ReportInfo | null>(null);
  const [generating, setGenerating] = useState<string | null>(null);

  // For the generate new report section
  const [searchExam, setSearchExam] = useState('');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [reps, exs] = await Promise.all([
        api.getReports(),
        api.getExams(),
      ]);
      setReports(reps);
      setExams(exs);
    } catch (err) {
      console.error('Failed to load data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerate = async (examId: string) => {
    try {
      setGenerating(examId);
      await api.generateReport(examId);
      await loadData();
    } catch (err) {
      console.error('Failed to generate report:', err);
    } finally {
      setGenerating(null);
    }
  };

  const handleExportCsv = async (reportId: string) => {
    try {
      const blob = await api.exportReportCsv(reportId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `exam-report-${reportId.slice(0, 8)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export:', err);
    }
  };

  const getExamName = (examId: string) =>
    exams.find(e => e.exam_id === examId)?.exam_name || 'Exam Report';

  const pendingExamsForReport = exams.filter(e => !reports.some(r => r.exam_id === e.exam_id));
  
  const filteredExams = pendingExamsForReport.filter(e => {
    if (!searchExam) return true;
    return e.exam_name.toLowerCase().includes(searchExam.toLowerCase());
  });

  return (
    <div className="page-container ds-flex-col" style={{ gap: '32px' }}>

      {/* Generate New Report Section */}
      <div 
        className="ds-flex-col" 
        style={{ 
          backgroundColor: '#ffffff', 
          border: '1px solid rgba(0,0,0,0.06)', 
          borderRadius: '12px', 
          overflow: 'hidden',
          boxShadow: '0 1px 2px rgba(0,0,0,0.02)'
        }}
      >
        <div className="ds-flex-row ds-items-center ds-justify-between" style={{ padding: '20px 24px' }}>
          <div style={{ fontSize: '16px', color: 'var(--color-text-primary)', fontWeight: '500' }}>Generate new exam report</div>
          <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>{pendingExamsForReport.length} exams available</div>
        </div>

        <div className="ds-flex-row ds-items-center" style={{ padding: '0 24px 16px 24px', gap: '12px' }}>
          <input 
            type="text"
            placeholder="Search exam by name or section"
            value={searchExam}
            onChange={e => setSearchExam(e.target.value)}
            style={{ 
              backgroundColor: 'var(--color-surface-raised)', 
              border: '1px solid rgba(0,0,0,0.06)', 
              borderRadius: '8px', 
              padding: '10px 16px', 
              fontSize: '14px', 
              color: 'var(--color-text-primary)',
              flex: 1,
              outline: 'none'
            }}
          />
          <button 
            style={{ 
              backgroundColor: '#ffffff', 
              border: '1px solid rgba(0,0,0,0.08)', 
              borderRadius: '8px', 
              padding: '10px 16px', 
              fontSize: '13px', 
              fontWeight: '500',
              color: 'var(--color-text-muted)',
              cursor: 'pointer'
            }}
          >
            Sort: recent
          </button>
        </div>

        <div className="ds-flex-col">
          {filteredExams.slice(0, 4).map((exam, i) => (
            <div 
              key={exam.exam_id}
              className="ds-flex-row ds-items-center ds-justify-between" 
              style={{ 
                padding: '16px 24px', 
                borderTop: '1px solid rgba(0,0,0,0.06)' 
              }}
            >
              <div className="ds-flex-row ds-items-center" style={{ gap: '12px' }}>
                <FileText size={16} style={{ color: 'var(--color-text-muted)' }} />
                <span style={{ fontSize: '14px', color: 'var(--color-text-primary)' }}>{exam.exam_name}</span>
              </div>
              <button 
                onClick={() => handleGenerate(exam.exam_id)}
                disabled={generating === exam.exam_id}
                style={{ 
                  backgroundColor: '#ffffff', 
                  border: '1px solid rgba(0,0,0,0.08)', 
                  borderRadius: '8px', 
                  padding: '8px 16px', 
                  fontSize: '13px', 
                  fontWeight: '500',
                  color: 'var(--color-text-primary)',
                  cursor: generating === exam.exam_id ? 'wait' : 'pointer',
                  opacity: generating === exam.exam_id ? 0.7 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                {generating === exam.exam_id ? <RefreshCw size={14} className="animate-spin" /> : null}
                Generate
              </button>
            </div>
          ))}
        </div>
        
        {filteredExams.length > 4 && (
          <div style={{ padding: '16px', textAlign: 'center', borderTop: '1px solid rgba(0,0,0,0.06)' }}>
            <span style={{ color: 'var(--color-warning)', fontSize: '13px', fontWeight: '500', cursor: 'pointer' }}>
              Show {filteredExams.length - 4} more
            </span>
          </div>
        )}
      </div>

      {/* Generated Reports Section */}
      <div className="ds-flex-col" style={{ gap: '12px' }}>
        <div style={{ fontSize: '12px', fontWeight: '500', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          GENERATED REPORTS
        </div>
        
        {loading ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--color-text-muted)' }}>Loading reports...</div>
        ) : reports.length === 0 ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--color-text-muted)', backgroundColor: '#ffffff', borderRadius: '12px', border: '1px solid rgba(0,0,0,0.06)' }}>
            No reports generated yet.
          </div>
        ) : (
          reports.map(report => {
            const examName = getExamName(report.exam_id);
            const d = new Date(report.generated_at);
            const genDate = `${d.toLocaleDateString()}, ${d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`;

            return (
              <div 
                key={report.report_id}
                className="ds-flex-row ds-items-center ds-justify-between" 
                style={{ 
                  backgroundColor: '#ffffff', 
                  border: '1px solid rgba(0,0,0,0.06)', 
                  borderRadius: '12px', 
                  padding: '16px 20px', 
                  boxShadow: '0 1px 2px rgba(0,0,0,0.02)',
                  flexWrap: 'wrap',
                  gap: '16px'
                }}
              >
                <div className="ds-flex-col">
                  <div className="ds-flex-row ds-items-center" style={{ gap: '10px', marginBottom: '4px' }}>
                    <div style={{ fontSize: '16px', color: 'var(--color-text-primary)', fontWeight: '500' }}>{examName}</div>
                    <div style={{ 
                      backgroundColor: 'var(--color-success-bg)', 
                      color: 'var(--color-success-fg)', 
                      padding: '2px 8px', 
                      borderRadius: '6px', 
                      fontSize: '11px', 
                      fontWeight: '500' 
                    }}>
                      Report ready
                    </div>
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>
                    Generated {genDate} &middot; {report.event_count || 0} events logged &middot; {report.alert_count || 0} violations
                  </div>
                </div>

                <div className="ds-flex-row ds-items-center" style={{ gap: '8px' }}>
                  <button 
                    onClick={() => setSelectedReport(report)}
                    style={{ 
                      backgroundColor: '#E79B25', /* custom gold color from screenshot */
                      color: '#fff', 
                      border: 'none', 
                      borderRadius: '8px', 
                      padding: '10px 16px', 
                      fontSize: '13px', 
                      fontWeight: '500',
                      cursor: 'pointer'
                    }}
                  >
                    View timeline
                  </button>
                  <button 
                    onClick={() => handleExportCsv(report.report_id)}
                    style={{ 
                      backgroundColor: '#fff', 
                      color: 'var(--color-text-primary)', 
                      border: '1px solid rgba(0,0,0,0.08)', 
                      borderRadius: '8px', 
                      padding: '9px 16px', 
                      fontSize: '13px', 
                      fontWeight: '500',
                      cursor: 'pointer'
                    }}
                  >
                    Export CSV
                  </button>
                  <button 
                    onClick={() => handleGenerate(report.exam_id)}
                    disabled={generating === report.exam_id}
                    style={{ 
                      backgroundColor: '#fff', 
                      color: 'var(--color-text-muted)', 
                      border: '1px solid rgba(0,0,0,0.08)', 
                      borderRadius: '8px', 
                      padding: '9px', 
                      display: 'flex', 
                      alignItems: 'center',
                      cursor: 'pointer'
                    }}
                  >
                    <RefreshCw size={16} className={generating === report.exam_id ? "animate-spin" : ""} />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Report Detail Modal */}
      {selectedReport && (
        <Modal
          open={true}
          onClose={() => setSelectedReport(null)}
          title={`Exam Report: ${getExamName(selectedReport.exam_id)}`}
          size="lg"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
              <div style={{ padding: '16px', borderRadius: '12px', background: 'var(--color-surface-raised)', border: '1px solid rgba(0,0,0,0.06)', textAlign: 'center' }}>
                <div style={{ fontSize: '24px', fontWeight: 500, color: 'var(--color-text-primary)' }}>
                  {selectedReport.summary?.total_sessions || selectedReport.report_data?.total_sessions || 0}
                </div>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginTop: '4px' }}>
                  Exam Sessions
                </div>
              </div>
              <div style={{ padding: '16px', borderRadius: '12px', background: 'var(--color-surface-raised)', border: '1px solid rgba(0,0,0,0.06)', textAlign: 'center' }}>
                <div style={{ fontSize: '24px', fontWeight: 500, color: 'var(--color-text-primary)' }}>
                  {selectedReport.event_count || selectedReport.summary?.total_events || 0}
                </div>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginTop: '4px' }}>
                  Recorded Events
                </div>
              </div>
              <div style={{ padding: '16px', borderRadius: '12px', background: 'var(--color-danger-bg)', border: '1px solid rgba(209, 36, 47, 0.2)', textAlign: 'center' }}>
                <div style={{ fontSize: '24px', fontWeight: 500, color: 'var(--color-danger)' }}>
                  {selectedReport.alert_count || selectedReport.summary?.total_alerts || 0}
                </div>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-danger)', textTransform: 'uppercase', marginTop: '4px' }}>
                  Security Alerts
                </div>
              </div>
            </div>

            {selectedReport.report_data?.timeline && selectedReport.report_data.timeline.length > 0 ? (
              <Timeline
                events={selectedReport.report_data.timeline as TimelineEvent[]}
                title="Detailed Event Timeline"
              />
            ) : (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '14px' }}>
                No chronological events recorded for this session.
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}
