import { useState, useEffect, useMemo } from 'react';
import {
  FileCode,
  RefreshCw,
  Plus,
  Search,
  Shield,
  Trash2,
  Edit2,
  X,
  Globe,
  Radio,
} from 'lucide-react';
import * as api from '@/services/api';

export interface PolicyVendor {
  id?: string;
  vendor_id?: string;
  vendor_name: string;
  description?: string;
  allowed_domains: string[];
  allowed_ips: string[];
  created_at?: string;
  updated_at?: string;
}

export function EnterprisePolicies() {
  const [policies, setPolicies] = useState<PolicyVendor[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<PolicyVendor | null>(null);

  // Form state
  const [vendorName, setVendorName] = useState('');
  const [description, setDescription] = useState('');
  const [allowedDomains, setAllowedDomains] = useState('');
  const [allowedIps, setAllowedIps] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Safe mutation state for delete dialog
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; name: string } | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const fetchPolicies = async () => {
    try {
      setError(null);
      const data = await api.getPolicyVendors();
      setPolicies(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err.message || 'Failed to load network policies');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchPolicies();
  };

  const handleOpenCreate = () => {
    setEditingPolicy(null);
    setVendorName('');
    setDescription('');
    setAllowedDomains('');
    setAllowedIps('');
    setShowCreateModal(true);
  };

  const handleOpenEdit = (policy: PolicyVendor) => {
    setEditingPolicy(policy);
    setVendorName(policy.vendor_name);
    setDescription(policy.description || '');
    setAllowedDomains((policy.allowed_domains || []).join('\n'));
    setAllowedIps((policy.allowed_ips || []).join('\n'));
    setShowCreateModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vendorName.trim()) return;

    setSubmitting(true);
    try {
      const payload = {
        vendor_name: vendorName.trim(),
        description: description.trim(),
        allowed_domains: allowedDomains
          .split('\n')
          .map((d) => d.trim())
          .filter(Boolean),
        allowed_ips: allowedIps
          .split('\n')
          .map((ip) => ip.trim())
          .filter(Boolean),
      };

      if (editingPolicy) {
        const vid = editingPolicy.vendor_id || editingPolicy.id || '';
        await api.updatePolicyVendor(vid, payload);
      } else {
        await api.createPolicyVendor(payload);
      }

      setShowCreateModal(false);
      fetchPolicies();
    } catch (err: any) {
      alert(`Policy submission failed: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await api.deletePolicyVendor(deleteTarget.id);
      setPolicies((prev) => prev.filter((p) => (p.vendor_id || p.id) !== deleteTarget.id));
      setDeleteTarget(null);
    } catch (err: any) {
      setDeleteError(err.message || 'Failed to delete policy profile');
    } finally {
      setDeleting(false);
    }
  };

  const filtered = useMemo(() => {
    return policies.filter(
      (p) =>
        (p.vendor_name || '').toLowerCase().includes(search.toLowerCase()) ||
        (p.description || '').toLowerCase().includes(search.toLowerCase())
    );
  }, [policies, search]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
      {/* Modern Page Header */}
      <div className="ep-page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-cyan)', textTransform: 'uppercase', letterSpacing: '1px' }}>
              POLICY & CONTROL // HOST FIREWALL TEMPLATES
            </span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#FFFFFF', margin: 0, letterSpacing: '-0.3px' }}>
            Network Policies
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', margin: '4px 0 0 0' }}>
            Perimeter rule definitions and cryptographic host firewall distribution
          </p>
        </div>

        <div className="ep-header-actions">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="ep-btn ep-btn-secondary"
            title="Refresh policies"
          >
            <RefreshCw size={14} className={refreshing ? 'ep-spin' : ''} />
            <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>
          <button
            onClick={handleOpenCreate}
            className="ep-btn ep-btn-primary"
          >
            <Plus size={15} />
            <span>Create Policy Profile</span>
          </button>
        </div>
      </div>

      {/* Toolbar: Search */}
      <div className="ep-toolbar">
        <div style={{ position: 'relative', flex: '1', minWidth: '240px' }}>
          <Search
            size={14}
            style={{
              position: 'absolute',
              left: '12px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--ep-text-dim)',
            }}
          />
          <input
            type="text"
            className="ep-input"
            style={{ paddingLeft: '34px', width: '100%', boxSizing: 'border-box' }}
            placeholder="Filter network policy profiles by identifier or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Policy Profiles Grid */}
      {loading ? (
        <div className="ep-card" style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--ep-text-secondary)', fontSize: '13px' }}>
          <RefreshCw size={20} className="ep-spin" style={{ margin: '0 auto 12px auto', display: 'block', color: 'var(--ep-cyan)' }} />
          Loading network policy templates...
        </div>
      ) : error ? (
        <div className="ep-card" style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--ep-crimson)', fontSize: '13px' }}>
          {error}
        </div>
      ) : filtered.length === 0 ? (
        <div className="ep-card" style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--ep-text-secondary)', fontSize: '13px' }}>
          <FileCode size={36} style={{ color: 'var(--ep-cyan)', margin: '0 auto 12px auto', display: 'block' }} />
          <div style={{ color: '#FFFFFF', fontWeight: '600', marginBottom: '4px' }}>No Network Policies Configured</div>
          <div style={{ color: 'var(--ep-text-muted)', fontSize: '12px' }}>
            Define approved domain lists and IP CIDR blocks for Windows Firewall distribution using the action above.
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(min(100%, 340px), 1fr))', gap: '16px' }}>
          {filtered.map((policy) => (
            <div key={policy.vendor_id || policy.id} className="ep-card" style={{ padding: '18px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '14px' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Shield size={16} style={{ color: 'var(--ep-cyan)' }} />
                    <h3 style={{ fontSize: '15px', fontWeight: '700', color: '#FFFFFF', margin: 0 }}>
                      {policy.vendor_name}
                    </h3>
                  </div>
                  <span className="ep-badge ep-badge-cyan" style={{ fontSize: '10px' }}>
                    TEMPLATE
                  </span>
                </div>

                <p style={{ fontSize: '12px', color: 'var(--ep-text-secondary)', margin: '0 0 14px 0', lineHeight: 1.5 }}>
                  {policy.description || 'No description provided for this network policy template.'}
                </p>

                {/* Rules Summary */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', background: 'var(--ep-surface-secondary)', padding: '10px', borderRadius: '4px', border: '1px solid var(--ep-surface-border)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--ep-font-mono)' }}>
                    <span style={{ color: 'var(--ep-text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Globe size={12} /> Approved Domains:
                    </span>
                    <span style={{ color: '#FFFFFF', fontWeight: '600' }}>
                      {(policy.allowed_domains || []).length} domains
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--ep-font-mono)' }}>
                    <span style={{ color: 'var(--ep-text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Radio size={12} /> IP CIDR Allowlist:
                    </span>
                    <span style={{ color: '#FFFFFF', fontWeight: '600' }}>
                      {(policy.allowed_ips || []).length} blocks
                    </span>
                  </div>
                </div>
              </div>

              {/* Actions Footer */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', paddingTop: '10px', borderTop: '1px solid var(--ep-surface-border)' }}>
                <button
                  onClick={() => handleOpenEdit(policy)}
                  className="ep-btn ep-btn-secondary"
                  style={{ padding: '5px 12px', fontSize: '11px' }}
                >
                  <Edit2 size={12} /> Edit
                </button>
                <button
                  onClick={() => setDeleteTarget({ id: policy.vendor_id || policy.id || '', name: policy.vendor_name })}
                  className="ep-btn ep-btn-secondary"
                  style={{ padding: '5px 12px', fontSize: '11px', color: 'var(--ep-crimson)' }}
                >
                  <Trash2 size={12} /> Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Delete Confirmation Modal (Replaces browser confirm) */}
      {deleteTarget && (
        <div className="ep-modal-backdrop" onClick={() => !deleting && setDeleteTarget(null)}>
          <div className="ep-modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--ep-surface-border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '32px', height: '32px', borderRadius: '6px', backgroundColor: 'var(--ep-crimson-bg)', border: '1px solid var(--ep-crimson-border)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--ep-crimson)' }}>
                  <Trash2 size={16} />
                </div>
                <h3 style={{ fontSize: '16px', fontWeight: '700', color: '#FFFFFF', margin: 0 }}>
                  Delete Policy Profile
                </h3>
              </div>
              <button
                onClick={() => !deleting && setDeleteTarget(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--ep-text-secondary)', cursor: 'pointer' }}
                disabled={deleting}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <p style={{ fontSize: '13px', color: 'var(--ep-text-secondary)', margin: 0, lineHeight: 1.5 }}>
                Are you sure you want to permanently delete policy profile <strong style={{ color: '#FFFFFF' }}>{deleteTarget.name}</strong>?
              </p>
              <div style={{ padding: '12px', borderRadius: '6px', backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)', fontSize: '12px', color: '#F87171', lineHeight: 1.4 }}>
                <strong>Consequence:</strong> Host endpoints evaluating this profile will no longer receive rules for this perimeter template upon subsequent policy synchronizations.
              </div>
              {deleteError && (
                <div style={{ padding: '10px 12px', borderRadius: '6px', backgroundColor: 'var(--ep-crimson-bg)', border: '1px solid var(--ep-crimson-border)', color: 'var(--ep-crimson)', fontSize: '12px' }}>
                  {deleteError}
                </div>
              )}
            </div>

            <div style={{ padding: '16px 24px', borderTop: '1px solid var(--ep-surface-border)', display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                type="button"
                onClick={() => setDeleteTarget(null)}
                disabled={deleting}
                className="ep-btn ep-btn-secondary"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmDelete}
                disabled={deleting}
                className="ep-btn"
                style={{ backgroundColor: 'var(--ep-crimson)', color: '#FFFFFF', fontWeight: 600 }}
              >
                {deleting ? 'Deleting...' : 'Delete Policy Profile'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create / Edit Modal */}
      {showCreateModal && (
        <div
          className="ep-modal-backdrop"
          onClick={() => !submitting && setShowCreateModal(false)}
        >
          <div
            className="ep-modal-dialog"
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '18px 24px', borderBottom: '1px solid var(--ep-surface-border)' }}>
              <h3 style={{ fontSize: '16px', fontWeight: '700', color: '#FFFFFF', margin: 0 }}>
                {editingPolicy ? 'Edit Policy Profile' : 'Create Network Policy Profile'}
              </h3>
              <button
                onClick={() => !submitting && setShowCreateModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--ep-text-secondary)', cursor: 'pointer' }}
                disabled={submitting}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleSubmit} style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
              <div>
                <label style={{ display: 'block', fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)', marginBottom: '4px', textTransform: 'uppercase' }}>
                  Policy Profile Name *
                </label>
                <input
                  type="text"
                  placeholder="e.g. AWS Core Infrastructure Access"
                  value={vendorName}
                  onChange={(e) => setVendorName(e.target.value)}
                  required
                  style={{
                    width: '100%',
                    background: 'var(--ep-surface-secondary)',
                    border: '1px solid var(--ep-surface-border)',
                    borderRadius: '4px',
                    padding: '8px 12px',
                    color: '#FFFFFF',
                    fontSize: '13px',
                    outline: 'none',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)', marginBottom: '4px', textTransform: 'uppercase' }}>
                  Description / Operational Scope
                </label>
                <input
                  type="text"
                  placeholder="e.g. Outbound network rules for managed workstations"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'var(--ep-surface-secondary)',
                    border: '1px solid var(--ep-surface-border)',
                    borderRadius: '4px',
                    padding: '8px 12px',
                    color: '#FFFFFF',
                    fontSize: '13px',
                    outline: 'none',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)', marginBottom: '4px', textTransform: 'uppercase' }}>
                  Allowed FQDN Domains (One per line)
                </label>
                <textarea
                  rows={4}
                  placeholder="api.aws.amazon.com&#10;spemcs.shivamsharma.tech&#10;github.com"
                  value={allowedDomains}
                  onChange={(e) => setAllowedDomains(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'var(--ep-surface-secondary)',
                    border: '1px solid var(--ep-surface-border)',
                    borderRadius: '4px',
                    padding: '8px 12px',
                    color: '#FFFFFF',
                    fontSize: '12px',
                    fontFamily: 'var(--ep-font-mono)',
                    outline: 'none',
                    boxSizing: 'border-box',
                    minHeight: '75px',
                    maxHeight: '150px',
                    overflowY: 'auto',
                    resize: 'vertical',
                    lineHeight: 1.4,
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '11px', fontFamily: 'var(--ep-font-mono)', color: 'var(--ep-text-muted)', marginBottom: '4px', textTransform: 'uppercase' }}>
                  Allowed IP CIDR Blocks (One per line)
                </label>
                <textarea
                  rows={3}
                  placeholder="10.240.0.0/16&#10;192.168.1.0/24"
                  value={allowedIps}
                  onChange={(e) => setAllowedIps(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'var(--ep-surface-secondary)',
                    border: '1px solid var(--ep-surface-border)',
                    borderRadius: '4px',
                    padding: '8px 12px',
                    color: '#FFFFFF',
                    fontSize: '12px',
                    fontFamily: 'var(--ep-font-mono)',
                    outline: 'none',
                    boxSizing: 'border-box',
                    minHeight: '65px',
                    maxHeight: '140px',
                    overflowY: 'auto',
                    resize: 'vertical',
                    lineHeight: 1.4,
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  disabled={submitting}
                  className="ep-btn ep-btn-secondary"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="ep-btn ep-btn-primary"
                >
                  {submitting ? 'Saving...' : editingPolicy ? 'Update Policy' : 'Create Policy'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default EnterprisePolicies;
