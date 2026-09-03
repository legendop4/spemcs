/**
 * DeviceTree - Hierarchical device selector for exam creation.
 * Supports Building -> Lab -> PC tree with tri-state checkboxes.
 */
import React, { useState, useMemo } from 'react';
import { ChevronRight, ChevronDown, Building2, Monitor, FolderOpen, Search } from 'lucide-react';

export interface TreeNode {
  name: string;
  type: 'building' | 'lab' | 'device';
  id: string;
  device_id?: string;
  hardware_uuid?: string;
  status?: string;
  children?: TreeNode[];
}

interface DeviceTreeProps {
  nodes: TreeNode[];
  selectedDeviceIds: Set<string>;
  onSelectionChange: (deviceIds: Set<string>) => void;
  showStatus?: boolean;
}

export function DeviceTree({ nodes, selectedDeviceIds, onSelectionChange, showStatus = true }: DeviceTreeProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState('');

  // Get all device IDs under a node
  const getDescendantDeviceIds = (node: TreeNode): string[] => {
    if (node.type === 'device' && node.device_id) return [node.device_id];
    return (node.children || []).flatMap(getDescendantDeviceIds);
  };

  // Compute check state: 'checked', 'unchecked', or 'indeterminate'
  const getCheckState = (node: TreeNode): 'checked' | 'unchecked' | 'indeterminate' => {
    const deviceIds = getDescendantDeviceIds(node);
    if (deviceIds.length === 0) return 'unchecked';
    const selectedCount = deviceIds.filter(id => selectedDeviceIds.has(id)).length;
    if (selectedCount === 0) return 'unchecked';
    if (selectedCount === deviceIds.length) return 'checked';
    return 'indeterminate';
  };

  const toggleNode = (node: TreeNode) => {
    const deviceIds = getDescendantDeviceIds(node);
    const newSelected = new Set(selectedDeviceIds);
    const currentState = getCheckState(node);

    if (currentState === 'checked') {
      deviceIds.forEach(id => newSelected.delete(id));
    } else {
      deviceIds.forEach(id => newSelected.add(id));
    }
    onSelectionChange(newSelected);
  };

  const toggleExpand = (nodeId: string) => {
    const newExpanded = new Set(expanded);
    if (newExpanded.has(nodeId)) {
      newExpanded.delete(nodeId);
    } else {
      newExpanded.add(nodeId);
    }
    setExpanded(newExpanded);
  };

  // Filter nodes by search
  const filterNodes = (nodes: TreeNode[], query: string): TreeNode[] => {
    if (!query) return nodes;
    const q = query.toLowerCase();
    return nodes.reduce<TreeNode[]>((acc, node) => {
      if (node.name.toLowerCase().includes(q)) {
        acc.push(node);
      } else if (node.children) {
        const filtered = filterNodes(node.children, query);
        if (filtered.length > 0) {
          acc.push({ ...node, children: filtered });
        }
      }
      return acc;
    }, []);
  };

  const filteredNodes = useMemo(() => filterNodes(nodes, search), [nodes, search]);

  const renderCheckbox = (state: 'checked' | 'unchecked' | 'indeterminate') => {
    const isDark = state === 'checked' || state === 'indeterminate';
    return (
      <div
        style={{
          width: '16px',
          height: '16px',
          borderRadius: '4px',
          backgroundColor: isDark ? '#3d3d3d' : '#ffffff',
          border: isDark ? '1px solid #3d3d3d' : '1px solid rgba(0,0,0,0.2)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0
        }}
      >
        {state === 'checked' && (
          <svg style={{ width: '12px', height: '12px', color: '#ffffff' }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
          </svg>
        )}
        {state === 'indeterminate' && (
          <div style={{ width: '8px', height: '2px', backgroundColor: '#ffffff', borderRadius: '2px' }} />
        )}
      </div>
    );
  };

  const getIcon = (type: string) => {
    switch (type) {
      case 'building': return <Building2 size={16} style={{ color: 'var(--color-warning)' }} />;
      case 'lab': return <FolderOpen size={16} style={{ color: 'var(--color-text-muted)' }} />;
      default: return null;
    }
  };

  const renderNode = (node: TreeNode, depth: number = 0) => {
    const hasChildren = (node.children?.length || 0) > 0;
    const isExpanded = expanded.has(node.id);
    const checkState = getCheckState(node);

    const isGroup = node.type === 'building' || node.type === 'lab';
    const bg = isGroup ? '#FCFAF8' : '#ffffff';
    const borderB = isGroup ? '1px solid rgba(0,0,0,0.06)' : '1px solid transparent';

    return (
      <div key={node.id} style={{ display: 'flex', flexDirection: 'column' }}>
        <div
          onClick={() => toggleNode(node)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: `12px 16px 12px ${depth * 24 + 16}px`,
            backgroundColor: bg,
            borderBottom: borderB,
            cursor: 'pointer',
            transition: 'background-color 0.2s'
          }}
        >
          {hasChildren ? (
            <div
              onClick={(e) => { e.stopPropagation(); toggleExpand(node.id); }}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', padding: '4px' }}
            >
              {isExpanded ? (
                <ChevronDown size={14} style={{ color: 'var(--color-text-muted)' }} />
              ) : (
                <ChevronRight size={14} style={{ color: 'var(--color-text-muted)' }} />
              )}
            </div>
          ) : (
            <div style={{ width: '22px' }} />
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1 }}>
            {(!isGroup || depth > 0) && renderCheckbox(checkState)}
            {getIcon(node.type)}
            <span style={{ fontSize: '14px', color: 'var(--color-text-primary)', fontWeight: isGroup ? 500 : 400 }}>
              {node.name}
            </span>
          </div>

          {showStatus && node.type === 'device' && node.status && (
            <span style={{
              fontSize: '11px',
              padding: '2px 8px',
              borderRadius: '12px',
              backgroundColor: node.status === 'online' ? 'var(--color-success-bg)' : 'var(--color-gray-bg)',
              color: node.status === 'online' ? 'var(--color-success)' : 'var(--color-text-muted)'
            }}>
              {node.status}
            </span>
          )}
        </div>

        {hasChildren && isExpanded && (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {(node.children || []).map(child => renderNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  const totalDevices = nodes.flatMap(n => getDescendantDeviceIds(n)).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <div style={{ position: 'relative' }}>
        <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: '#A89F91' }} />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search devices"
          style={{ width: '100%', padding: '10px 16px 10px 36px', backgroundColor: 'var(--color-bg)', border: '1px solid rgba(0,0,0,0.06)', borderRadius: '8px', fontSize: '14px', outline: 'none', color: 'var(--color-text-primary)' }}
        />
      </div>
      <div style={{ maxHeight: '240px', overflowY: 'auto', border: '1px solid rgba(0,0,0,0.06)', borderRadius: '8px', display: 'flex', flexDirection: 'column', backgroundColor: '#ffffff' }}>
        {filteredNodes.map(node => renderNode(node))}
        {filteredNodes.length === 0 && (
          <div style={{ textAlign: 'center', padding: '32px', color: 'var(--color-text-muted)', fontSize: '14px' }}>No devices found</div>
        )}
      </div>
    </div>
  );
}
