import React, { type ReactNode } from 'react';

interface EmptyStateProps {
  title: string;
  message?: string;
  description?: string;
  action?: ReactNode;
  icon?: ReactNode | React.ElementType;
}

export function EmptyState({ title, message, description, action, icon }: EmptyStateProps) {
  const displayMsg = message || description || '';

  const renderIcon = () => {
    if (!icon) {
      return (
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
          <rect x="6" y="6" width="36" height="36" rx="10" stroke="currentColor" strokeWidth="2" opacity="0.3" />
          <path d="M24 16v16M16 24h16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.3" />
        </svg>
      );
    }
    if (React.isValidElement(icon)) {
      return icon;
    }
    if (typeof icon === 'function' || typeof icon === 'object') {
      const IconComponent = icon as React.ElementType;
      return <IconComponent className="w-8 h-8 opacity-40" />;
    }
    return null;
  };

  return (
    <div className="empty-state">
      <div className="empty-state-grid" />
      <div className="empty-state-icon">
        {renderIcon()}
      </div>
      <h3 className="empty-state-title">{title}</h3>
      {displayMsg && <p className="empty-state-message">{displayMsg}</p>}
      {action && <div className="empty-state-action">{action}</div>}
    </div>
  );
}
