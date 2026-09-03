import React from 'react';

interface PageHeaderProps {
  title: string;
  description?: string;
  actions?: React.ReactNode;
  children?: React.ReactNode;
}

export function PageHeader({ title, description, actions, children }: PageHeaderProps) {
  return (
    <div className="ds-flex-row ds-justify-between ds-items-center" style={{ marginBottom: '32px', flexWrap: 'wrap', gap: '16px' }}>
      <div className="ds-flex-col" style={{ gap: '4px' }}>
        <h1 
          style={{ 
            fontSize: '24px', 
            fontWeight: 700, 
            color: 'var(--color-text-primary)',
            margin: 0
          }}
        >
          {title}
        </h1>
        {description && (
          <p style={{ fontSize: '14px', color: 'var(--color-text-muted)', margin: 0 }}>
            {description}
          </p>
        )}
      </div>
      {(actions || children) && (
        <div className="ds-flex-row ds-items-center" style={{ gap: '12px', flexShrink: 0 }}>
          {actions}
          {children}
        </div>
      )}
    </div>
  );
}
