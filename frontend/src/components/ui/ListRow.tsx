import React from 'react';

interface ListRowProps {
  title: React.ReactNode;
  metadata: React.ReactNode[];
  badge?: React.ReactNode;
  actions?: React.ReactNode;
  onClick?: () => void;
}

export function ListRow({ title, metadata, badge, actions, onClick }: ListRowProps) {
  return (
    <div 
      onClick={onClick}
      className={`ds-flex-row ds-items-center transition-colors ${onClick ? 'cursor-pointer hover:bg-gray-50' : ''}`}
      style={{
        gap: '16px',
        padding: '16px 20px',
        borderBottom: '1px solid rgba(0,0,0,0.04)',
        backgroundColor: '#ffffff'
      }}
    >
      <div className="ds-flex-col ds-flex-1" style={{ minWidth: 0, gap: '2px' }}>
        <div 
          style={{ 
            fontSize: '14px', 
            fontWeight: '400', 
            color: 'var(--color-text-primary)',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis'
          }}
        >
          {title}
        </div>
        
        <div 
          className="ds-flex-row ds-items-center"
          style={{ 
            flexWrap: 'wrap',
            fontSize: '13px', 
            color: 'var(--color-text-muted)',
            gap: '6px'
          }}
        >
          {metadata.map((item, index) => (
            <React.Fragment key={index}>
              {index > 0 && <span style={{ opacity: 0.5 }}>&middot;</span>}
              <span className="ds-flex-row ds-items-center" style={{ gap: '6px' }}>{item}</span>
            </React.Fragment>
          ))}
        </div>
      </div>

      {badge && (
        <div className="ds-shrink-0">
          {badge}
        </div>
      )}

      {actions && (
        <div 
          className="ds-shrink-0 ds-flex-row ds-items-center ds-justify-end" 
          style={{ gap: '8px' }}
        >
          {actions}
        </div>
      )}
    </div>
  );
}
