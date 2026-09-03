import React from 'react';
import { ChevronRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

interface SectionCardProps {
  title: string;
  count?: number;
  statusDot?: 'success' | 'warning' | 'danger' | 'info' | 'gray';
  viewAllLink?: string;
  children: React.ReactNode;
}

export function SectionCard({ title, count, statusDot, viewAllLink, children }: SectionCardProps) {
  const navigate = useNavigate();

  return (
    <div 
      className="ds-flex-col"
      style={{
        backgroundColor: '#ffffff',
        borderRadius: '12px',
        border: '1px solid rgba(0,0,0,0.06)',
        boxShadow: '0 1px 2px rgba(0,0,0,0.02)'
      }}
    >
      <div 
        className="ds-flex-row ds-justify-between ds-items-center"
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid rgba(0,0,0,0.04)'
        }}
      >
        <div className="ds-flex-row ds-items-center" style={{ gap: '8px' }}>
          {statusDot && (
            <span 
              style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: `var(--color-${statusDot})` }}
            />
          )}
          <h2 
            style={{ 
              fontSize: '14px', 
              fontWeight: '500',
              color: 'var(--color-text-primary)',
              margin: 0
            }}
          >
            {title}
            {count !== undefined && (
              <span style={{ color: 'var(--color-text-muted)', marginLeft: '6px' }}>
                ({count})
              </span>
            )}
          </h2>
        </div>
        
        {viewAllLink && (
          <button 
            onClick={() => navigate(viewAllLink)}
            className="ds-flex-row ds-items-center transition-opacity hover:opacity-80"
            style={{ 
              gap: '4px',
              fontSize: '13px', 
              fontWeight: '400',
              color: '#D89400', // Gold/orange color from screenshot
              cursor: 'pointer'
            }}
          >
            View all <ChevronRight size={14} />
          </button>
        )}
      </div>

      <div className="ds-flex-col" style={{ padding: 0 }}>
        {children}
      </div>
    </div>
  );
}
