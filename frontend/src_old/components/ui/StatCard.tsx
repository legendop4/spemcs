import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  label: string;
  value: string | number;
  sublabel?: string;
  icon: LucideIcon;
  accent?: 'success' | 'warning' | 'danger' | 'info' | 'gray' | 'accent';
}

export function StatCard({ label, value, sublabel, icon: Icon, accent = 'gray' }: StatCardProps) {
  return (
    <div 
      className="ds-flex-col"
      style={{ 
        backgroundColor: '#ffffff',
        padding: '20px',
        border: '1px solid rgba(0,0,0,0.06)',
        boxShadow: '0 1px 2px rgba(0,0,0,0.02)',
        borderRadius: '12px'
      }}
    >
      <div 
        className="ds-flex-row ds-items-center ds-justify-center"
        style={{ 
          width: '36px', 
          height: '36px',
          borderRadius: '8px',
          backgroundColor: `var(--color-${accent}-bg)`,
          color: `var(--color-${accent}-fg)`,
          marginBottom: '16px'
        }}
      >
        <Icon size={18} strokeWidth={2.5} />
      </div>
      
      <h3 
        style={{ 
          fontSize: '11px', 
          fontWeight: '600', 
          color: 'var(--color-text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          margin: '0 0 4px 0'
        }}
      >
        {label}
      </h3>
      
      <div 
        style={{ 
          fontSize: '28px', 
          fontWeight: '500', 
          color: 'var(--color-text-primary)',
          lineHeight: '1.2',
          letterSpacing: '-0.5px',
          margin: '0 0 2px 0'
        }}
      >
        {value}
      </div>
      
      {sublabel && (
        <div 
          style={{ 
            fontSize: '13px', 
            color: 'var(--color-text-muted)',
            fontWeight: '400'
          }}
        >
          {sublabel}
        </div>
      )}
    </div>
  );
}
