import React from 'react';

type BadgeVariant = 'success' | 'warning' | 'danger' | 'info' | 'gray' | 'accent';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  dot?: boolean;
  className?: string;
}

export function Badge({ children, variant = 'gray', dot = false, className = '' }: BadgeProps) {
  return (
    <span
      className={`ds-flex-row ds-items-center ${className}`}
      style={{
        gap: '6px',
        padding: '4px 10px',
        borderRadius: 'var(--radius-sm)',
        fontSize: 'var(--text-xs)',
        fontWeight: 'var(--font-semibold)',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
        backgroundColor: `var(--color-${variant}-bg)`,
        color: `var(--color-${variant}-fg)`,
        border: `1px solid var(--color-${variant}-bg)`, 
        // using the bg color for border to give a solid edge but same tint
      }}
    >
      {dot && (
        <span
          style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: `var(--color-${variant}-fg)` }}
        />
      )}
      {children}
    </span>
  );
}
