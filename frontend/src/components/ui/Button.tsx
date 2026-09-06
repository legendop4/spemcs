import type { ButtonHTMLAttributes, ReactNode } from 'react';

// 'outline-danger' was already implemented below but was missing from this union, and the branch
// that renders it was reachable only through an `as any` cast inside the component. The variant is
// real - ExamShieldPage uses it for the "Stop" control on an active exam, where a filled danger
// button next to "Live monitor" reads as the primary action.
type Variant = 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline-danger';
type Size = 'sm' | 'md' | 'lg';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  children: ReactNode;
}

export function Button({ variant = 'primary', size = 'md', children, className = '', ...props }: ButtonProps) {
  let bg = 'transparent';
  let color = 'inherit';
  let border = '1px solid transparent';
  let pad = size === 'sm' ? '6px 12px' : size === 'lg' ? '12px 24px' : '8px 16px';
  let fs = size === 'sm' ? '13px' : size === 'lg' ? '15px' : '14px';

  if (variant === 'primary') {
    bg = '#D89400';
    color = '#ffffff';
  } else if (variant === 'secondary') {
    bg = '#ffffff';
    color = 'var(--color-text-primary)';
    border = '1px solid var(--color-border)';
  } else if (variant === 'danger') {
    bg = 'var(--color-danger)';
    color = '#ffffff';
  } else if (variant === 'ghost') {
    bg = 'transparent';
    color = 'var(--color-text-muted)';
  } else if (variant === 'outline-danger') {
    bg = '#ffffff';
    color = 'var(--color-danger)';
    border = '1px solid rgba(209, 36, 47, 0.2)'; // faint red border
  }

  return (
    <button 
      className={`ds-flex-row ds-items-center ds-justify-center transition-opacity hover:opacity-80 ${className}`} 
      style={{
        gap: '6px',
        padding: pad,
        fontSize: fs,
        fontWeight: '500',
        borderRadius: '8px',
        backgroundColor: bg,
        color: color,
        border: border,
        cursor: props.disabled ? 'not-allowed' : 'pointer',
        opacity: props.disabled ? 0.6 : 1,
      }}
      {...props}
    >
      {children}
    </button>
  );
}
