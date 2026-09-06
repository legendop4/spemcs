import React from 'react';

// Every variant here must have a matching `--color-<variant>-bg` / `-fg` pair in tokens.css, because
// that is how the styles below are built. A variant named after a raw colour ('green', 'red',
// 'amber') resolves to an undefined custom property and renders the badge with no fill at all, so
// this union is the guard against a silently invisible badge, not merely a naming preference.
type BadgeVariant = 'success' | 'warning' | 'danger' | 'info' | 'gray' | 'accent';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  dot?: boolean;
  className?: string;
  // Merged over the computed style below, so a caller can adjust presentation (AlertsPage wants a
  // larger badge for its per-device summary) without being able to lose the variant colours by
  // accident. `Button` already accepts `style` by spreading ButtonHTMLAttributes; Badge was the one
  // primitive that took `className` but dropped `style` on the floor.
  style?: React.CSSProperties;
}

export function Badge({ children, variant = 'gray', dot = false, className = '', style }: BadgeProps) {
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
        ...style,
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
