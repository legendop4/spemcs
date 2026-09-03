import type { ShieldStatus as ShieldStatusType } from '@/types';

interface ShieldStatusProps {
  status: ShieldStatusType;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

export function ShieldStatus({ status, size = 'md', showLabel = true }: ShieldStatusProps) {
  const labels: Record<ShieldStatusType, string> = {
    protected: 'Protected',
    partially: 'Partially Protected',
    unprotected: 'Unprotected',
  };

  return (
    <span className={`shield-status shield-${status} shield-${size}`}>
      <span className="shield-status-dot" />
      {showLabel && <span className="shield-status-label">{labels[status]}</span>}
    </span>
  );
}
