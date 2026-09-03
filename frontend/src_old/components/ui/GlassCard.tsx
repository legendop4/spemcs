import type { ReactNode, MouseEvent } from 'react';

interface GlassCardProps {
  children: ReactNode;
  className?: string;
  glass?: boolean;
  onClick?: (e: MouseEvent<HTMLDivElement>) => void;
}

export function GlassCard({ children, className = '', glass = true, onClick }: GlassCardProps) {
  return (
    <div className={`glass-card ${glass ? 'glass' : ''} ${className}`} onClick={onClick}>
      {children}
    </div>
  );
}
