interface SkeletonProps {
  width?: string;
  height?: string;
  rounded?: string;
  className?: string;
}

export function Skeleton({ width = '100%', height = '20px', rounded = '8px', className = '' }: SkeletonProps) {
  return (
    <div
      className={`skeleton ${className}`}
      style={{ width, height, borderRadius: rounded }}
    />
  );
}

export function SkeletonCard() {
  return (
    <div className="skeleton-card">
      <Skeleton width="60px" height="14px" />
      <Skeleton width="48px" height="40px" rounded="12px" />
      <Skeleton width="80px" height="12px" />
    </div>
  );
}

export function SkeletonRow() {
  return (
    <div className="skeleton-row">
      <Skeleton width="24px" height="24px" rounded="6px" />
      <Skeleton width="160px" height="16px" />
      <Skeleton width="100px" height="14px" />
      <Skeleton width="80px" height="14px" />
      <Skeleton width="60px" height="24px" rounded="9999px" />
    </div>
  );
}
