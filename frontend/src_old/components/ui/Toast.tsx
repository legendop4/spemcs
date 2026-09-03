import { useApp } from '@/context/AppContext';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';

export function ToastContainer() {
  const { toasts, dismissToast } = useApp();

  return (
    <div className="toast-container">
      {toasts.map((toast) => (
        <div key={toast.id} className={`toast toast-${toast.variant}`} onClick={() => dismissToast(toast.id)}>
          <span className="toast-icon">
            {toast.variant === 'success' && <CheckCircle2 size={18} />}
            {toast.variant === 'error' && <AlertCircle size={18} />}
            {toast.variant === 'info' && <Info size={18} />}
          </span>
          <span className="toast-message">{toast.message}</span>
          <button className="toast-close" onClick={(e) => { e.stopPropagation(); dismissToast(toast.id); }}>
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}
