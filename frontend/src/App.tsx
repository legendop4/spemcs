import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { type ReactNode, useEffect, Suspense, lazy } from 'react';
import { AppProvider, useApp } from '@/context/AppContext';
import { AppShell } from '@/components/layout/AppShell';
import { ToastContainer } from '@/components/ui/Toast';
import { LoginPage } from '@/pages/LoginPage';
import { DashboardPage } from '@/pages/DashboardPage';
import { ExamShieldPage } from '@/pages/ExamShieldPage';
import { AlertsPage } from '@/pages/AlertsPage';
import { AuditLogsPage } from '@/pages/AuditLogsPage';
import { SettingsPage } from '@/pages/SettingsPage';

// New pages
const LiveMonitorPage = lazy(() => import('@/pages/LiveMonitorPage'));
const DeviceStatusPage = lazy(() => import('@/pages/DeviceStatusPage'));
const ReportsPage = lazy(() => import('@/pages/ReportsPage'));

function ProtectedRoute({ children }: { children: ReactNode }) {
  const { isAuthenticated, authLoading } = useApp();
  const location = useLocation();
  if (authLoading) return <LoadingFallback />;
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  return <>{children}</>;
}

function PublicRoute({ children }: { children: ReactNode }) {
  const { isAuthenticated, authLoading } = useApp();
  if (authLoading) return <LoadingFallback />;
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }
  return <>{children}</>;
}

function ScrollToTop() {
  const location = useLocation();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);
  return null;
}

function LoadingFallback() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="w-8 h-8 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
    </div>
  );
}

function AppRoutes() {
  return (
    <>
      <ScrollToTop />
      <Routes>
        <Route path="/login" element={<PublicRoute><LoginPage /></PublicRoute>} />
        <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/exam-shield" element={<ExamShieldPage />} />
          <Route path="/exam-shield/monitor/:id" element={
            <Suspense fallback={<LoadingFallback />}><LiveMonitorPage /></Suspense>
          } />
          <Route path="/devices" element={
            <Suspense fallback={<LoadingFallback />}><DeviceStatusPage /></Suspense>
          } />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/reports" element={
            <Suspense fallback={<LoadingFallback />}><ReportsPage /></Suspense>
          } />
          <Route path="/audit-logs" element={<AuditLogsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
      <ToastContainer />
    </>
  );
}

function App() {
  return (
    <AppProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </AppProvider>
  );
}

export default App;
