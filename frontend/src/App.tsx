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

import { LabsPage } from '@/pages/LabsPage';
import { PoliciesPage } from '@/pages/PoliciesPage';

// New pages
const LiveMonitorPage = lazy(() => import('@/pages/LiveMonitorPage'));
const DeviceStatusPage = lazy(() => import('@/pages/DeviceStatusPage'));
const ReportsPage = lazy(() => import('@/pages/ReportsPage'));

// Enterprise Experience
import { EnterpriseShell } from '@/components/enterprise/EnterpriseShell';
import { EnterpriseOverview } from '@/pages/enterprise/EnterpriseOverview';
import { EnterpriseEndpoints } from '@/pages/enterprise/EnterpriseEndpoints';
import { EnterpriseEvents } from '@/pages/enterprise/EnterpriseEvents';
import { EnterpriseAlerts } from '@/pages/enterprise/EnterpriseAlerts';
import { EnterprisePolicies } from '@/pages/enterprise/EnterprisePolicies';
import { EnterpriseSessions } from '@/pages/enterprise/EnterpriseSessions';
import { EnterpriseAudit } from '@/pages/enterprise/EnterpriseAudit';
import { EnterpriseAuthority } from '@/pages/enterprise/EnterpriseAuthority';
import { EnterpriseSettings } from '@/pages/enterprise/EnterpriseSettings';
import { SpemcsLandingPage } from '@/pages/public/SpemcsLandingPage';

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
    return <Navigate to="/console/overview" replace />;
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
        {/* SPEMCS Public Product Website */}
        <Route path="/" element={<SpemcsLandingPage />} />

        {/* Authentication */}
        <Route path="/login" element={<PublicRoute><LoginPage /></PublicRoute>} />

        {/* College UI (Untouched) */}
        <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/labs" element={<LabsPage />} />
          <Route path="/policies" element={<PoliciesPage />} />
          <Route path="/exam-shield" element={<ExamShieldPage />} />
          <Route path="/exam-shield/monitor/:id" element={
            <Suspense fallback={<LoadingFallback />}><LiveMonitorPage /></Suspense>
          } />
          <Route path="/exams/:id" element={
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

        {/* SPEMCS Enterprise Security Console */}
        <Route element={<ProtectedRoute><EnterpriseShell /></ProtectedRoute>}>
          <Route path="/console" element={<Navigate to="/console/overview" replace />} />
          <Route path="/console/overview" element={<EnterpriseOverview />} />
          <Route path="/console/endpoints" element={<EnterpriseEndpoints />} />
          <Route path="/console/events" element={<EnterpriseEvents />} />
          <Route path="/console/alerts" element={<EnterpriseAlerts />} />
          <Route path="/console/policies" element={<EnterprisePolicies />} />
          <Route path="/console/sessions" element={<EnterpriseSessions />} />
          <Route path="/console/audit" element={<EnterpriseAudit />} />
          <Route path="/console/authority" element={<EnterpriseAuthority />} />
          <Route path="/console/settings" element={<EnterpriseSettings />} />
          {/* Backwards compatibility aliases */}
          <Route path="/enterprise" element={<Navigate to="/console/overview" replace />} />
          <Route path="/enterprise/overview" element={<Navigate to="/console/overview" replace />} />
          <Route path="/enterprise/endpoints" element={<Navigate to="/console/endpoints" replace />} />
          <Route path="/enterprise/events" element={<Navigate to="/console/events" replace />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
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
