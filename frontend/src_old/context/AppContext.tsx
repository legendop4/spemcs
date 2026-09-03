import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from 'react';
import * as api from '@/services/api';
import { wsClient, type WsMessage } from '@/services/websocket';

export interface Toast {
  id: string;
  message: string;
  variant: 'success' | 'error' | 'info';
}

interface DashboardSummary {
  total_exams: number;
  active_exams: number;
  total_devices: number;
  devices_online: number;
  devices_offline: number;
  open_alerts: number;
  active_sessions: number;
  total_labs: number;
  ws_connected_devices: number;
  ws_connected_dashboards: number;
  active_exam_summary: any[];
  online_device_list: any[];
}

interface AppContextValue {
  // Auth
  currentUser: any | null;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;

  // Data
  devices: any[];
  exams: any[];
  alerts: any[];
  labs: any[];
  dashboardSummary: DashboardSummary | null;

  // Actions
  refresh: () => Promise<void>;
  createExam: (data: any) => Promise<any>;
  activateExam: (examId: string) => Promise<any>;
  deactivateExam: (examId: string) => Promise<any>;
  deleteExam: (examId: string) => Promise<void>;

  // Toast
  toasts: Toast[];
  showToast: (message: string, variant?: Toast['variant']) => void;
  dismissToast: (id: string) => void;

  // WebSocket
  wsConnected: boolean;

  // Loading
  loading: boolean;
  authLoading: boolean;
}

const AppContext = createContext<AppContextValue | null>(null);

export function useApp(): AppContextValue {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [currentUser, setCurrentUser] = useState<any | null>(null);
  const [devices, setDevices] = useState<any[]>([]);
  const [exams, setExams] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [labs, setLabs] = useState<any[]>([]);
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [loading, setLoading] = useState(true);
  const [authLoading, setAuthLoading] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);

  // Check for stored auth token on mount
  useEffect(() => {
    const token = localStorage.getItem('spemcs_token');
    if (token) {
      api.setAuthToken(token);
      api.getCurrentUser()
        .then(user => {
          setCurrentUser(user);
        })
        .catch(() => {
          localStorage.removeItem('spemcs_token');
          api.setAuthToken(null);
        })
        .finally(() => {
          setAuthLoading(false);
        });
    } else {
      setAuthLoading(false);
    }
  }, []);

  // Refresh all data from backend without UI blocking
  const refresh = useCallback(async (isInitial = false) => {
    if (isInitial) setLoading(true);
    try {
      const [devicesData, examsData, alertsData, labsData, summaryData] = await Promise.allSettled([
        api.getDevices(),
        api.getExams(),
        api.getAlerts(),
        api.getLabs(),
        api.getDashboardSummary(),
      ]);

      if (devicesData.status === 'fulfilled') setDevices(devicesData.value);
      if (examsData.status === 'fulfilled') setExams(examsData.value);
      if (alertsData.status === 'fulfilled') setAlerts(alertsData.value);
      if (labsData.status === 'fulfilled') setLabs(labsData.value);
      if (summaryData.status === 'fulfilled') setDashboardSummary(summaryData.value);
    } catch (err) {
      console.error('Error refreshing data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial data load
  useEffect(() => {
    refresh(true);
  }, [refresh]);

  // WebSocket connection and real-time updates
  useEffect(() => {
    wsClient.connect();

    const offDeviceStatus = wsClient.on('DEVICE_STATUS_CHANGE', (msg: WsMessage) => {
      const payload = msg.payload;
      if (!payload) return;
      setDevices(prev => prev.map(d =>
        (d.hardware_uuid === payload.hardware_uuid || d.device_name === payload.device_name)
          ? { ...d, status: payload.status, last_seen: payload.timestamp }
          : d
      ));
    });

    const offAlert = wsClient.on('VIOLATION_ALERT', (msg: WsMessage) => {
      if (msg.payload) {
        setAlerts(prev => {
          const alertId = msg.payload.alert_id || msg.payload.id || msg.payload.event_id;
          if (prev.some(a => (a.alert_id || a.id || a.event_id) === alertId)) return prev;
          return [msg.payload, ...prev];
        });
        setDashboardSummary(prev => prev ? { ...prev, open_alerts: prev.open_alerts + 1 } : prev);
      }
    });

    const offSessionStarted = wsClient.on('SESSION_STARTED', (msg: WsMessage) => {
      if (msg.payload) {
        setDashboardSummary(prev => prev ? { ...prev, active_sessions: prev.active_sessions + 1 } : prev);
      }
    });

    const offExamStatus = wsClient.on('EXAM_STATUS_CHANGE', (msg: WsMessage) => {
      if (msg.payload) {
        setExams(prev => prev.map(e =>
          e.exam_id === msg.payload.exam_id
            ? { ...e, status: msg.payload.status }
            : e
        ));
      }
    });

    // Track connection state
    const checkConnection = setInterval(() => {
      setWsConnected(wsClient.isConnected);
    }, 2000);

    return () => {
      offDeviceStatus();
      offAlert();
      offSessionStarted();
      offExamStatus();
      clearInterval(checkConnection);
      wsClient.disconnect();
    };
  }, []);

  // Auth
  const login = useCallback(async (username: string, password: string): Promise<boolean> => {
    const result = await api.login(username, password);
    if (result?.access_token) {
      localStorage.setItem('spemcs_token', result.access_token);
      api.setAuthToken(result.access_token);
      const user = await api.getCurrentUser();
      setCurrentUser(user);
      await refresh();
      return true;
    }
    return false;
  }, [refresh]);

  const logout = useCallback(() => {
    localStorage.removeItem('spemcs_token');
    api.setAuthToken(null);
    setCurrentUser(null);
  }, []);

  // Exam actions
  const createExam = useCallback(async (data: any) => {
    const exam = await api.createExam(data);
    await refresh();
    showToastFn('Exam created successfully');
    return exam;
  }, [refresh]);

  const activateExam = useCallback(async (examId: string) => {
    const result = await api.activateExam(examId);
    await refresh();
    showToastFn(`Exam activated — ${result.devices_reached}/${result.devices_targeted} devices reached`);
    return result;
  }, [refresh]);

  const deactivateExam = useCallback(async (examId: string) => {
    const result = await api.deactivateExam(examId);
    await refresh();
    showToastFn('Exam deactivated');
    return result;
  }, [refresh]);

  const deleteExam = useCallback(async (examId: string) => {
    await api.deleteExam(examId);
    await refresh();
    showToastFn('Exam deleted');
  }, [refresh]);

  // Toasts
  const showToastFn = (message: string, variant: Toast['variant'] = 'success') => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    setToasts(prev => [...prev, { id, message, variant }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 3500);
  };

  const showToast = useCallback(showToastFn, []);

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const value: AppContextValue = {
    currentUser,
    isAuthenticated: currentUser !== null,
    login,
    logout,
    devices,
    exams,
    alerts,
    labs,
    dashboardSummary,
    refresh,
    createExam,
    activateExam,
    deactivateExam,
    deleteExam,
    toasts,
    showToast,
    dismissToast,
    wsConnected,
    loading,
    authLoading,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}
