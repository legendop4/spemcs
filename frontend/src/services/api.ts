const BASE = '/api';

let authToken: string | null = null;

export function setAuthToken(token: string | null) {
  authToken = token;
}

function parseNaiveDates(obj: any): any {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') {
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(obj)) {
      return obj + 'Z';
    }
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(parseNaiveDates);
  }
  if (typeof obj === 'object') {
    const newObj: any = {};
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        newObj[key] = parseNaiveDates(obj[key]);
      }
    }
    return newObj;
  }
  return obj;
}

async function fetchJson(path: string, opts: RequestInit = {}) {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(opts.headers as Record<string, string> || {}),
  };
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }
  const res = await fetch(`${BASE}${path}`, { ...opts, headers });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(error.detail || `HTTP ${res.status}`);
  }
  if (res.status === 204) return null;
  const json = await res.json();
  return parseNaiveDates(json);
}

// --- Auth ---
export const login = (username: string, password: string) =>
  fetchJson('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
export const register = (username: string, email: string, password: string, role = 'admin') =>
  fetchJson('/auth/register', { method: 'POST', body: JSON.stringify({ username, email, password, role }) });
export const getCurrentUser = () => fetchJson('/auth/me');
export const getAuditLogs = () => fetchJson('/audit-logs');

// --- Dashboard ---
export const getDashboardSummary = () => fetchJson('/dashboard/summary');

// --- Devices ---
export const getDevices = () => fetchJson('/devices');
export const getDevice = (id: string) => fetchJson(`/devices/${id}`);
export const createDevice = (data: any) => fetchJson('/devices', { method: 'POST', body: JSON.stringify(data) });
export const updateDevice = (id: string, data: any) => fetchJson(`/devices/${id}`, { method: 'PUT', body: JSON.stringify(data) });
export const deleteDevice = (id: string) => fetchJson(`/devices/${id}`, { method: 'DELETE' });
export const getDeviceTree = () => fetchJson('/devices/tree');
export const getOnlineDevices = () => fetchJson('/devices/online');
export const getDeviceStatus = (id: string) => fetchJson(`/devices/${id}/status`);

// --- Labs ---
export const getLabs = () => fetchJson('/labs');
export const getLabDevices = (labId: string) => fetchJson(`/labs/${labId}/devices`);
export const setLabSpemcs = (labId: string, enabled: boolean) =>
  fetchJson(`/labs/${labId}/status`, { method: 'PATCH', body: JSON.stringify({ spemcs_enabled: enabled }) });

// --- Exams ---
export const getExams = () => fetchJson('/exams');
export const getExam = (id: string) => fetchJson(`/exams/${id}`);
export const createExam = (data: any) => fetchJson('/exams', { method: 'POST', body: JSON.stringify(data) });
export const updateExam = (id: string, data: any) => fetchJson(`/exams/${id}`, { method: 'PUT', body: JSON.stringify(data) });
export const deleteExam = (id: string) => fetchJson(`/exams/${id}`, { method: 'DELETE' });
export const activateExam = (id: string) => fetchJson(`/exams/${id}/activate`, { method: 'POST' });
export const deactivateExam = (id: string) => fetchJson(`/exams/${id}/deactivate`, { method: 'POST' });
export const getExamDevices = (examId: string) => fetchJson(`/exams/${examId}/devices`);
export const getExamSessions = (examId: string) => fetchJson(`/exams/${examId}/sessions`);
export const getExamAlerts = (examId: string) => fetchJson(`/exams/${examId}/alerts`);
export const getExamTimeline = (examId: string) => fetchJson(`/exams/${examId}/timeline`);

// --- Alerts ---
export const getAlerts = () => fetchJson('/alerts');
export const getAlert = (id: string) => fetchJson(`/alerts/${id}`);
export const updateAlert = (id: string, data: any) => fetchJson(`/alerts/${id}`, { method: 'PUT', body: JSON.stringify(data) });

// --- Sessions ---
export const getSessions = () => fetchJson('/sessions');

// --- Events ---
export const getEvents = () => fetchJson('/events');

// --- Reports ---
export const getReports = () => fetchJson('/reports');
export const getReport = (id: string) => fetchJson(`/reports/${id}`);
export const generateReport = (examId: string) => fetchJson(`/reports/generate/${examId}`, { method: 'POST' });
export const exportReportCsv = (reportId: string) =>
  fetch(`${BASE}/reports/${reportId}/export/csv`, {
    headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {},
  }).then(res => res.blob());

// --- Health ---
export const getHealth = () => fetchJson('/health');

export const deploymentApi = {
  pushDeploy: async (data: DeploymentRequest): Promise<DeploymentResult[]> => {
    const response = await api.post('/deployment/push', data);
    return response.data;
  },
};
