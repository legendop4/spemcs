const BASE = '/api';

import type { DeploymentRequest, DeploymentResult } from '@/types';

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

// A FastAPI `detail` is not always a string. The enforcement-readiness refusal on
// POST /exams/{id}/activate answers 409 with a structured object ({ready, problems, message, ...}),
// and FastAPI's own request-validation errors answer 422 with an array. `new Error(someObject)`
// stringifies to "[object Object]", so every caller that shows `err.message` in a toast used to
// render exactly that for the one refusal an operator most needs to read. The structured value is
// preserved on `err.detail` so a caller can render `problems` properly if it wants to.
export class ApiError extends Error {
  status: number;
  detail: any;
  constructor(message: string, status: number, detail: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

function describeDetail(detail: any, status: number): string {
  if (typeof detail === 'string' && detail) return detail;
  if (detail && typeof detail === 'object') {
    if (typeof detail.message === 'string' && detail.message) return detail.message;
    if (Array.isArray(detail)) {
      const parts = detail
        .map((d: any) => (typeof d?.msg === 'string' ? d.msg : null))
        .filter(Boolean);
      if (parts.length) return parts.join('; ');
    }
  }
  return `HTTP ${status}`;
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
    throw new ApiError(describeDetail(error?.detail, res.status), res.status, error?.detail);
  }
  if (res.status === 204) return null;
  const json = await res.json();
  return parseNaiveDates(json);
}

// --- Auth ---
export const login = (username: string, password: string) =>
  fetchJson('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
// Creating an account is an ADMIN action and requires an authenticated administrator's token; the
// endpoint is no longer self-service. The role parameter defaulted to 'admin', which meant the
// obvious call created an administrator - so it is now required and explicit at the call site.
export const register = (username: string, email: string, password: string, role: 'admin' | 'proctor') =>
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

// --- Policies ---
export const getPolicyVendors = () => fetchJson('/policies/vendors');
export const createPolicyVendor = (data: any) => fetchJson('/policies/vendors', { method: 'POST', body: JSON.stringify(data) });
export const getPolicyVendor = (id: string) => fetchJson(`/policies/vendors/${id}`);
export const updatePolicyVendor = (id: string, data: any) => fetchJson(`/policies/vendors/${id}`, { method: 'PUT', body: JSON.stringify(data) });
export const deletePolicyVendor = (id: string) => fetchJson(`/policies/vendors/${id}`, { method: 'DELETE' });

export const getExamPolicy = (examId: string) => fetchJson(`/policies/exam/${examId}`);
export const compileExamPolicy = (examId: string, data: any = {}) =>
  fetchJson(`/policies/compile/${examId}`, { method: 'POST', body: JSON.stringify(data) });
export const distributeExamPolicy = (examId: string, hardwareUuid: string) =>
  fetchJson(`/policies/distribute/${examId}/${hardwareUuid}`, { method: 'POST' });
export const updateExamPolicy = (examId: string, hardwareUuid: string) =>
  fetchJson(`/policies/update/${examId}/${hardwareUuid}`, { method: 'POST' });

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

// /deployment/push is now admin-only, so this call has to carry the operator's bearer token.
// It previously went through an `api` object that does not exist in this module and never existed
// - the function could not have run - so it also never sent an Authorization header. Routing it
// through fetchJson attaches the token the same way every other call does.
export const deploymentApi = {
  pushDeploy: (data: DeploymentRequest): Promise<DeploymentResult[]> =>
    fetchJson('/deployment/push', { method: 'POST', body: JSON.stringify(data) }),
};
