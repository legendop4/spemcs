export type ID = string;

export type Theme = 'light' | 'dark' | 'system';

export type BuildingStatus = 'active' | 'maintenance' | 'inactive';
export type LabStatus = 'active' | 'maintenance' | 'inactive';
export type DeviceStatus = 'online' | 'offline' | 'maintenance';
export type ShieldStatus = 'protected' | 'partially' | 'unprotected';

export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';
export type AlertStatus = 'open' | 'investigating' | 'resolved' | 'dismissed';

export interface User {
  id: ID;
  name: string;
  email: string;
  password?: string;
  role: string;
  avatarColor?: string;
}

export interface Building {
  id: ID;
  name: string;
  code: string;
  location: string;
  description: string;
  status: BuildingStatus;
  createdAt: string;
}

export interface Lab {
  id: ID;
  name: string;
  code: string;
  buildingId: ID;
  capacity: number;
  description?: string;
  status: LabStatus;
  createdAt: string;
}

export interface Device {
  id: ID;
  hardware_uuid: string;
  name: string;
  building_name: string;
  lab_name: string;
  pc_number: string;
  ipAddress: string;
  status: DeviceStatus;
  shieldEnabled: boolean;
  createdAt: string;
  risk_score?: number;
  risk_level?: string;
}

export interface Alert {
  id?: ID;
  alert_id?: ID;
  event_id?: ID;
  exam_id?: ID;
  exam_name?: string;
  agent_event_id?: string;
  buildingId?: ID;
  labId?: ID | null;
  deviceId?: ID | null;
  device_id?: ID | null;
  device_name?: string;
  student_roll_number?: string;
  type?: string;
  event_type?: string;
  severity: AlertSeverity;
  message?: string;
  description?: string;
  reason?: string;
  process_name?: string | null;
  pid?: number | null;
  executable_path?: string | null;
  classification?: string | null;
  ip_address?: string | null;
  attachment?: string | null;
  status: AlertStatus | string;
  createdAt?: string;
  created_at?: string;
  updatedAt?: string;
}

export interface Exam {
  id: ID;
  examName: string;
  examLink: string;
  approvedBrowser: string;
  status: string;
  startedAt?: string;
  endedAt?: string;
  createdAt: string;
  deviceCount: number;
  alertCount: number;
  sessionCount: number;
}

export interface ExamSession {
  id: ID;
  examId: ID;
  deviceId: ID;
  studentRollNumber: string;
  startedAt: string;
  endedAt?: string;
}

export interface ExamDevice {
  examId: ID;
  deviceId: ID;
  status: string;
}

export interface DeviceTreeNode {
  id: string;
  name: string;
  type: 'building' | 'lab' | 'device';
  children?: DeviceTreeNode[];
  status?: string;
}

export interface Report {
  id: ID;
  examId: ID;
  generatedAt: string;
  generatedBy: ID;
  downloadUrl: string;
}

export interface AuditLog {
  id: ID;
  timestamp: string;
  user: string;
  action: string;
  entity: string;
  entityId: ID | null;
  description: string;
}

export interface Settings {
  theme: Theme;
  notifications: {
    securityAlerts: boolean;
    criticalAlerts: boolean;
    emailNotifications: boolean;
  };
  security: {
    shieldConfirmation: boolean;
    loginSecurity: boolean;
  };
}

export interface Session {
  userId: ID | null;
  remember: boolean;
}

export type WsMessageType =
  | 'INITIAL_STATE'
  | 'DEVICE_STATUS_CHANGE'
  | 'VIOLATION_ALERT'
  | 'SESSION_STARTED'
  | 'SESSION_ENDED'
  | 'EXAM_STATUS_CHANGE'
  | 'EXAM_ACTIVATED'
  | 'EXAM_DEACTIVATED'
  | 'HEARTBEAT_PING'
  | 'SUBSCRIBED'
  | 'UNSUBSCRIBED'
  | 'STATUS_SNAPSHOT'
  | 'REGISTERED';

export interface WsMessage {
  type: WsMessageType;
  payload?: any;
  exam_id?: string;
  timestamp?: string;
}

export interface DeploymentRequest {
  ips: string[];
  admin_username: string;
  admin_password: string;
  lab_name?: string;
  building_name?: string;
}

export interface DeploymentResult {
  ip: string;
  status: 'pending' | 'success' | 'failed';
  message?: string;
}
