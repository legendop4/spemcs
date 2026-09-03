/**
 * SPEMCS WebSocket Service
 * 
 * Connects to the dashboard WebSocket endpoint with:
 * - Auto-reconnect with exponential backoff
 * - Heartbeat ping/pong
 * - Exam room subscriptions
 * - Typed event dispatching
 * - State preservation across reconnects
 */

const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const WS_URL = `${wsProtocol}//${window.location.host}/api/v1/ws/dashboard`;

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

type MessageHandler = (message: WsMessage) => void;

export class SpemcsWebSocket {
  private ws: WebSocket | null = null;
  private handlers: Map<string, Set<MessageHandler>> = new Map();
  private globalHandlers: Set<MessageHandler> = new Set();
  private reconnectAttempts = 0;
  private maxReconnectDelay = 30000; // 30 seconds
  private baseReconnectDelay = 1000; // 1 second
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private subscribedExams: Set<string> = new Set();
  private _isConnected = false;
  private _isConnecting = false;
  private _shouldReconnect = true;

  get isConnected(): boolean {
    return this._isConnected;
  }

  connect(): void {
    if (this._isConnecting || this._isConnected) return;
    this._isConnecting = true;
    this._shouldReconnect = true;

    try {
      this.ws = new WebSocket(WS_URL);

      this.ws.onopen = () => {
        console.log('[WS] Connected to dashboard WebSocket');
        this._isConnected = true;
        this._isConnecting = false;
        this.reconnectAttempts = 0;
        this.startHeartbeat();

        // Re-subscribe to previously subscribed exams
        for (const examId of this.subscribedExams) {
          this.sendAction('SUBSCRIBE_EXAM', { exam_id: examId });
        }
      };

      this.ws.onmessage = (event) => {
        try {
          const rawMessage = JSON.parse(event.data);
          const message: WsMessage = parseNaiveDates(rawMessage);
          this.dispatch(message);

          // Auto-respond to heartbeat
          if (message.type === 'HEARTBEAT_PING') {
            this.sendAction('HEARTBEAT_PONG', {});
          }
        } catch (err) {
          console.error('[WS] Failed to parse message:', err);
        }
      };

      this.ws.onclose = (event) => {
        console.log(`[WS] Disconnected (code: ${event.code}, reason: ${event.reason})`);
        this._isConnected = false;
        this._isConnecting = false;
        this.stopHeartbeat();

        if (this._shouldReconnect) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = (error) => {
        console.error('[WS] Error:', error);
        this._isConnecting = false;
      };
    } catch (err) {
      console.error('[WS] Failed to create WebSocket:', err);
      this._isConnecting = false;
      if (this._shouldReconnect) {
        this.scheduleReconnect();
      }
    }
  }

  disconnect(): void {
    this._shouldReconnect = false;
    this.stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }
    this._isConnected = false;
    this._isConnecting = false;
  }

  // --- Exam Room Subscriptions ---

  subscribeExam(examId: string): void {
    this.subscribedExams.add(examId);
    if (this._isConnected) {
      this.sendAction('SUBSCRIBE_EXAM', { exam_id: examId });
    }
  }

  unsubscribeExam(examId: string): void {
    this.subscribedExams.delete(examId);
    if (this._isConnected) {
      this.sendAction('UNSUBSCRIBE_EXAM', { exam_id: examId });
    }
  }

  // --- Event Handlers ---

  on(type: WsMessageType | '*', handler: MessageHandler): () => void {
    if (type === '*') {
      this.globalHandlers.add(handler);
      return () => this.globalHandlers.delete(handler);
    }
    if (!this.handlers.has(type)) {
      this.handlers.set(type, new Set());
    }
    this.handlers.get(type)!.add(handler);
    return () => this.handlers.get(type)?.delete(handler);
  }

  off(type: WsMessageType | '*', handler: MessageHandler): void {
    if (type === '*') {
      this.globalHandlers.delete(handler);
    } else {
      this.handlers.get(type)?.delete(handler);
    }
  }

  // --- Internal ---

  private sendAction(action: string, data: Record<string, any>): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ action, ...data }));
    }
  }

  private dispatch(message: WsMessage): void {
    // Type-specific handlers
    const handlers = this.handlers.get(message.type);
    if (handlers) {
      for (const handler of handlers) {
        try {
          handler(message);
        } catch (err) {
          console.error(`[WS] Handler error for ${message.type}:`, err);
        }
      }
    }
    // Global handlers
    for (const handler of this.globalHandlers) {
      try {
        handler(message);
      } catch (err) {
        console.error('[WS] Global handler error:', err);
      }
    }
  }

  private scheduleReconnect(): void {
    const delay = Math.min(
      this.baseReconnectDelay * Math.pow(2, this.reconnectAttempts),
      this.maxReconnectDelay
    );
    console.log(`[WS] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts + 1})`);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectAttempts++;
      this.connect();
    }, delay);
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatInterval = setInterval(() => {
      if (this._isConnected) {
        this.sendAction('HEARTBEAT_PONG', {});
      }
    }, 30000);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }
}

// Singleton instance
export const wsClient = new SpemcsWebSocket();

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
