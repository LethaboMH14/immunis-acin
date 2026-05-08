// frontend/src/providers/WebSocketProvider.tsx
// Centralised WebSocket connection for IMMUNIS ACIN real-time events
// WHY: The dashboard is real-time. Pipeline stages, battleground rounds,
// mesh broadcasts, immunity updates — all arrive via WebSocket.
// One connection, auto-reconnect, typed event distribution.

import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  useCallback,
  type ReactNode,
} from 'react';
import { WS_URL } from '../utils/constants';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ConnectionStatus =
  | 'connecting'
  | 'connected'
  | 'disconnected'
  | 'error';

export interface WSMessage {
  type: string;
  data: Record<string, unknown>;
  timestamp: string;
}

type EventCallback = (data: Record<string, unknown>) => void;

interface WebSocketContextValue {
  /** Current connection status */
  status: ConnectionStatus;
  /** Last received message (any type) */
  lastMessage: WSMessage | null;
  /** Subscribe to a specific event type. Returns unsubscribe function. */
  subscribe: (eventType: string, callback: EventCallback) => () => void;
  /** Send a message to the backend */
  sendMessage: (message: Record<string, unknown>) => void;
  /** Force reconnect */
  reconnect: () => void;
  /** Total messages received this session */
  messageCount: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const INITIAL_RETRY_DELAY = 1000;
const MAX_RETRY_DELAY = 30000;
const MAX_RETRIES = 5;
const HEARTBEAT_INTERVAL = 30000;

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const WebSocketContext = createContext<WebSocketContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

interface WebSocketProviderProps {
  children: ReactNode;
  /** Override WebSocket URL (for testing) */
  url?: string;
  /** Disable auto-connect (for testing) */
  disabled?: boolean;
}

export function WebSocketProvider({
  children,
  url = WS_URL,
  disabled = false,
}: WebSocketProviderProps) {
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null);
  const [messageCount, setMessageCount] = useState(0);

  const wsRef = useRef<WebSocket | null>(null);
  const retriesRef = useRef(0);
  const retryDelayRef = useRef(INITIAL_RETRY_DELAY);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const heartbeatTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const subscribersRef = useRef<Map<string, Set<EventCallback>>>(new Map());
  const mountedRef = useRef(true);

  // -----------------------------------------------------------------------
  // Subscriber management
  // -----------------------------------------------------------------------

  const subscribe = useCallback(
    (eventType: string, callback: EventCallback): (() => void) => {
      if (!subscribersRef.current.has(eventType)) {
        subscribersRef.current.set(eventType, new Set());
      }
      subscribersRef.current.get(eventType)!.add(callback);

      // Return unsubscribe function
      return () => {
        const subs = subscribersRef.current.get(eventType);
        if (subs) {
          subs.delete(callback);
          if (subs.size === 0) {
            subscribersRef.current.delete(eventType);
          }
        }
      };
    },
    []
  );

  // -----------------------------------------------------------------------
  // Dispatch to subscribers
  // -----------------------------------------------------------------------

  const dispatch = useCallback((msg: WSMessage) => {
    // Notify type-specific subscribers
    const typeSubs = subscribersRef.current.get(msg.type);
    if (typeSubs) {
      typeSubs.forEach((cb) => {
        try {
          cb(msg.data);
        } catch (err) {
          console.error(
            `[WS] Subscriber error for event "${msg.type}":`,
            err
          );
        }
      });
    }

    // Notify wildcard subscribers (subscribe to '*')
    const wildcardSubs = subscribersRef.current.get('*');
    if (wildcardSubs) {
      wildcardSubs.forEach((cb) => {
        try {
          cb({ type: msg.type, ...msg.data });
        } catch (err) {
          console.error('[WS] Wildcard subscriber error:', err);
        }
      });
    }
  }, []);

  // -----------------------------------------------------------------------
  // Heartbeat
  // -----------------------------------------------------------------------

  const startHeartbeat = useCallback(() => {
    stopHeartbeat();
    heartbeatTimerRef.current = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'ping' }));
      }
    }, HEARTBEAT_INTERVAL);
  }, []);

  const stopHeartbeat = useCallback(() => {
    if (heartbeatTimerRef.current) {
      clearInterval(heartbeatTimerRef.current);
      heartbeatTimerRef.current = null;
    }
  }, []);

  // -----------------------------------------------------------------------
  // Connection
  // -----------------------------------------------------------------------

  const connect = useCallback(() => {
    if (disabled || !mountedRef.current) return;

    // Clean up existing connection
    if (wsRef.current) {
      wsRef.current.onopen = null;
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      wsRef.current.onmessage = null;
      if (
        wsRef.current.readyState === WebSocket.OPEN ||
        wsRef.current.readyState === WebSocket.CONNECTING
      ) {
        wsRef.current.close();
      }
    }

    setStatus('connecting');

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        setStatus('connected');
        retriesRef.current = 0;
        retryDelayRef.current = INITIAL_RETRY_DELAY;
        startHeartbeat();
        console.log('[WS] Connected to', url);
      };

      ws.onmessage = (event: MessageEvent) => {
        if (!mountedRef.current) return;
        try {
          const msg = JSON.parse(event.data as string) as WSMessage;
          // Skip pong responses
          if (msg.type === 'pong') return;

          setLastMessage(msg);
          setMessageCount((c) => c + 1);
          dispatch(msg);
        } catch (err) {
          console.error('[WS] Failed to parse message:', err);
        }
      };

      ws.onclose = (event: CloseEvent) => {
        if (!mountedRef.current) return;
        stopHeartbeat();
        setStatus('disconnected');
        console.log(
          `[WS] Disconnected (code: ${event.code}, reason: ${event.reason})`
        );

        // Auto-reconnect unless intentionally closed
        if (event.code !== 1000 && retriesRef.current < MAX_RETRIES) {
          const delay = Math.min(retryDelayRef.current, MAX_RETRY_DELAY);
          const attempt = retriesRef.current + 1;
          // Suppress console.log after attempt 3
          if (attempt <= 3) {
            console.log(
              `[WS] Reconnecting in ${delay}ms (attempt ${attempt}/${MAX_RETRIES})`
            );
          }
          retryTimerRef.current = setTimeout(() => {
            retriesRef.current += 1;
            retryDelayRef.current *= 2;
            connect();
          }, delay);
        }
      };

      ws.onerror = () => {
        if (!mountedRef.current) return;
        setStatus('error');
      };
    } catch (err) {
      console.error('[WS] Connection error:', err);
      setStatus('error');
    }
  }, [url, disabled, dispatch, startHeartbeat, stopHeartbeat]);

  // -----------------------------------------------------------------------
  // Send message
  // -----------------------------------------------------------------------

  const sendMessage = useCallback((message: Record<string, unknown>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    } else {
      console.warn('[WS] Cannot send — not connected');
    }
  }, []);

  // -----------------------------------------------------------------------
  // Manual reconnect
  // -----------------------------------------------------------------------

  const reconnect = useCallback(() => {
    retriesRef.current = 0;
    retryDelayRef.current = INITIAL_RETRY_DELAY;
    if (retryTimerRef.current) {
      clearTimeout(retryTimerRef.current);
      retryTimerRef.current = null;
    }
    connect();
  }, [connect]);

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      stopHeartbeat();
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current);
      }
      if (wsRef.current) {
        wsRef.current.onopen = null;
        wsRef.current.onclose = null;
        wsRef.current.onerror = null;
        wsRef.current.onmessage = null;
        wsRef.current.close(1000, 'Component unmounted');
      }
    };
  }, [connect, stopHeartbeat]);

  return (
    <WebSocketContext.Provider
      value={{
        status,
        lastMessage,
        subscribe,
        sendMessage,
        reconnect,
        messageCount,
      }}
    >
      {children}
    </WebSocketContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useWebSocket(): WebSocketContextValue {
  const ctx = useContext(WebSocketContext);
  if (!ctx) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return ctx;
}
