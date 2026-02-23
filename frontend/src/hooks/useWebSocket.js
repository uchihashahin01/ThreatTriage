import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * Reusable WebSocket hook with auto-reconnect and message parsing.
 * @param {string} url - WebSocket URL (e.g., ws://localhost:8000/ws/alerts)
 * @param {object} options - { onMessage, onConnect, onDisconnect, reconnectInterval }
 */
export default function useWebSocket(url, options = {}) {
    const {
        onMessage,
        onConnect,
        onDisconnect,
        reconnectInterval = 3000,
        enabled = true,
    } = options;

    const [isConnected, setIsConnected] = useState(false);
    const [lastMessage, setLastMessage] = useState(null);
    const wsRef = useRef(null);
    const reconnectTimer = useRef(null);
    const mountedRef = useRef(true);

    const connect = useCallback(() => {
        if (!enabled || !mountedRef.current) return;

        try {
            const ws = new WebSocket(url);
            wsRef.current = ws;

            ws.onopen = () => {
                if (!mountedRef.current) return;
                setIsConnected(true);
                onConnect?.();
                // Start ping interval to keep connection alive
                ws._pingInterval = setInterval(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send('ping');
                    }
                }, 30000);
            };

            ws.onmessage = (event) => {
                if (!mountedRef.current) return;
                try {
                    const data = JSON.parse(event.data);
                    setLastMessage(data);
                    onMessage?.(data);
                } catch (e) {
                    // Ignore non-JSON messages
                }
            };

            ws.onclose = () => {
                if (!mountedRef.current) return;
                setIsConnected(false);
                onDisconnect?.();
                clearInterval(ws._pingInterval);
                // Auto-reconnect
                reconnectTimer.current = setTimeout(() => {
                    if (mountedRef.current && enabled) connect();
                }, reconnectInterval);
            };

            ws.onerror = () => {
                ws.close();
            };
        } catch (e) {
            // Connection failed — retry
            reconnectTimer.current = setTimeout(() => {
                if (mountedRef.current && enabled) connect();
            }, reconnectInterval);
        }
    }, [url, enabled, onMessage, onConnect, onDisconnect, reconnectInterval]);

    useEffect(() => {
        mountedRef.current = true;
        connect();

        return () => {
            mountedRef.current = false;
            clearTimeout(reconnectTimer.current);
            if (wsRef.current) {
                clearInterval(wsRef.current._pingInterval);
                wsRef.current.close();
            }
        };
    }, [connect]);

    return { isConnected, lastMessage };
}
