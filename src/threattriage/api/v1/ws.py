"""WebSocket connection manager for real-time alert broadcasting."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["websocket"])


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Send a message to all connected clients."""
        dead: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for ws in dead:
            self.disconnect(ws)

    async def broadcast_alert(self, alert: dict[str, Any]) -> None:
        """Broadcast a new alert to all connected dashboard clients."""
        await self.broadcast({
            "type": "new_alert",
            "data": alert,
        })

    async def broadcast_incident(self, incident: dict[str, Any]) -> None:
        """Broadcast a new incident to all connected clients."""
        await self.broadcast({
            "type": "new_incident",
            "data": incident,
        })

    async def broadcast_stats_update(self, stats: dict[str, Any]) -> None:
        """Broadcast updated dashboard stats."""
        await self.broadcast({
            "type": "stats_update",
            "data": stats,
        })


# Singleton manager instance
manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time alert streaming."""
    await manager.connect(websocket)
    try:
        # Send a welcome message
        await websocket.send_json({
            "type": "connected",
            "data": {"message": "Connected to ThreatTriage alert stream"},
        })
        # Keep connection alive — listen for client pings
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.disconnect(websocket)
