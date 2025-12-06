from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Set
import json
import asyncio

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
    
    async def connect(self, websocket: WebSocket):
        """Accept and track a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        self.active_connections.discard(websocket)
    
    async def broadcast(self, event_type: str, data: dict):
        """Broadcast a message to all connected clients."""
        message = json.dumps({
            "type": event_type,
            "data": data
        }, default=str)  # Handle datetime serialization
        
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.add(connection)
        
        # Clean up disconnected clients
        self.active_connections -= disconnected
    
    async def send_personal(self, websocket: WebSocket, event_type: str, data: dict):
        """Send a message to a specific client."""
        message = json.dumps({
            "type": event_type,
            "data": data
        }, default=str)
        await websocket.send_text(message)


# Global connection manager
manager = ConnectionManager()


async def scanner_callback(event_type: str, data: dict):
    """Callback for scanner events to broadcast to WebSocket clients."""
    await manager.broadcast(event_type, data)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)
    
    try:
        # Send initial connection confirmation
        await manager.send_personal(websocket, "connected", {
            "message": "Connected to LAN Monitor WebSocket"
        })
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for messages (with timeout to check connection)
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                
                # Parse and handle incoming messages
                try:
                    message = json.loads(data)
                    msg_type = message.get("type")
                    
                    if msg_type == "ping":
                        await manager.send_personal(websocket, "pong", {})
                    elif msg_type == "subscribe":
                        # Handle subscription requests (future feature)
                        await manager.send_personal(websocket, "subscribed", {
                            "topic": message.get("topic")
                        })
                except json.JSONDecodeError:
                    pass
                    
            except asyncio.TimeoutError:
                # Send keepalive ping
                try:
                    await manager.send_personal(websocket, "ping", {})
                except Exception:
                    break
                    
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)
