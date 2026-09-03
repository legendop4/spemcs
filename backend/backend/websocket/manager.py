"""RealtimeManager — Thread-safe WebSocket connection manager with
device registry, exam room subscriptions, heartbeat, and targeted messaging."""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, Set

from fastapi import WebSocket
from starlette.websockets import WebSocketState

logger = logging.getLogger(__name__)


@dataclass
class ConnectionInfo:
    """Metadata attached to each WebSocket connection."""
    ws: WebSocket
    connected_at: datetime = field(default_factory=datetime.utcnow)
    hardware_uuid: Optional[str] = None  # set for device agents
    client_type: str = "unknown"  # 'agent' or 'dashboard'
    subscribed_exams: Set[str] = field(default_factory=set)
    last_pong: datetime = field(default_factory=datetime.utcnow)


class RealtimeManager:
    """Centralized WebSocket connection manager.
    
    Responsibilities:
    - Device registry: hardware_uuid -> WebSocket mapping
    - Exam rooms: exam_id -> set of dashboard WebSocket connections
    - Dashboard subscribers: connections receiving device status updates
    - Heartbeat: periodic ping/pong to detect dead connections
    - Targeted messaging: send commands to specific devices
    """

    def __init__(self):
        # Device agent connections: hardware_uuid -> WebSocket
        self._device_connections: Dict[str, WebSocket] = {}
        
        # Dashboard/proctor connections subscribed to exam rooms: exam_id -> set[WebSocket]
        self._exam_rooms: Dict[str, Set[WebSocket]] = {}
        
        # All dashboard connections (for global device status broadcasts)
        self._dashboard_connections: Set[WebSocket] = set()
        
        # Reverse lookup: WebSocket -> ConnectionInfo
        self._connection_meta: Dict[WebSocket, ConnectionInfo] = {}
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
        
        # Cache for active exams and their assigned devices (both hardware_uuid and device_name mapped to exam_id)
        self._active_exams: Dict[str, Set[str]] = {}
        self._device_exam_map: Dict[str, str] = {}
        
        # Cache for device identifier -> database device_id (UUID string)
        self._device_id_map: Dict[str, str] = {}

    def set_exam_active(self, exam_id: str, device_identifiers: list[str]) -> None:
        """Register an active exam and its assigned devices in the cache."""
        self._active_exams[exam_id] = set(device_identifiers)
        for dev_id in device_identifiers:
            self._device_exam_map[dev_id] = exam_id
        logger.info(f"Cache: Exam {exam_id} marked active with {len(device_identifiers)} devices")

    def set_exam_inactive(self, exam_id: str) -> None:
        """Remove an exam and its device mappings from the cache."""
        device_identifiers = self._active_exams.pop(exam_id, set())
        for dev_id in device_identifiers:
            self._device_exam_map.pop(dev_id, None)
        logger.info(f"Cache: Exam {exam_id} marked inactive")

    def get_active_exam_for_device(self, device_identifier: str) -> Optional[str]:
        """Get the active exam ID for a device from the cache."""
        return self._device_exam_map.get(device_identifier)

    def register_device_id(self, device_identifier: str, device_id: str) -> None:
        """Cache the database device_id for a device identifier."""
        self._device_id_map[device_identifier] = device_id

    def get_device_id(self, device_identifier: str) -> Optional[str]:
        """Retrieve the cached database device_id for a device identifier."""
        return self._device_id_map.get(device_identifier)

    
    # --- Device Agent Management ---
    
    async def register_device(self, ws: WebSocket, hardware_uuid: str) -> None:
        """Register a device agent connection by its hardware UUID."""
        async with self._lock:
            # If this UUID already has a connection, close the old one
            old_ws = self._device_connections.get(hardware_uuid)
            if old_ws and old_ws != ws:
                logger.warning(f"Device {hardware_uuid} reconnected, closing old connection")
                await self._safe_close(old_ws, reason="Replaced by new connection")
                self._cleanup_connection(old_ws)
            
            self._device_connections[hardware_uuid] = ws
            
            # Update or create connection info
            if ws in self._connection_meta:
                self._connection_meta[ws].hardware_uuid = hardware_uuid
                self._connection_meta[ws].client_type = "agent"
            else:
                self._connection_meta[ws] = ConnectionInfo(
                    ws=ws, hardware_uuid=hardware_uuid, client_type="agent"
                )
        
        logger.info(f"Device registered: {hardware_uuid}")
    
    async def unregister_device(self, ws: WebSocket) -> Optional[str]:
        """Unregister a device agent. Returns the hardware_uuid if found."""
        async with self._lock:
            info = self._connection_meta.get(ws)
            if not info or not info.hardware_uuid:
                self._cleanup_connection(ws)
                return None
            
            hw_uuid = info.hardware_uuid
            if self._device_connections.get(hw_uuid) == ws:
                del self._device_connections[hw_uuid]
            
            self._cleanup_connection(ws)
        
        logger.info(f"Device unregistered: {hw_uuid}")
        return hw_uuid
    
    # --- Dashboard Connection Management ---
    
    async def register_dashboard(self, ws: WebSocket) -> None:
        """Register a dashboard/proctor WebSocket connection."""
        async with self._lock:
            self._dashboard_connections.add(ws)
            self._connection_meta[ws] = ConnectionInfo(
                ws=ws, client_type="dashboard"
            )
        logger.info("Dashboard client connected")
    
    async def unregister_dashboard(self, ws: WebSocket) -> None:
        """Unregister a dashboard connection and clean up room subscriptions."""
        async with self._lock:
            self._dashboard_connections.discard(ws)
            info = self._connection_meta.get(ws)
            if info:
                for exam_id in info.subscribed_exams:
                    room = self._exam_rooms.get(exam_id)
                    if room:
                        room.discard(ws)
                        if not room:
                            del self._exam_rooms[exam_id]
            self._cleanup_connection(ws)
        logger.info("Dashboard client disconnected")
    
    # --- Exam Room Subscriptions ---
    
    async def subscribe_exam(self, ws: WebSocket, exam_id: str) -> None:
        """Subscribe a dashboard connection to an exam room."""
        async with self._lock:
            if exam_id not in self._exam_rooms:
                self._exam_rooms[exam_id] = set()
            self._exam_rooms[exam_id].add(ws)
            
            info = self._connection_meta.get(ws)
            if info:
                info.subscribed_exams.add(exam_id)
        
        logger.info(f"Dashboard subscribed to exam {exam_id}")
    
    async def unsubscribe_exam(self, ws: WebSocket, exam_id: str) -> None:
        """Unsubscribe a dashboard connection from an exam room."""
        async with self._lock:
            room = self._exam_rooms.get(exam_id)
            if room:
                room.discard(ws)
                if not room:
                    del self._exam_rooms[exam_id]
            
            info = self._connection_meta.get(ws)
            if info:
                info.subscribed_exams.discard(exam_id)
    
    # --- Targeted Messaging ---
    
    async def send_to_device(self, hardware_uuid: str, payload: dict) -> bool:
        """Send a targeted message to a specific device by hardware UUID.
        Returns True if the message was sent successfully."""
        ws = self._device_connections.get(hardware_uuid)
        if not ws:
            logger.warning(f"Cannot send to device {hardware_uuid}: not connected")
            return False
        
        try:
            await ws.send_json(payload)
            return True
        except Exception as e:
            logger.error(f"Failed to send to device {hardware_uuid}: {e}")
            await self.unregister_device(ws)
            return False

    async def send_signed_policy_to_device(
        self,
        hardware_uuid: str,
        raw_policy_json: str,
        signature_base64: str,
        message_type: str = "SIGNED_NETWORK_POLICY",
    ) -> bool:
        """Send a signed network policy to a specific device over WebSocket."""
        payload = {
            "message_type": message_type,
            "protocol_version": 1,
            "raw_policy_json": raw_policy_json,
            "signature_base64": signature_base64,
        }
        return await self.send_to_device(hardware_uuid, payload)
    
    async def broadcast_to_exam(self, exam_id: str, payload: dict) -> int:
        """Broadcast a message to all dashboard connections subscribed to an exam.
        Returns the number of connections that received the message."""
        room = self._exam_rooms.get(exam_id)
        if not room:
            return 0
        
        sent = 0
        dead = []
        for ws in list(room):
            try:
                await ws.send_json(payload)
                sent += 1
            except Exception:
                dead.append(ws)
        
        # Clean up dead connections
        for ws in dead:
            await self.unregister_dashboard(ws)
        
        return sent
    
    async def broadcast_to_dashboard(self, payload: dict) -> int:
        """Broadcast a message to ALL dashboard connections (e.g., device status changes).
        Returns the number of connections that received the message."""
        sent = 0
        dead = []
        for ws in list(self._dashboard_connections):
            try:
                await ws.send_json(payload)
                sent += 1
            except Exception:
                dead.append(ws)
        
        for ws in dead:
            await self.unregister_dashboard(ws)
        
        return sent
    
    async def send_to_exam_devices(self, device_uuids: list[str], payload: dict) -> dict:
        """Send a message to multiple devices concurrently with a timeout. Returns {uuid: success_bool}."""
        import asyncio
        
        async def _safe_send(uuid: str) -> tuple[str, bool]:
            try:
                success = await asyncio.wait_for(self.send_to_device(uuid, payload), timeout=2.0)
                return uuid, success
            except Exception as e:
                logger.error(f"Timeout or error sending to device {uuid}: {e}")
                return uuid, False

        tasks = [_safe_send(uuid) for uuid in device_uuids]
        completed = await asyncio.gather(*tasks)
        return dict(completed)
    
    # --- Presence Queries ---
    
    def get_online_devices(self) -> set[str]:
        """Return set of hardware_uuids currently connected."""
        return set(self._device_connections.keys())
    
    def is_device_online(self, hardware_uuid: str) -> bool:
        """Check if a specific device is currently connected."""
        return hardware_uuid in self._device_connections
    
    def get_dashboard_count(self) -> int:
        """Return number of connected dashboard clients."""
        return len(self._dashboard_connections)
    
    def get_device_count(self) -> int:
        """Return number of connected device agents."""
        return len(self._device_connections)
    
    def get_exam_room_count(self, exam_id: str) -> int:
        """Return number of dashboard clients watching a specific exam."""
        room = self._exam_rooms.get(exam_id)
        return len(room) if room else 0
    
    # --- Heartbeat ---
    
    async def heartbeat_check(self) -> list[str]:
        """Check all connections with a ping. Returns list of disconnected hardware_uuids."""
        disconnected = []
        
        # Check device connections
        for hw_uuid, ws in list(self._device_connections.items()):
            try:
                await ws.send_json({"type": "HEARTBEAT_PING", "timestamp": datetime.utcnow().isoformat()})
            except Exception:
                logger.warning(f"Device {hw_uuid} failed heartbeat")
                disconnected.append(hw_uuid)
                await self.unregister_device(ws)
        
        # Check dashboard connections
        for ws in list(self._dashboard_connections):
            try:
                await ws.send_json({"type": "HEARTBEAT_PING", "timestamp": datetime.utcnow().isoformat()})
            except Exception:
                await self.unregister_dashboard(ws)
        
        return disconnected
    
    # --- Internal Helpers ---
    
    def _cleanup_connection(self, ws: WebSocket) -> None:
        """Remove all traces of a WebSocket connection (must be called under lock)."""
        self._connection_meta.pop(ws, None)
        self._dashboard_connections.discard(ws)
    
    async def _safe_close(self, ws: WebSocket, reason: str = "Connection closed") -> None:
        """Safely close a WebSocket connection."""
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.close(code=1000, reason=reason)
        except Exception:
            pass


# Singleton instance used across the application
realtime_manager = RealtimeManager()
