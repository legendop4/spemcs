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
    device_name: Optional[str] = None
    device_id: Optional[str] = None
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
    
    async def register_device(
        self,
        ws: WebSocket,
        hardware_uuid: str,
        device_name: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> None:
        """Register a device agent connection by its hardware UUID and enrolled identity."""
        async with self._lock:
            # 1. Clean up any previous registration keys tied to this specific WebSocket
            prev_info = self._connection_meta.get(ws)
            if prev_info:
                if prev_info.hardware_uuid and self._device_connections.get(prev_info.hardware_uuid) == ws:
                    del self._device_connections[prev_info.hardware_uuid]
                if prev_info.device_name and self._device_connections.get(prev_info.device_name) == ws:
                    del self._device_connections[prev_info.device_name]
                if prev_info.device_id and self._device_connections.get(prev_info.device_id) == ws:
                    del self._device_connections[prev_info.device_id]

            # 2. Check for any OLD sockets that belonged to this hardware_uuid, device_name, or device_id
            keys_to_check = [k for k in (hardware_uuid, device_name, device_id) if k]
            old_sockets: Set[WebSocket] = set()
            for key in keys_to_check:
                old_ws = self._device_connections.get(key)
                if old_ws and old_ws != ws:
                    old_sockets.add(old_ws)

            for old_ws in old_sockets:
                logger.warning(f"Device reconnected with identity {keys_to_check}; closing old connection")
                await self._safe_close(old_ws, reason="Replaced by new connection")
                self._cleanup_connection_under_lock(old_ws)

            # 3. Associate keys with this active socket
            self._device_connections[hardware_uuid] = ws
            if device_name:
                self._device_connections[device_name] = ws
            if device_id:
                self._device_connections[str(device_id)] = ws

            # Also cache device_id mapping
            if device_id:
                self._device_id_map[hardware_uuid] = str(device_id)
                if device_name:
                    self._device_id_map[device_name] = str(device_id)

            # 4. Update or create ConnectionInfo
            self._connection_meta[ws] = ConnectionInfo(
                ws=ws,
                hardware_uuid=hardware_uuid,
                device_name=device_name,
                device_id=str(device_id) if device_id else None,
                client_type="agent",
            )
        
        logger.info(f"Device registered: {hardware_uuid} (device_name={device_name}, device_id={device_id})")
    
    async def unregister_device(self, ws: WebSocket) -> Optional[str]:
        """Unregister a device agent. Socket-aware: only removes entries if they still point to ws."""
        async with self._lock:
            info = self._connection_meta.get(ws)
            if not info:
                self._cleanup_connection_under_lock(ws)
                return None
            
            hw_uuid = info.hardware_uuid
            dev_name = info.device_name
            dev_id = info.device_id

            if hw_uuid and self._device_connections.get(hw_uuid) == ws:
                del self._device_connections[hw_uuid]
            if dev_name and self._device_connections.get(dev_name) == ws:
                del self._device_connections[dev_name]
            if dev_id and self._device_connections.get(dev_id) == ws:
                del self._device_connections[dev_id]

            self._cleanup_connection_under_lock(ws)
        
        logger.info(f"Device unregistered: {hw_uuid} (device_name={dev_name})")
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

    async def resolve_device_connection(self, target_identifier: str) -> Optional[WebSocket]:
        """Resolve a target identifier to an active WebSocket connection.
        
        Strict resolution order:
        1. Exact connected hardware_uuid
        2. Exact connected enrolled device identity (device_name or device_id)
        3. Authenticated enrollment-transition alias only when provably the same enrolled device (same device_id)
        
        If ambiguity exists or target is not connected, returns None.
        NEVER uses client IP for identity resolution.
        """
        async with self._lock:
            # Step 1: Exact connected hardware_uuid match
            for ws, info in self._connection_meta.items():
                if info.hardware_uuid and info.hardware_uuid == target_identifier:
                    return ws
            
            ws = self._device_connections.get(target_identifier)
            if ws and ws in self._connection_meta:
                info = self._connection_meta[ws]
                if info.hardware_uuid == target_identifier:
                    return ws

            # Step 2: Exact connected enrolled device identity (device_name or device_id)
            name_or_id_matches = []
            for ws, info in self._connection_meta.items():
                if (info.device_name and info.device_name == target_identifier) or \
                   (info.device_id and info.device_id == target_identifier):
                    name_or_id_matches.append(ws)

            if len(name_or_id_matches) == 1:
                return name_or_id_matches[0]
            elif len(name_or_id_matches) > 1:
                logger.warning(
                    f"Ambiguous device resolution for '{target_identifier}': {len(name_or_id_matches)} matching connections. Refusing to guess."
                )
                return None

            # Step 3: Authenticated enrollment-transition alias only when provably the same enrolled device.
            mapped_device_id = self._device_id_map.get(target_identifier)
            if not mapped_device_id:
                try:
                    from backend.app.database import SessionLocal
                    from backend.models.device import Device
                    db = SessionLocal()
                    dev = db.query(Device).filter(
                        (Device.hardware_uuid == target_identifier) | (Device.device_name == target_identifier)
                    ).first()
                    if dev:
                        mapped_device_id = str(dev.device_id)
                        self._device_id_map[target_identifier] = mapped_device_id
                    db.close()
                except Exception:
                    pass

            if mapped_device_id:
                alias_matches = []
                for ws, info in self._connection_meta.items():
                    if info.device_id and info.device_id == mapped_device_id:
                        alias_matches.append(ws)
                if len(alias_matches) == 1:
                    logger.info(f"Resolved '{target_identifier}' via provable enrolled device_id alias: {mapped_device_id}")
                    return alias_matches[0]
                elif len(alias_matches) > 1:
                    logger.warning(
                        f"Ambiguous alias resolution for '{target_identifier}' (device_id={mapped_device_id}): {len(alias_matches)} connections."
                    )
                    return None

            return None
    
    async def send_to_device(self, hardware_uuid: str, payload: dict) -> bool:
        """Send a targeted message to a specific device by hardware_uuid, device_name, or device_id.
        Returns True if the message was sent successfully."""
        ws = await self.resolve_device_connection(hardware_uuid)
        if not ws:
            logger.warning(f"Cannot send to device '{hardware_uuid}': not connected or identity unresolved")
            return False
        
        try:
            await ws.send_json(payload)
            return True
        except Exception as e:
            logger.error(f"Failed to send to device '{hardware_uuid}': {e}")
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
            "action": message_type,
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
        """Return set of hardware_uuids and device_names currently connected."""
        result = set()
        for info in self._connection_meta.values():
            if info.hardware_uuid:
                result.add(info.hardware_uuid)
            if info.device_name:
                result.add(info.device_name)
        return result
    
    def is_device_online(self, identifier: str) -> bool:
        """Check if a specific device is currently connected."""
        if identifier in self._device_connections:
            return True
        for info in self._connection_meta.values():
            if info.hardware_uuid == identifier or info.device_name == identifier or info.device_id == identifier:
                return True
        mapped_id = self._device_id_map.get(identifier)
        if mapped_id:
            for info in self._connection_meta.values():
                if info.device_id == mapped_id:
                    return True
        return False
    
    def get_dashboard_count(self) -> int:
        """Return number of connected dashboard clients."""
        return len(self._dashboard_connections)
    
    def get_device_count(self) -> int:
        """Return number of connected device agents."""
        return sum(1 for info in self._connection_meta.values() if info.client_type == "agent")
    
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
                try:
                    from backend.websocket.agent_ws import _update_device_presence
                    from fastapi.concurrency import run_in_threadpool
                    await run_in_threadpool(_update_device_presence, hw_uuid, False)
                except Exception as db_err:
                    logger.error(f"Failed to update device presence on heartbeat loss: {db_err}")

        
        # Check dashboard connections
        for ws in list(self._dashboard_connections):
            try:
                await ws.send_json({"type": "HEARTBEAT_PING", "timestamp": datetime.utcnow().isoformat()})
            except Exception:
                await self.unregister_dashboard(ws)
        
        return disconnected
    
    # --- Internal Helpers ---
    
    def _cleanup_connection_under_lock(self, ws: WebSocket) -> None:
        """Remove WebSocket from all mappings under lock."""
        keys_to_remove = [k for k, v in self._device_connections.items() if v == ws]
        for k in keys_to_remove:
            del self._device_connections[k]
        self._connection_meta.pop(ws, None)
        self._dashboard_connections.discard(ws)

    def _cleanup_connection(self, ws: WebSocket) -> None:
        """Remove all traces of a WebSocket connection (must be called under lock)."""
        self._cleanup_connection_under_lock(ws)
    
    async def _safe_close(self, ws: WebSocket, reason: str = "Connection closed") -> None:
        """Safely close a WebSocket connection."""
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.close(code=1000, reason=reason)
        except Exception:
            pass


# Singleton instance used across the application
realtime_manager = RealtimeManager()
