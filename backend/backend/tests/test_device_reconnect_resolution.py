"""Tests for device reconnect, enrolled identity resolution, and socket-aware lifecycle.

Verifies:
1. Exact connected hardware_uuid delivery.
2. Exact connected enrolled device identity (device_name or device_id) delivery.
3. Authenticated enrollment-transition alias delivery only when provably the same enrolled device.
4. Ambiguous device resolution fails closed (returns None, never guesses).
5. IP match is NEVER used for policy delivery.
6. Reconnect replaces old registration cleanly (e.g. DESKTOP-3 replaced by NetworkLab-PC2557).
7. Socket-aware unregistration does not remove the newer socket when an older socket unregisters late.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from fastapi import WebSocket
from backend.websocket.manager import RealtimeManager, ConnectionInfo


class MockWebSocket:
    """Mock WebSocket for unit testing RealtimeManager."""
    def __init__(self, client_state=1):
        self.client_state = client_state
        self.sent_messages = []
        self.closed = False
        self.close_code = None
        self.close_reason = None

    async def send_json(self, payload):
        if self.closed:
            raise RuntimeError("WebSocket is closed")
        self.sent_messages.append(payload)

    async def close(self, code=1000, reason=""):
        self.closed = True
        self.close_code = code
        self.close_reason = reason


@pytest.fixture
def manager():
    return RealtimeManager()


def test_exact_connected_hardware_uuid_resolution(manager):
    """Step 1: Exact connected hardware_uuid resolves successfully."""
    async def _run():
        ws = MockWebSocket()
        await manager.register_device(
            ws,
            hardware_uuid="hw-uuid-1234",
            device_name="Lab01-PC01",
            device_id="dev-uuid-aaa",
        )

        resolved = await manager.resolve_device_connection("hw-uuid-1234")
        assert resolved is ws

        sent = await manager.send_to_device("hw-uuid-1234", {"type": "TEST"})
        assert sent is True
        assert len(ws.sent_messages) == 1
        assert ws.sent_messages[0] == {"type": "TEST"}

    asyncio.run(_run())


def test_exact_enrolled_device_name_and_id_resolution(manager):
    """Step 2: Exact enrolled device_name or device_id resolves when targeted."""
    async def _run():
        ws = MockWebSocket()
        await manager.register_device(
            ws,
            hardware_uuid="hw-uuid-pc2557",
            device_name="NetworkLab-PC2557",
            device_id="dev-db-id-2557",
        )

        # Resolve by device_name
        resolved_by_name = await manager.resolve_device_connection("NetworkLab-PC2557")
        assert resolved_by_name is ws

        # Resolve by device_id
        resolved_by_id = await manager.resolve_device_connection("dev-db-id-2557")
        assert resolved_by_id is ws

        # Delivery by device_name
        sent = await manager.send_to_device("NetworkLab-PC2557", {"cmd": "LOCKDOWN"})
        assert sent is True
        assert ws.sent_messages[-1] == {"cmd": "LOCKDOWN"}

    asyncio.run(_run())


def test_provable_device_id_alias_resolution(manager):
    """Step 3: Authenticated enrollment-transition alias resolves via device_id mapping."""
    async def _run():
        ws = MockWebSocket()
        # Cache mapping: target_alias -> dev-db-id-999
        manager.register_device_id("LabAlias-PC99", "dev-db-id-999")

        await manager.register_device(
            ws,
            hardware_uuid="hw-uuid-999",
            device_name="Real-PC99",
            device_id="dev-db-id-999",
        )

        resolved = await manager.resolve_device_connection("LabAlias-PC99")
        assert resolved is ws

        sent = await manager.send_to_device("LabAlias-PC99", {"cmd": "SYNC"})
        assert sent is True
        assert ws.sent_messages[-1] == {"cmd": "SYNC"}

    asyncio.run(_run())


def test_ambiguous_resolution_fails_closed(manager):
    """If ambiguity exists (e.g. multiple conflicting connections), never guess."""
    async def _run():
        ws1 = MockWebSocket()
        ws2 = MockWebSocket()

        # Artificially inject two connections with identical device_name to test defensive guard
        async with manager._lock:
            manager._connection_meta[ws1] = ConnectionInfo(
                ws=ws1, hardware_uuid="hw-1", device_name="Conflicting-Name"
            )
            manager._connection_meta[ws2] = ConnectionInfo(
                ws=ws2, hardware_uuid="hw-2", device_name="Conflicting-Name"
            )

        resolved = await manager.resolve_device_connection("Conflicting-Name")
        assert resolved is None  # Fails closed, does not guess

        sent = await manager.send_to_device("Conflicting-Name", {"cmd": "FAIL"})
        assert sent is False
        assert len(ws1.sent_messages) == 0
        assert len(ws2.sent_messages) == 0

    asyncio.run(_run())


def test_ip_address_never_resolves_or_delivers(manager):
    """IP address must NEVER be used to route policies."""
    async def _run():
        ws = MockWebSocket()
        await manager.register_device(
            ws,
            hardware_uuid="hw-uuid-pc2557",
            device_name="NetworkLab-PC2557",
            device_id="dev-id-2557",
        )

        # Attempting to deliver by IP address fails
        resolved = await manager.resolve_device_connection("192.168.11.33")
        assert resolved is None

        sent = await manager.send_to_device("192.168.11.33", {"policy": "test"})
        assert sent is False

    asyncio.run(_run())


def test_reconnect_replaces_old_registration_cleanly(manager):
    """When a device reconnects under a new identity (e.g. DESKTOP-3 -> NetworkLab-PC2557):
    - Old socket is closed.
    - DESKTOP-3 is removed.
    - NetworkLab-PC2557 is active.
    """
    async def _run():
        old_ws = MockWebSocket()
        new_ws = MockWebSocket()

        # Step 1: Agent initially connects under un-enrolled raw machine name DESKTOP-3
        await manager.register_device(
            old_ws,
            hardware_uuid="DESKTOP-3",
            device_name="DESKTOP-3",
        )
        assert manager.is_device_online("DESKTOP-3") is True
        assert await manager.resolve_device_connection("DESKTOP-3") is old_ws

        # Step 2: Agent is enrolled, re-registers or connects as NetworkLab-PC2557 on new_ws
        await manager.register_device(
            new_ws,
            hardware_uuid="hw-uuid-2557",
            device_name="NetworkLab-PC2557",
            device_id="db-id-2557",
        )

        # Clean unregister of old socket
        await manager.unregister_device(old_ws)

        # Final state:
        # NetworkLab-PC2557 -> active WebSocket
        # DESKTOP-3 -> NO active WebSocket
        assert manager.is_device_online("NetworkLab-PC2557") is True
        assert await manager.resolve_device_connection("NetworkLab-PC2557") is new_ws
        assert manager.is_device_online("DESKTOP-3") is False
        assert await manager.resolve_device_connection("DESKTOP-3") is None
        assert old_ws.closed or manager._device_connections.get("DESKTOP-3") is None

    asyncio.run(_run())


def test_socket_aware_unregistration_preserves_new_connection(manager):
    """If an old socket's disconnect handler runs AFTER a new socket registered the same identity,
    the newer socket must NOT be unregistered."""
    async def _run():
        old_ws = MockWebSocket()
        new_ws = MockWebSocket()

        # Register old socket
        await manager.register_device(old_ws, hardware_uuid="HW-100", device_name="PC-100")
        assert manager._device_connections["HW-100"] is old_ws

        # New socket connects with same HW-100
        await manager.register_device(new_ws, hardware_uuid="HW-100", device_name="PC-100")
        assert manager._device_connections["HW-100"] is new_ws

        # Late disconnect handler for old_ws arrives
        await manager.unregister_device(old_ws)

        # New socket is STILL registered and online!
        assert manager._device_connections.get("HW-100") is new_ws
        assert manager._device_connections.get("PC-100") is new_ws
        assert manager.is_device_online("HW-100") is True
        assert await manager.resolve_device_connection("HW-100") is new_ws

    asyncio.run(_run())
