"""WebSocket endpoint for proctor/dashboard clients.

Dashboard lifecycle:
1. Connect to /api/v1/ws/dashboard
2. AUTHENTICATE as the first frame: {"action": "AUTHENTICATE", "token": "<operator JWT>"}
   (or present Authorization: Bearer <jwt> on the handshake, for non-browser clients)
3. Optionally subscribe to exam rooms: {"action": "SUBSCRIBE_EXAM", "exam_id": "..."}
4. Receive: VIOLATION_ALERT, DEVICE_STATUS_CHANGE, SESSION_STARTED, EXAM_ACTIVATED, etc.
5. Only receives alerts for subscribed exams (no global alert broadcast)
6. Always receives DEVICE_STATUS_CHANGE for all devices

AUTHENTICATION — what step 2 replaced
------------------------------------
This socket previously accepted every connection and pushed INITIAL_STATE (the full online-device
inventory) as its first frame, before reading anything from the client. Anyone who could reach the
port received the live invigilation feed for every exam: device presence, session starts and every
violation alert for any exam id they cared to SUBSCRIBE_EXAM to. The agent socket next door has
required a signed device token since M8; this one required nothing.

Three properties are deliberate:

* **Nothing is sent before the identity is established.** Not INITIAL_STATE, not an ack. The
  connection is registered with ``realtime_manager`` only after authorization succeeds, so an
  unauthenticated socket cannot receive a broadcast in the window between accept and auth.
* **The credential is NOT accepted as a query parameter.** ``?token=`` is the usual way to
  authenticate a browser WebSocket and it puts the bearer token in the request line, where every
  reverse proxy and access log records it verbatim. A first-frame handshake keeps it in the
  message body. The ``Authorization`` header is also honoured because non-browser clients can set
  it and it is strictly better when available.
* **Failures are indistinguishable to the client.** Absent, malformed, expired and unknown-subject
  all close with 4401 and the same message; only role refusal is separate (4403), because a caller
  who authenticated successfully already knows their token is good.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.models.user import UserRole
from backend.websocket.manager import realtime_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket-dashboard"])

#: Roles permitted to observe the dashboard feed. Proctors invigilate, so they need it; any other
#: role does not. Spelled from the enum for the reason given in backend/app/dependencies.py.
DASHBOARD_ROLES = frozenset({UserRole.ADMIN.value, UserRole.PROCTOR.value})

#: Seconds to wait for the AUTHENTICATE frame before dropping the connection. Without a bound, an
#: unauthenticated socket that simply never speaks would occupy a connection slot indefinitely.
AUTH_TIMEOUT_SECONDS = 10.0

WS_UNAUTHENTICATED = 4401
WS_FORBIDDEN = 4403


def _handshake_token(websocket: WebSocket) -> Optional[str]:
    """Extract a bearer token from the handshake, if the client could set one."""
    header = websocket.headers.get("authorization") or ""
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return None


async def _close_quietly(websocket: WebSocket, code: int) -> None:
    """Close the socket, tolerating a peer that has already gone away.

    A refusal path must not raise: the caller's next action is to return, and an exception here
    would be logged as a server error rather than as the rejection it is.
    """
    try:
        await websocket.close(code=code)
    except Exception:
        pass


async def _send_quietly(websocket: WebSocket, message: dict) -> None:
    """Send a refusal message, tolerating a peer that has already gone away."""
    try:
        await websocket.send_json(message)
    except Exception:
        pass


async def _authenticate(websocket: WebSocket):
    """Establish and authorize the operator behind this socket, or close it.

    Returns the ``User`` on success and ``None`` after closing the socket on any failure, so the
    caller's only correct response to ``None`` is to return.
    """
    from backend.app.database import SessionLocal
    from backend.services.auth_service import resolve_operator_token

    token = _handshake_token(websocket)
    if token is None:
        try:
            data = await asyncio.wait_for(
                websocket.receive_json(), timeout=AUTH_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            logger.warning("Dashboard WebSocket closed: no AUTHENTICATE frame within timeout")
            await _close_quietly(websocket, WS_UNAUTHENTICATED)
            return None
        except WebSocketDisconnect:
            return None
        except Exception:
            # A non-JSON first frame lands here. Nothing has been sent, so simply close.
            logger.warning("Dashboard WebSocket closed: unreadable first frame")
            await _close_quietly(websocket, WS_UNAUTHENTICATED)
            return None

        if not isinstance(data, dict) or str(data.get("action", "")).upper() != "AUTHENTICATE":
            logger.warning("Dashboard WebSocket closed: first frame was not AUTHENTICATE")
            await _send_quietly(websocket, {
                "type": "ERROR",
                "error_code": "AUTH_REQUIRED",
                "message": "The first frame must be {\"action\": \"AUTHENTICATE\", \"token\": ...}",
            })
            await _close_quietly(websocket, WS_UNAUTHENTICATED)
            return None
        token = data.get("token")

    db = SessionLocal()
    try:
        user = resolve_operator_token(token or "", db)
        if user is None:
            # Uniform message: absent, malformed, bad signature, expired, unknown subject and
            # disabled account are one answer to the client.
            logger.warning("Dashboard WebSocket closed: authentication failed")
            await _send_quietly(websocket, {
                "type": "ERROR",
                "error_code": "AUTH_FAILED",
                "message": "Invalid or expired credentials",
            })
            await _close_quietly(websocket, WS_UNAUTHENTICATED)
            return None

        if (user.role or "").lower() not in DASHBOARD_ROLES:
            logger.warning(
                "Dashboard WebSocket closed: user %s (role %s) is not authorized for dashboard data",
                user.username, user.role,
            )
            await _send_quietly(websocket, {
                "type": "ERROR",
                "error_code": "FORBIDDEN",
                "message": "This account is not authorized for dashboard data",
            })
            await _close_quietly(websocket, WS_FORBIDDEN)
            return None

        # Detached from the session below, so read what is needed while it is still live.
        return user.username, (user.role or "").lower()
    finally:
        try:
            db.rollback()
        finally:
            db.close()


@router.websocket("/api/v1/ws/dashboard")
async def dashboard_websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for authenticated proctor/dashboard connections."""
    await websocket.accept()

    identity = await _authenticate(websocket)
    if identity is None:
        # _authenticate already closed the socket, and registration never happened, so there is
        # nothing to unregister. Returning here is what keeps an unauthorized connection out of
        # realtime_manager's broadcast set entirely.
        return
    username, role = identity

    await realtime_manager.register_dashboard(websocket)
    logger.info("Dashboard client authenticated: %s (%s)", username, role)

    try:
        # Send initial state: list of online devices
        online_devices = realtime_manager.get_online_devices()
        await websocket.send_json({
            "type": "AUTHENTICATED",
            "payload": {"username": username, "role": role},
        })
        await websocket.send_json({
            "type": "INITIAL_STATE",
            "payload": {
                "online_devices": list(online_devices),
                "connected_dashboards": realtime_manager.get_dashboard_count(),
                "timestamp": datetime.utcnow().isoformat(),
            }
        })

        while True:
            data = await websocket.receive_json()
            action = data.get("action", "").upper()

            if action == "SUBSCRIBE_EXAM":
                exam_id = data.get("exam_id")
                if exam_id:
                    await realtime_manager.subscribe_exam(websocket, exam_id)
                    await websocket.send_json({
                        "type": "SUBSCRIBED",
                        "exam_id": exam_id,
                        "timestamp": datetime.utcnow().isoformat(),
                    })
            
            elif action == "UNSUBSCRIBE_EXAM":
                exam_id = data.get("exam_id")
                if exam_id:
                    await realtime_manager.unsubscribe_exam(websocket, exam_id)
                    await websocket.send_json({
                        "type": "UNSUBSCRIBED",
                        "exam_id": exam_id,
                    })
            
            elif action == "HEARTBEAT_PONG":
                info = realtime_manager._connection_meta.get(websocket)
                if info:
                    info.last_pong = datetime.utcnow()
            
            elif action == "GET_STATUS":
                # Dashboard requesting current status snapshot
                await websocket.send_json({
                    "type": "STATUS_SNAPSHOT",
                    "payload": {
                        "online_devices": list(realtime_manager.get_online_devices()),
                        "connected_dashboards": realtime_manager.get_dashboard_count(),
                        "connected_agents": realtime_manager.get_device_count(),
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                })
            
            else:
                logger.debug(f"Unknown dashboard action: {action}")
    
    except WebSocketDisconnect:
        logger.info("Dashboard client disconnected")
    except Exception as e:
        logger.error(f"Dashboard WebSocket error: {e}")
    finally:
        await realtime_manager.unregister_dashboard(websocket)
