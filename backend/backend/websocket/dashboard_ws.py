"""WebSocket endpoint for proctor/dashboard clients.

Dashboard lifecycle:
1. Connect to /api/v1/ws/dashboard
2. Optionally subscribe to exam rooms: {"action": "SUBSCRIBE_EXAM", "exam_id": "..."}
3. Receive: VIOLATION_ALERT, DEVICE_STATUS_CHANGE, SESSION_STARTED, EXAM_ACTIVATED, etc.
4. Only receives alerts for subscribed exams (no global alert broadcast)
5. Always receives DEVICE_STATUS_CHANGE for all devices
"""

import logging
from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.websocket.manager import realtime_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket-dashboard"])


@router.websocket("/api/v1/ws/dashboard")
async def dashboard_websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for proctor/dashboard connections."""
    await websocket.accept()
    await realtime_manager.register_dashboard(websocket)
    
    try:
        # Send initial state: list of online devices
        online_devices = realtime_manager.get_online_devices()
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
