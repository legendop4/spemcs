"""WebSocket endpoint for device agents.

Agent lifecycle:
1. Connect to /api/v1/ws/agent
2. Send identity handshake: {"action": "REGISTER", "hardware_uuid": "..."}
3. Receive commands: LAUNCH_EXAM_MODE, STOP_EXAM_MODE, HEARTBEAT_PING
4. On disconnect: device marked offline, dashboard notified
5. On reconnect: recovery check sends active exam payload if applicable
"""

import logging
from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool

from backend.app.database import SessionLocal
from backend.models.device import Device, DeviceStatus
from backend.models.exam import Exam, ExamDevice, ExamStatus
from backend.models.session import ExamSession
from backend.websocket.manager import realtime_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket-agent"])


def _update_device_presence(hardware_uuid: str, online: bool) -> None:
    """Update device status and last_seen in the database (synchronous).
    Auto-registers device and its lab if they do not exist in the database."""
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.hardware_uuid == hardware_uuid).first()
        if device:
            device.status = DeviceStatus.ONLINE.value if online else DeviceStatus.OFFLINE.value
            device.last_seen = datetime.utcnow()
            db.commit()
            
            # Cache mapping in memory just in case
            from backend.websocket.manager import realtime_manager
            realtime_manager.register_device_id(hardware_uuid, str(device.device_id))
        elif online:
            # Parse hierarchy from hardware_uuid (splitting by either ':' or '-')
            import re
            parts = re.split(r'[:\-]', hardware_uuid)
            building = None
            lab_name = None
            pc_num = None
            if len(parts) == 3:
                building = parts[0].strip()
                lab_name = parts[1].strip()
                pc_num = parts[2].strip()
            elif len(parts) == 2:
                building = parts[0].strip()
                lab_name = parts[1].strip()
            
            # Auto-create the device
            logger.info(f"Device {hardware_uuid} not found in DB. Auto-registering.")
            device = Device(
                hardware_uuid=hardware_uuid,
                device_name=hardware_uuid,
                building_name=building,
                lab_name=lab_name,
                pc_number=pc_num,
                status=DeviceStatus.ONLINE.value,
                last_seen=datetime.utcnow(),
            )
            db.add(device)
            db.flush()
            
            # Auto-create the Lab if it doesn't exist
            if lab_name:
                from backend.models.lab import Lab, LabStatus
                from backend.models.lab_device import LabDevice
                lab = db.query(Lab).filter(Lab.lab_name == lab_name).first()
                if not lab:
                    lab = Lab(
                        lab_name=lab_name,
                        building_id=building or "Default",
                        description=f"Auto-generated lab: {lab_name}",
                        capacity=40,
                        spemcs_enabled=True,
                        status=LabStatus.ACTIVE.value,
                    )
                    db.add(lab)
                    db.flush()
                
                # Link device to lab
                link = LabDevice(lab_id=lab.lab_id, device_id=device.device_id)
                db.add(link)
                
            db.commit()
            logger.info(f"Auto-registered device: {hardware_uuid} (Building: {building}, Lab: {lab_name}, PC: {pc_num})")
            
            # Cache it in memory
            from backend.websocket.manager import realtime_manager
            realtime_manager.register_device_id(hardware_uuid, str(device.device_id))
    except Exception as e:
        logger.error(f"Failed to update device presence for {hardware_uuid}: {e}")
        db.rollback()
    finally:
        db.close()


def _get_recovery_payload(hardware_uuid: str) -> dict | None:
    """Check if this device has an active exam and session. If so, return
    the LAUNCH_EXAM_MODE payload so the agent can resume."""
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.hardware_uuid == hardware_uuid).first()
        if not device:
            return None
        
        # Find active exam assignment for this device
        exam_device = (
            db.query(ExamDevice)
            .join(Exam, ExamDevice.exam_id == Exam.exam_id)
            .filter(
                ExamDevice.device_id == device.device_id,
                Exam.status == ExamStatus.ACTIVE.value,
            )
            .first()
        )
        if not exam_device:
            return None
        
        exam = db.query(Exam).filter(Exam.exam_id == exam_device.exam_id).first()
        if not exam:
            return None
        
        # Check for active session
        session = (
            db.query(ExamSession)
            .filter(
                ExamSession.device_id == device.device_id,
                ExamSession.exam_id == exam.exam_id,
                ExamSession.status == "active",
            )
            .first()
        )
        
        import secrets
        import uuid

        payload = {
            "action": "LAUNCH_EXAM_MODE",
            "command_id": str(uuid.uuid4()),
            "nonce": secrets.token_hex(16),
            "issued_at_utc": datetime.utcnow().isoformat() + "Z",
            "exam_id": str(exam.exam_id),
            "exam_name": exam.exam_name,
            "allowed_domain": exam.exam_link or "",
            "approved_browser": exam.approved_browser,
            "is_recovery": True,
        }
        
        if session:
            payload["session_id"] = str(session.session_id)
            payload["student_roll_number"] = session.student_roll_number
        
        return payload
    except Exception as e:
        logger.error(f"Recovery check failed for {hardware_uuid}: {e}")
        return None
    finally:
        try:
            db.rollback()
        except Exception:
            pass
        db.close()


@router.websocket("/api/v1/ws/agent")
async def agent_websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for device agent connections."""
    await websocket.accept()
    hardware_uuid = None
    
    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action", "").upper()
            
            if action == "REGISTER":
                hardware_uuid = data.get("hardware_uuid")
                device_token = data.get("device_token")

                if not hardware_uuid or not device_token:
                    logger.warning("WebSocket registration rejected: missing hardware_uuid or device_token.")
                    await websocket.send_json({
                        "type": "ERROR",
                        "error_code": "AUTH_REQUIRED",
                        "message": "Both hardware_uuid and device_token are required for registration"
                    })
                    await websocket.close(code=4401)
                    return

                from backend.services.auth_service import verify_device_token
                token_payload = verify_device_token(device_token, expected_hardware_uuid=hardware_uuid)
                if not token_payload:
                    logger.warning(
                        "WebSocket registration rejected: invalid, expired, or mismatched device_token for hardware_uuid '%s'",
                        hardware_uuid
                    )
                    await websocket.send_json({
                        "type": "ERROR",
                        "error_code": "AUTH_FAILED",
                        "message": "Invalid, expired, or mismatched device_token"
                    })
                    await websocket.close(code=4401)
                    return
                
                # Register in realtime manager
                await realtime_manager.register_device(websocket, hardware_uuid)
                
                # Update DB presence in threadpool
                await run_in_threadpool(_update_device_presence, hardware_uuid, True)
                
                # Notify dashboard of device coming online
                await realtime_manager.broadcast_to_dashboard({
                    "type": "DEVICE_STATUS_CHANGE",
                    "payload": {
                        "hardware_uuid": hardware_uuid,
                        "status": "online",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                })
                
                # Send registration acknowledgment
                await websocket.send_json({
                    "type": "REGISTERED",
                    "hardware_uuid": hardware_uuid,
                    "timestamp": datetime.utcnow().isoformat(),
                })
                
                # Recovery check: resend exam payload if device was in active exam (run in threadpool)
                recovery = await run_in_threadpool(_get_recovery_payload, hardware_uuid)
                if recovery:
                    logger.info(f"Recovery: resending exam payload to {hardware_uuid}")
                    await websocket.send_json(recovery)
            
            elif action == "HEARTBEAT_PONG":
                # Device responding to our ping
                info = realtime_manager._connection_meta.get(websocket)
                if info:
                    info.last_pong = datetime.utcnow()
                
                # Update last_seen in threadpool
                if hardware_uuid:
                    await run_in_threadpool(_update_device_presence, hardware_uuid, True)
            
            elif action == "STATUS_UPDATE":
                # Agent reporting its current state
                if hardware_uuid:
                    await realtime_manager.broadcast_to_dashboard({
                        "type": "DEVICE_STATUS_CHANGE",
                        "payload": {
                            "hardware_uuid": hardware_uuid,
                            "status": data.get("status", "online"),
                            "exam_id": data.get("exam_id"),
                            "session_id": data.get("session_id"),
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    })

            elif action == "POLICY_VALIDATION_RESULT":
                # Agent reporting network policy acceptance or rejection
                policy_id = data.get("policy_id")
                status_str = data.get("status")
                logger.info(f"Agent {hardware_uuid} reported policy {policy_id} status: {status_str}")
                if hardware_uuid:
                    await realtime_manager.broadcast_to_dashboard({
                        "type": "POLICY_STATUS_CHANGE",
                        "payload": {
                            "hardware_uuid": hardware_uuid,
                            "policy_id": policy_id,
                            "exam_id": data.get("exam_id"),
                            "version": data.get("version"),
                            "status": status_str,
                            "details": data.get("details"),
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    })

            elif action == "POLICY_UPDATE_STATUS":
                # Agent reporting dynamic network policy update outcome
                logger.info(f"Agent {hardware_uuid} reported policy update: {data}")
                if hardware_uuid:
                    await realtime_manager.broadcast_to_dashboard({
                        "type": "POLICY_UPDATE_STATUS_CHANGE",
                        "payload": {
                            "hardware_uuid": hardware_uuid,
                            "session_id": data.get("session_id"),
                            "exam_id": data.get("exam_id"),
                            "old_version": data.get("old_version"),
                            "new_version": data.get("new_version"),
                            "status": data.get("status"),
                            "failure_reason": data.get("failure_reason"),
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    })

            else:
                logger.debug(f"Unknown action from agent {hardware_uuid}: {action}")
    
    except WebSocketDisconnect:
        logger.info(f"Agent disconnected: {hardware_uuid}")
    except Exception as e:
        logger.error(f"Agent WebSocket error for {hardware_uuid}: {e}")
    finally:
        # Clean up
        if hardware_uuid:
            await realtime_manager.unregister_device(websocket)
            await run_in_threadpool(_update_device_presence, hardware_uuid, False)
            
            # Notify dashboard of device going offline
            await realtime_manager.broadcast_to_dashboard({
                "type": "DEVICE_STATUS_CHANGE",
                "payload": {
                    "hardware_uuid": hardware_uuid,
                    "status": "offline",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            })
