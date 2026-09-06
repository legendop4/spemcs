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
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool

from backend.app.database import SessionLocal
from backend.app.identifiers import parse_uuid
from backend.models.device import Device, DeviceStatus
from backend.models.exam import Exam, ExamDevice, ExamStatus
from backend.models.policy import NetworkPolicy
from backend.models.session import ExamSession
from backend.services import device_policy_state_service as dps
from backend.websocket.manager import realtime_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket-agent"])


# ── Endpoint-reported enforcement status ──────────────────────────────────────
# The wire vocabulary an agent may report in POLICY_VALIDATION_RESULT / POLICY_UPDATE_STATUS,
# mapped onto the `device_policy_states` lifecycle. This is a contract the endpoint has to
# implement, not an observation: the shipped C# agent sends only REGISTER and HEARTBEAT_PONG over
# this socket, so today these handlers persist nothing because nothing arrives. They exist and are
# wired so the loop closes as soon as the agent side is written, and so the failure mode in the
# meantime is a row stuck at APPLYING rather than a status invented by the server.
_REPORTED_STATUS_MAP = {
    "APPLIED": dps.STATUS_APPLIED,
    "ENFORCING": dps.STATUS_APPLIED,
    "APPLYING": dps.STATUS_APPLYING,
    "FAILED": dps.STATUS_FAILED,
    "REJECTED": dps.STATUS_FAILED,
    "INVALID": dps.STATUS_FAILED,
    "ROLLED_BACK": dps.STATUS_ROLLED_BACK,
}


def _map_reported_status(reported: Optional[str]) -> tuple[str, Optional[str]]:
    """Map an endpoint-reported status onto the lifecycle. Unrecognised means FAILED.

    Failing closed is deliberate and it is a trade. An unrecognised status could be a future agent
    reporting something richer, and downgrading that to FAILED will refuse an activation. The
    alternative is worse: leaving the row at APPLYING - which the activation precondition counts as
    armed - would claim a workstation is locked down on the strength of a message the server could
    not read. The unparsed value is carried into `last_error`, so the operator sees exactly what
    arrived rather than a bare refusal.

    It also grants an attacker nothing: anything that can reach this socket can send
    ``status: "FAILED"`` outright.
    """
    key = (reported or "").strip().upper()
    mapped = _REPORTED_STATUS_MAP.get(key)
    if mapped is not None:
        return mapped, None
    return dps.STATUS_FAILED, f"Endpoint reported an unrecognised policy status: {reported!r}"


def _persist_policy_state(
    hardware_uuid: str,
    *,
    reported_status: Optional[str],
    exam_id: Optional[str] = None,
    policy_id: Optional[str] = None,
    version: Optional[int] = None,
    rules_installed: Optional[int] = None,
    detail: Optional[str] = None,
) -> None:
    """Record an endpoint's enforcement report in `device_policy_states` (synchronous).

    Runs in a threadpool with its own session, like the other database helpers in this module.
    Every failure is contained: a WebSocket message handler must not be able to drop the
    connection because a bookkeeping row could not be written.
    """
    status_value, mapping_error = _map_reported_status(reported_status)
    last_error = mapping_error or detail if status_value == dps.STATUS_FAILED else None

    db = SessionLocal()
    try:
        resolved_exam_id, resolved_policy_id = _resolve_policy_identity(
            db, exam_id=exam_id, policy_id=policy_id, version=version
        )
        if resolved_exam_id is None or resolved_policy_id is None:
            # Without both, the row cannot be keyed or its foreign key satisfied. Logged rather
            # than guessed: attributing a report to the wrong exam is worse than not recording it,
            # and "no row" is the not-armed answer the activation precondition already handles.
            logger.warning(
                "Cannot record enforcement state from %s: could not resolve exam/policy "
                "(exam_id=%r, policy_id=%r, version=%r)",
                hardware_uuid, exam_id, policy_id, version,
            )
            return

        dps.record_state_for_hardware_uuid(
            db,
            exam_id=resolved_exam_id,
            hardware_uuid=hardware_uuid,
            policy_id=resolved_policy_id,
            status=status_value,
            rules_installed=rules_installed,
            last_error=last_error,
        )
    except Exception as exc:
        logger.error("Failed to record enforcement state for %s: %s", hardware_uuid, exc)
        db.rollback()
    finally:
        db.close()


def _resolve_policy_identity(
    db,
    *,
    exam_id: Optional[str],
    policy_id: Optional[str],
    version: Optional[int],
) -> tuple[Optional[UUID], Optional[UUID]]:
    """Work out which (exam, policy) a report refers to, without guessing.

    An agent may name the policy (POLICY_VALIDATION_RESULT) or the exam (POLICY_UPDATE_STATUS);
    each is enough, because the policy row carries the exam id and an exam has a latest policy.
    Deriving the exam from the policy row is exact - it is a foreign key, not an inference - and it
    is why a report that omits `exam_id` is still recordable. What is never done is falling back to
    "the device's active exam": at distribution time the exam is still PENDING, so that lookup
    would fail in precisely the case this table exists to cover.
    """
    parsed_policy_id = parse_uuid(policy_id)
    parsed_exam_id = parse_uuid(exam_id)

    if parsed_policy_id is not None:
        policy = (
            db.query(NetworkPolicy)
            .filter(NetworkPolicy.policy_id == parsed_policy_id)
            .first()
        )
        if policy is not None:
            return policy.exam_id, policy.policy_id

    if parsed_exam_id is not None:
        query = db.query(NetworkPolicy).filter(NetworkPolicy.exam_id == parsed_exam_id)
        if version is not None:
            match = query.filter(NetworkPolicy.version == version).first()
            if match is not None:
                return match.exam_id, match.policy_id
        latest = query.order_by(NetworkPolicy.version.desc()).first()
        if latest is not None:
            return latest.exam_id, latest.policy_id

    return None, None


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
                    # Persisted BEFORE the broadcast. A broadcast reaches whichever dashboards
                    # happen to be connected and is lost otherwise, so it was never a record of
                    # anything - which is why the enforcement state of an exam could not be
                    # answered after a page refresh.
                    await run_in_threadpool(
                        _persist_policy_state,
                        hardware_uuid,
                        reported_status=status_str,
                        exam_id=data.get("exam_id"),
                        policy_id=policy_id,
                        version=data.get("version"),
                        rules_installed=data.get("rules_installed"),
                        detail=data.get("details"),
                    )
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
                    # A dynamic update carries the exam and the new version rather than a policy
                    # id; _resolve_policy_identity handles either.
                    await run_in_threadpool(
                        _persist_policy_state,
                        hardware_uuid,
                        reported_status=data.get("status"),
                        exam_id=data.get("exam_id"),
                        version=data.get("new_version"),
                        rules_installed=data.get("rules_installed"),
                        detail=data.get("failure_reason"),
                    )
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
