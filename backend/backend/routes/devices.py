"""Device CRUD and presence management endpoints."""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.models.device import Device
from backend.models.exam import Exam, ExamDevice, ExamStatus
from backend.schemas.device import DeviceCreate, DeviceRead, DeviceUpdate
from backend.services import device_service
from backend.services.auth_service import require_role
from backend.websocket.manager import realtime_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/devices", tags=["devices"])


def _as_dict(model: Any) -> dict:
    return model.model_dump(exclude_unset=True) if hasattr(model, "model_dump") else model.dict(exclude_unset=True)


@router.get("", response_model=list[DeviceRead])
def list_devices(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    from backend.services.risk_service import get_device_risk_score

    devices = db.query(Device).order_by(Device.building_name, Device.lab_name, Device.device_name).offset(skip).limit(limit).all()
    results = []
    for d in devices:
        risk_info = get_device_risk_score(db, d.device_id)
        d_dict = {
            "device_id": d.device_id,
            "device_name": d.device_name,
            "hardware_uuid": d.hardware_uuid,
            "building_name": d.building_name,
            "lab_name": d.lab_name,
            "pc_number": d.pc_number,
            "registered_ip": d.registered_ip,
            "status": d.status,
            "last_seen": d.last_seen,
            "created_at": d.created_at,
            "risk_score": risk_info.get("score", 0),
            "risk_level": risk_info.get("level", "normal"),
        }
        results.append(DeviceRead(**d_dict))
    return results


@router.get("/tree")
def get_device_tree(
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Get hierarchical device tree: Building -> Lab -> PC."""
    return device_service.get_device_tree(db)


@router.get("/online")
def get_online_devices(
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Get all devices currently online (from both DB and WebSocket registry)."""
    # Get DB online devices
    db_online = device_service.get_online_devices(db)
    
    # Get WebSocket connected devices
    ws_online = realtime_manager.get_online_devices()
    
    devices = []
    for d in db_online:
        devices.append({
            "device_id": str(d.device_id),
            "device_name": d.device_name,
            "hardware_uuid": d.hardware_uuid,
            "building_name": d.building_name,
            "lab_name": d.lab_name,
            "pc_number": d.pc_number,
            "status": d.status,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            "ws_connected": d.hardware_uuid in ws_online if d.hardware_uuid else False,
        })
    
    return devices


@router.get("/{device_id}", response_model=DeviceRead)
def get_device(
    device_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


@router.get("/{device_id}/status")
def get_device_status(
    device_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Get detailed device status including active exam info."""
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    
    # Check for active exam
    active_exam = (
        db.query(Exam)
        .join(ExamDevice, ExamDevice.exam_id == Exam.exam_id)
        .filter(
            ExamDevice.device_id == device_id,
            Exam.status == ExamStatus.ACTIVE.value,
        )
        .first()
    )
    
    ws_connected = False
    if device.hardware_uuid:
        ws_connected = realtime_manager.is_device_online(device.hardware_uuid)
    
    return {
        "device_id": str(device.device_id),
        "device_name": device.device_name,
        "hardware_uuid": device.hardware_uuid,
        "building_name": device.building_name,
        "lab_name": device.lab_name,
        "pc_number": device.pc_number,
        "registered_ip": device.registered_ip,
        "status": device.status,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        "ws_connected": ws_connected,
        "active_exam": {
            "exam_id": str(active_exam.exam_id),
            "exam_name": active_exam.exam_name,
            "status": active_exam.status,
        } if active_exam else None,
    }


@router.post("", response_model=DeviceRead, status_code=status.HTTP_201_CREATED)
def create_device(
    payload: DeviceCreate,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    # Parse hierarchy from device name if not provided
    data = _as_dict(payload)
    if not data.get("building_name") and ":" in data.get("device_name", ""):
        parsed = device_service.parse_friendly_name(data["device_name"])
        data.update(parsed)
    
    device = Device(**data)
    db.add(device)
    db.commit()
    db.refresh(device)
    
    from backend.models.audit_log import AuditLog
    db.add(AuditLog(
        action="DEVICE_REGISTERED",
        entity_type="device",
        entity_id=str(device.device_id),
        details={"device_name": device.device_name}
    ))
    db.commit()
    return device


@router.put("/{device_id}", response_model=DeviceRead)
def update_device(
    device_id: UUID,
    payload: DeviceUpdate,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    for key, value in _as_dict(payload).items():
        setattr(device, key, value)
    db.commit()
    db.refresh(device)
    return device


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(
    device_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    db.delete(device)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
