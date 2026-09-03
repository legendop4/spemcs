"""Device management service — registration, presence, hierarchy."""

import logging
import re
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.models.device import Device, DeviceStatus
from backend.models.lab import Lab
from backend.models.lab_device import LabDevice

logger = logging.getLogger(__name__)


def parse_friendly_name(friendly_name: str) -> dict:
    """Parse a structured friendly name like 'TechTower:Lab-03:PC-012'
    into building_name, lab_name, pc_number components."""
    parts = friendly_name.split(":")
    if len(parts) == 3:
        return {
            "building_name": parts[0].strip(),
            "lab_name": parts[1].strip(),
            "pc_number": parts[2].strip(),
        }
    elif len(parts) == 2:
        return {
            "building_name": parts[0].strip(),
            "lab_name": parts[1].strip(),
            "pc_number": None,
        }
    else:
        return {
            "building_name": None,
            "lab_name": None,
            "pc_number": None,
        }


def register_device(
    db: Session,
    hardware_uuid: str,
    device_name: str,
    ip_address: Optional[str] = None,
    lab_id: Optional[str] = None,
    pc_number: Optional[str] = None,
    hostname: Optional[str] = None,
) -> Device:
    """Register or update a device by hardware UUID.
    Associates with Lab and checks (lab_id, pc_number) uniqueness."""
    hierarchy = parse_friendly_name(device_name)
    
    target_lab = None
    if lab_id:
        try:
            target_lab = db.query(Lab).filter(Lab.lab_id == lab_id).first()
        except Exception:
            target_lab = db.query(Lab).filter(Lab.lab_name == lab_id).first()
    
    effective_building = target_lab.building_id if target_lab else hierarchy["building_name"]
    effective_lab_name = target_lab.lab_name if target_lab else hierarchy["lab_name"]
    effective_pc = pc_number or hierarchy["pc_number"]
    
    # Check duplicate PC number within the same lab
    if target_lab and effective_pc:
        existing_device_in_lab = (
            db.query(Device)
            .join(LabDevice, LabDevice.device_id == Device.device_id)
            .filter(
                LabDevice.lab_id == target_lab.lab_id,
                Device.pc_number == effective_pc,
                Device.hardware_uuid != hardware_uuid,
            )
            .first()
        )
        if existing_device_in_lab:
            raise ValueError(f"PC number '{effective_pc}' is already registered in lab '{target_lab.lab_name}'.")

    # Check if device already exists by hardware_uuid
    device = db.query(Device).filter(Device.hardware_uuid == hardware_uuid).first()
    
    if device:
        # Update existing device
        device.device_name = device_name
        device.registered_ip = ip_address or device.registered_ip
        device.building_name = effective_building or device.building_name
        device.lab_name = effective_lab_name or device.lab_name
        device.pc_number = effective_pc or device.pc_number
        device.status = DeviceStatus.ONLINE.value
        device.last_seen = datetime.utcnow()
    else:
        # Check by device_name for backward compatibility
        device = db.query(Device).filter(Device.device_name == device_name).first()
        if device:
            device.hardware_uuid = hardware_uuid
            device.registered_ip = ip_address or device.registered_ip
            device.building_name = effective_building or device.building_name
            device.lab_name = effective_lab_name or device.lab_name
            device.pc_number = effective_pc or device.pc_number
            device.status = DeviceStatus.ONLINE.value
            device.last_seen = datetime.utcnow()
        else:
            # Create new device
            device = Device(
                hardware_uuid=hardware_uuid,
                device_name=device_name,
                registered_ip=ip_address,
                building_name=effective_building,
                lab_name=effective_lab_name,
                pc_number=effective_pc,
                status=DeviceStatus.ONLINE.value,
                last_seen=datetime.utcnow(),
            )
            db.add(device)
            db.flush()
    
    # Associate with Lab if target_lab resolved
    if target_lab:
        existing_link = (
            db.query(LabDevice)
            .filter(LabDevice.lab_id == target_lab.lab_id, LabDevice.device_id == device.device_id)
            .first()
        )
        if not existing_link:
            lab_link = LabDevice(lab_id=target_lab.lab_id, device_id=device.device_id)
            db.add(lab_link)
    
    db.commit()
    db.refresh(device)
    logger.info(f"Device registered: {device_name} (UUID: {hardware_uuid}, Lab: {effective_lab_name}, PC: {effective_pc})")
    return device


def get_device_by_uuid(db: Session, hardware_uuid: str) -> Optional[Device]:
    """Look up a device by its hardware UUID."""
    return db.query(Device).filter(Device.hardware_uuid == hardware_uuid).first()


def get_device_by_name(db: Session, device_name: str) -> Optional[Device]:
    """Look up a device by its friendly name."""
    return db.query(Device).filter(Device.device_name == device_name).first()


def get_device_by_id(db: Session, device_id: UUID) -> Optional[Device]:
    """Look up a device by its database ID."""
    return db.query(Device).filter(Device.device_id == device_id).first()


def update_presence(db: Session, hardware_uuid: str, online: bool) -> Optional[Device]:
    """Update device online/offline status and last_seen timestamp."""
    device = db.query(Device).filter(Device.hardware_uuid == hardware_uuid).first()
    if device:
        device.status = DeviceStatus.ONLINE.value if online else DeviceStatus.OFFLINE.value
        device.last_seen = datetime.utcnow()
        db.commit()
        db.refresh(device)
    return device


def get_device_tree(db: Session) -> list[dict]:
    """Build hierarchical device tree: Building -> Lab -> PC.
    Returns a nested structure for frontend tree component."""
    devices = db.query(Device).order_by(
        Device.building_name, Device.lab_name, Device.pc_number
    ).all()
    
    # Build tree structure
    buildings: dict = {}
    unassigned = []
    
    for device in devices:
        if not device.building_name:
            unassigned.append({
                "name": device.device_name,
                "type": "device",
                "id": str(device.device_id),
                "device_id": str(device.device_id),
                "hardware_uuid": device.hardware_uuid,
                "status": device.status,
                "children": [],
            })
            continue
        
        bldg = device.building_name
        lab = device.lab_name or "Unassigned"
        
        if bldg not in buildings:
            buildings[bldg] = {"name": bldg, "type": "building", "id": bldg, "children": {}}
        
        if lab not in buildings[bldg]["children"]:
            buildings[bldg]["children"][lab] = {
                "name": lab, "type": "lab", "id": f"{bldg}:{lab}", "children": []
            }
        
        buildings[bldg]["children"][lab]["children"].append({
            "name": device.pc_number or device.device_name,
            "type": "device",
            "id": str(device.device_id),
            "device_id": str(device.device_id),
            "hardware_uuid": device.hardware_uuid,
            "status": device.status,
            "children": [],
        })
    
    # Convert nested dicts to lists
    tree = []
    for bldg_data in buildings.values():
        bldg_node = {
            "name": bldg_data["name"],
            "type": "building",
            "id": bldg_data["id"],
            "children": [],
        }
        for lab_data in bldg_data["children"].values():
            bldg_node["children"].append({
                "name": lab_data["name"],
                "type": "lab",
                "id": lab_data["id"],
                "children": lab_data["children"],
            })
        tree.append(bldg_node)
    
    # Add unassigned devices at root level
    if unassigned:
        tree.append({
            "name": "Unassigned",
            "type": "building",
            "id": "unassigned",
            "children": unassigned,
        })
    
    return tree


def get_online_devices(db: Session) -> list[Device]:
    """Get all devices currently marked as online."""
    return db.query(Device).filter(Device.status == DeviceStatus.ONLINE.value).all()
