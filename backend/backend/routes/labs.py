from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from backend.app.database import get_db
from backend.app.dependencies import require_admin, require_staff
from backend.models.lab import Lab
from backend.models.lab_device import LabDevice
from backend.models.device import Device
from backend.schemas.lab import LabCreate, LabRead, LabUpdate, LabAssignDevices

# PATCH /{lab_id}/status flips spemcs_enabled, which decides whether a whole lab is monitored at
# all. Anonymous access to it was a one-request way to switch invigilation off for a room, so it
# is admin-only; the reads are staff.
router = APIRouter(
    prefix="/api/labs",
    tags=["labs"],
    dependencies=[Depends(require_staff)],
)


@router.get("", response_model=list[LabRead])
def list_labs(db: Session = Depends(get_db)):
    return db.query(Lab).order_by(Lab.building_id, Lab.lab_name).all()


@router.post("", response_model=LabRead, status_code=status.HTTP_201_CREATED)
def create_lab(payload: LabCreate, db: Session = Depends(get_db),
               _admin=Depends(require_admin)):
    """Create a lab. Admin-only.

    There was previously no way to create a Lab through any API at all - the table was populated by
    hand or as a side effect of ``agent_ws._update_device_presence`` parsing a hardware UUID. That
    left a fresh deployment with an empty lab list, which the setup wizard cannot enrol against.

    Admin rather than staff because creating a room is estate configuration, and because
    ``spemcs_enabled`` here is the same switch ``PATCH /{lab_id}/status`` guards at admin level;
    accepting it on a staff-level create would route around that gate.

    ``(building_id, lab_name)`` is refused as a duplicate. The pair is what an operator reads as the
    identity of a room, and two rows carrying it makes the wizard's dropdown ambiguous in a way the
    person at the workstation cannot resolve. It is not a database constraint (the index on those
    columns is non-unique), so it is enforced here.
    """
    existing = (
        db.query(Lab)
        .filter(Lab.building_id == payload.building_id, Lab.lab_name == payload.lab_name)
        .first()
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A lab named '{payload.lab_name}' already exists in '{payload.building_id}'",
        )

    lab = Lab(
        building_id=payload.building_id,
        lab_name=payload.lab_name,
        description=payload.description,
        capacity=payload.capacity,
        spemcs_enabled=payload.spemcs_enabled,
        status=payload.status.value,
    )
    db.add(lab)
    db.commit()
    db.refresh(lab)
    return lab


@router.get("/{lab_id}", response_model=LabRead)
def get_lab(lab_id: str, db: Session = Depends(get_db)):
    lab = db.get(Lab, lab_id)
    if lab is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lab not found")
    return lab


@router.put("/{lab_id}", response_model=LabRead)
def update_lab(lab_id: str, payload: LabUpdate, db: Session = Depends(get_db),
               _admin=Depends(require_admin)):
    lab = db.get(Lab, lab_id)
    if lab is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lab not found")
    if payload.building_id is not None:
        lab.building_id = payload.building_id
    if payload.lab_name is not None:
        lab.lab_name = payload.lab_name
    if payload.description is not None:
        lab.description = payload.description
    if payload.capacity is not None:
        lab.capacity = payload.capacity
    if payload.spemcs_enabled is not None:
        lab.spemcs_enabled = payload.spemcs_enabled
    if payload.status is not None:
        lab.status = payload.status
    db.commit()
    db.refresh(lab)
    return lab


@router.patch("/{lab_id}/status", response_model=LabRead)
def update_lab_status(lab_id: str, payload: LabUpdate, db: Session = Depends(get_db),
                      _admin=Depends(require_admin)):
    lab = db.get(Lab, lab_id)
    if lab is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lab not found")
    if payload.spemcs_enabled is not None:
        lab.spemcs_enabled = payload.spemcs_enabled
    if payload.status is not None:
        lab.status = payload.status.value if hasattr(payload.status, 'value') else payload.status
    db.commit()
    db.refresh(lab)
    return lab


@router.delete("/{lab_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_lab(lab_id: str, db: Session = Depends(get_db), _admin=Depends(require_admin)):
    lab = db.get(Lab, lab_id)
    if lab is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lab not found")
    # Remove associations
    db.query(LabDevice).filter(LabDevice.lab_id == lab_id).delete()
    db.delete(lab)
    db.commit()
    return None


@router.get("/{lab_id}/devices")
def get_lab_devices(lab_id: str, db: Session = Depends(get_db)):
    lab = db.get(Lab, lab_id)
    if lab is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lab not found")
    q = db.query(Device).join(LabDevice, LabDevice.device_id == Device.device_id).filter(LabDevice.lab_id == lab_id)
    return q.all()


@router.post("/{lab_id}/devices", status_code=status.HTTP_200_OK)
def assign_devices_to_lab(lab_id: str, payload: LabAssignDevices, db: Session = Depends(get_db),
                          _admin=Depends(require_admin)):
    lab = db.get(Lab, lab_id)
    if lab is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lab not found")

    assigned_count = 0
    for dev_id in payload.device_ids:
        device = db.get(Device, dev_id)
        if not device:
            continue
        # Check if already assigned
        existing = db.query(LabDevice).filter(
            LabDevice.lab_id == lab.lab_id,
            LabDevice.device_id == device.device_id
        ).first()
        if not existing:
            # Remove any previous lab assignment for this device
            db.query(LabDevice).filter(LabDevice.device_id == device.device_id).delete()
            ld = LabDevice(lab_id=lab.lab_id, device_id=device.device_id)
            db.add(ld)
            # Update device metadata for consistency
            device.building_name = lab.building_id
            device.lab_name = lab.lab_name
            assigned_count += 1

    db.commit()
    return {"status": "assigned", "count": assigned_count}


@router.delete("/{lab_id}/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_device_from_lab(lab_id: str, device_id: str, db: Session = Depends(get_db),
                           _admin=Depends(require_admin)):
    lab = db.get(Lab, lab_id)
    if lab is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lab not found")
    db.query(LabDevice).filter(
        LabDevice.lab_id == lab.lab_id,
        LabDevice.device_id == device_id
    ).delete()
    db.commit()
    return None
