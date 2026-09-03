from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from backend.app.database import get_db
from backend.models.lab import Lab
from backend.models.lab_device import LabDevice
from backend.models.device import Device
from backend.schemas.lab import LabRead, LabUpdate

router = APIRouter(prefix="/api/labs", tags=["labs"])


@router.get("", response_model=list[LabRead])
def list_labs(db: Session = Depends(get_db)):
    return db.query(Lab).order_by(Lab.building_id, Lab.lab_name).all()


@router.get("/{lab_id}", response_model=LabRead)
def get_lab(lab_id: str, db: Session = Depends(get_db)):
    lab = db.get(Lab, lab_id)
    if lab is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lab not found")
    return lab


@router.patch("/{lab_id}/status", response_model=LabRead)
def update_lab_status(lab_id: str, payload: LabUpdate, db: Session = Depends(get_db)):
    lab = db.get(Lab, lab_id)
    if lab is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lab not found")
    if payload.spemcs_enabled is not None:
        lab.spemcs_enabled = payload.spemcs_enabled
    db.commit()
    db.refresh(lab)
    return lab


@router.get("/{lab_id}/devices")
def get_lab_devices(lab_id: str, db: Session = Depends(get_db)):
    # join lab_devices -> devices
    lab = db.get(Lab, lab_id)
    if lab is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lab not found")
    q = db.query(Device).join(LabDevice, LabDevice.device_id == Device.device_id).filter(LabDevice.lab_id == lab_id)
    return q.all()
