from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.dependencies import require_admin, require_staff
from backend.models.event import Event
from backend.schemas.event import EventCreate, EventRead, EventUpdate

# These are the MANAGEMENT views of the violation record. Endpoints post their observations to
# POST /api/v1/events instead, which authenticates with a device token (see routes/agent_api.py);
# nothing in the agent uses this router, so gating it does not affect ingestion.
#
# Mutations here are admin-only rather than staff. An event is the primary evidence that a
# candidate did something, so being able to write or erase one is being able to manufacture or
# destroy the finding - a strictly stronger power than reading it, and not one a proctor
# invigilating the exam under review should hold.
router = APIRouter(
    prefix="/api/events",
    tags=["events"],
    dependencies=[Depends(require_staff)],
)


def _as_dict(model: Any) -> dict:
    return model.model_dump(exclude_unset=True) if hasattr(model, "model_dump") else model.dict(exclude_unset=True)


@router.get("", response_model=list[EventRead])
def list_events(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(Event).offset(skip).limit(limit).all()


@router.get("/{event_id}", response_model=EventRead)
def get_event(event_id: UUID, db: Session = Depends(get_db)):
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event


@router.post("", response_model=EventRead, status_code=status.HTTP_201_CREATED)
def create_event(payload: EventCreate, db: Session = Depends(get_db),
                 _admin=Depends(require_admin)):
    data = _as_dict(payload)
    if data.get("event_id") is None:
        data.pop("event_id", None)
    event = Event(**data)
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


@router.put("/{event_id}", response_model=EventRead)
def update_event(event_id: UUID, payload: EventUpdate, db: Session = Depends(get_db),
                 _admin=Depends(require_admin)):
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    for key, value in _as_dict(payload).items():
        setattr(event, key, value)
    db.commit()
    db.refresh(event)
    return event


@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_event(event_id: UUID, db: Session = Depends(get_db),
                 _admin=Depends(require_admin)):
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    db.delete(event)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
