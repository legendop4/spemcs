from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.dependencies import require_admin, require_staff
from backend.models.session import ExamSession
from backend.schemas.session import ExamSessionCreate, ExamSessionRead, ExamSessionUpdate

# Management view of candidate sessions - roll numbers, which machine each candidate sat at, and
# when. Endpoints create their own sessions through POST /api/v1/sessions/start, which
# authenticates with a device token (routes/agent_api.py); this router is for operators only, so
# gating it does not affect the agent.
router = APIRouter(
    prefix="/api/sessions",
    tags=["sessions"],
    dependencies=[Depends(require_staff)],
)


def _as_dict(model: Any) -> dict:
    return model.model_dump(exclude_unset=True) if hasattr(model, "model_dump") else model.dict(exclude_unset=True)


@router.get("", response_model=list[ExamSessionRead])
def list_sessions(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(ExamSession).offset(skip).limit(limit).all()


@router.get("/{session_id}", response_model=ExamSessionRead)
def get_session(session_id: UUID, db: Session = Depends(get_db)):
    exam_session = db.get(ExamSession, session_id)
    if exam_session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ExamSession not found")
    return exam_session


@router.post("", response_model=ExamSessionRead, status_code=status.HTTP_201_CREATED)
def create_session(payload: ExamSessionCreate, db: Session = Depends(get_db),
                   _admin=Depends(require_admin)):
    data = _as_dict(payload)
    if data.get("session_id") is None:
        data.pop("session_id", None)
    exam_session = ExamSession(**data)
    db.add(exam_session)
    db.commit()
    db.refresh(exam_session)
    return exam_session


@router.put("/{session_id}", response_model=ExamSessionRead)
def update_session(session_id: UUID, payload: ExamSessionUpdate, db: Session = Depends(get_db),
                   _admin=Depends(require_admin)):
    exam_session = db.get(ExamSession, session_id)
    if exam_session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ExamSession not found")
    for key, value in _as_dict(payload).items():
        setattr(exam_session, key, value)
    db.commit()
    db.refresh(exam_session)
    return exam_session


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(session_id: UUID, db: Session = Depends(get_db),
                   _admin=Depends(require_admin)):
    exam_session = db.get(ExamSession, session_id)
    if exam_session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ExamSession not found")
    db.delete(exam_session)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
