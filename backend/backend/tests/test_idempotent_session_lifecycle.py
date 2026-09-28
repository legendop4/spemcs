"""Regression tests for Idempotent Session Lifecycle Handling.

Validates the 6 mandatory scenarios:
1. Exam A starts -> session active -> Exam A ends -> Exam B starts -> succeeds.
2. Exam A activation is retried twice -> exactly one active session.
3. Exam A activation fails midway -> cleanup occurs -> Exam B can start.
4. Endpoint service restarts during Exam A -> stale state is reconciled correctly.
5. Same exam activation request repeated -> idempotent behavior.
6. Two genuinely simultaneous exams targeting the same device -> second one remains blocked.
"""

import uuid
from datetime import datetime, timedelta
import pytest
from sqlalchemy.orm import Session

from backend.app.database import SessionLocal
from backend.models.device import Device
from backend.models.exam import Exam, ExamDevice, ExamStatus
from backend.models.session import ExamSession, SessionStatus
from backend.services import exam_service, session_service


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _create_device(db: Session, name: str = "TestPC") -> Device:
    dev = Device(
        device_id=uuid.uuid4(),
        hardware_uuid=f"HW-{uuid.uuid4().hex[:8]}",
        device_name=name,
        status="online",
        last_seen=datetime.utcnow(),
    )
    db.add(dev)
    db.commit()
    db.refresh(dev)
    return dev


def _create_exam(db: Session, name: str = "Exam", status: str = "pending") -> Exam:
    ex = Exam(
        exam_id=uuid.uuid4(),
        exam_name=name,
        exam_link="https://exam.example.com",
        approved_browser="chrome",
        network_enforcement=True,
        status=status,
    )
    db.add(ex)
    db.commit()
    db.refresh(ex)
    return ex


def test_scenario_1_exam_a_ends_then_exam_b_succeeds(db: Session):
    """Scenario 1: Exam A starts -> session active -> Exam A ends -> Exam B starts -> succeeds."""
    dev = _create_device(db, "PC-01")
    exam_a = _create_exam(db, "Exam-A", status="pending")
    exam_b = _create_exam(db, "Exam-B", status="pending")

    # 1. Exam A starts & creates session
    sess_a = session_service.start_session(
        db=db,
        device_id=dev.device_id,
        exam_id=exam_a.exam_id,
        student_roll_number="ROLL-001",
    )
    assert sess_a.status == "active"
    assert sess_a.student_roll_number == "ROLL-001"

    # Verify 1 active session exists
    active_sessions = db.query(ExamSession).filter(
        ExamSession.device_id == dev.device_id, ExamSession.status == "active"
    ).all()
    assert len(active_sessions) == 1

    # 2. Exam A ends
    exam_service.deactivate_exam(db, exam_a.exam_id)
    assert exam_a.status == ExamStatus.STOPPED.value
    db.refresh(sess_a)
    assert sess_a.status == "completed"

    # 3. Exam B starts
    sess_b = session_service.start_session(
        db=db,
        device_id=dev.device_id,
        exam_id=exam_b.exam_id,
        student_roll_number="ROLL-001",
    )
    assert sess_b.status == "active"
    assert sess_b.exam_id == exam_b.exam_id

    # Verify only 1 active session exists on this device
    active_after = db.query(ExamSession).filter(
        ExamSession.device_id == dev.device_id, ExamSession.status == "active"
    ).all()
    assert len(active_after) == 1
    assert active_after[0].session_id == sess_b.session_id


def test_scenario_2_activation_retried_twice_yields_one_active_session(db: Session):
    """Scenario 2: Exam A activation is retried twice -> exactly one active session."""
    dev = _create_device(db, "PC-02")
    exam_a = _create_exam(db, "Exam-Retry", status="pending")

    # Assign device
    ed = ExamDevice(exam_id=exam_a.exam_id, device_id=dev.device_id)
    db.add(ed)
    db.commit()

    # First activation
    exam_service.activate_exam(db, exam_a.exam_id)
    sess_1 = session_service.start_session(
        db=db,
        device_id=dev.device_id,
        exam_id=exam_a.exam_id,
        student_roll_number="ROLL-002",
    )

    # Second activation (retry)
    exam_service.activate_exam(db, exam_a.exam_id)
    sess_2 = session_service.start_session(
        db=db,
        device_id=dev.device_id,
        exam_id=exam_a.exam_id,
        student_roll_number="ROLL-002",
    )

    # Third activation (retry)
    exam_service.activate_exam(db, exam_a.exam_id)
    sess_3 = session_service.start_session(
        db=db,
        device_id=dev.device_id,
        exam_id=exam_a.exam_id,
        student_roll_number="ROLL-002",
    )

    # Reused exactly the same session
    assert sess_1.session_id == sess_2.session_id == sess_3.session_id

    active_sessions = db.query(ExamSession).filter(
        ExamSession.device_id == dev.device_id, ExamSession.status == "active"
    ).all()
    assert len(active_sessions) == 1


def test_scenario_3_activation_fails_midway_cleanup_allows_exam_b(db: Session):
    """Scenario 3: Exam A activation fails midway -> cleanup occurs -> Exam B can start."""
    dev = _create_device(db, "PC-03")
    exam_a = _create_exam(db, "Exam-Failed", status="pending")
    exam_b = _create_exam(db, "Exam-Next", status="pending")

    # Simulate midway session created during aborted/failed Exam A attempt
    sess_a = session_service.start_session(
        db=db,
        device_id=dev.device_id,
        exam_id=exam_a.exam_id,
        student_roll_number="PENDING",
    )
    # Mark Exam A as stopped / failed
    exam_a.status = ExamStatus.STOPPED.value
    db.commit()

    # Now Exam B starts on the same device without manual DB cleanup
    sess_b = session_service.start_session(
        db=db,
        device_id=dev.device_id,
        exam_id=exam_b.exam_id,
        student_roll_number="ROLL-NEW",
    )

    assert sess_b.status == "active"
    assert sess_b.exam_id == exam_b.exam_id

    # The stale session from failed Exam A was automatically reconciled to completed
    db.refresh(sess_a)
    assert sess_a.status == "completed"

    active_sessions = db.query(ExamSession).filter(
        ExamSession.device_id == dev.device_id, ExamSession.status == "active"
    ).all()
    assert len(active_sessions) == 1
    assert active_sessions[0].session_id == sess_b.session_id


def test_scenario_4_endpoint_restarts_during_exam_reconciles_stale_state(db: Session):
    """Scenario 4: Endpoint service restarts during Exam A -> stale state is reconciled correctly."""
    dev = _create_device(db, "PC-04")
    exam_a = _create_exam(db, "Exam-Restart", status="pending")

    # Start session on Exam A
    sess_a = session_service.start_session(
        db=db,
        device_id=dev.device_id,
        exam_id=exam_a.exam_id,
        student_roll_number="ROLL-004",
    )
    assert sess_a.status == "active"

    # Simulate exam being stopped while endpoint was rebooting / restarting offline
    exam_a.status = ExamStatus.STOPPED.value
    exam_a.ended_at = datetime.utcnow()
    # Note: simulate sess_a remaining 'active' in DB because offline endpoint missed termination signal
    db.commit()

    # When Exam B is created and activates this device
    exam_b = _create_exam(db, "Exam-AfterRestart", status="pending")
    ed_b = ExamDevice(exam_id=exam_b.exam_b_id if hasattr(exam_b, 'exam_b_id') else exam_b.exam_id, device_id=dev.device_id)
    db.add(ed_b)
    db.commit()

    # activate_exam must reconcile the stale session automatically
    exam_service.activate_exam(db, exam_b.exam_id)

    db.refresh(sess_a)
    assert sess_a.status == "completed"

    # Now starting session for Exam B succeeds
    sess_b = session_service.start_session(
        db=db,
        device_id=dev.device_id,
        exam_id=exam_b.exam_id,
        student_roll_number="ROLL-004-NEW",
    )
    assert sess_b.status == "active"
    assert sess_b.exam_id == exam_b.exam_id


def test_scenario_5_same_exam_activation_repeated_idempotent(db: Session):
    """Scenario 5: Same exam activation request repeated -> idempotent behavior."""
    dev = _create_device(db, "PC-05")
    exam_a = _create_exam(db, "Exam-Idempotent", status="pending")
    ed = ExamDevice(exam_id=exam_a.exam_id, device_id=dev.device_id)
    db.add(ed)
    db.commit()

    # Call activate_exam 3 times in a row
    res_1, hw_1 = exam_service.activate_exam(db, exam_a.exam_id)
    assert res_1.status == ExamStatus.ACTIVE.value

    res_2, hw_2 = exam_service.activate_exam(db, exam_a.exam_id)
    assert res_2.status == ExamStatus.ACTIVE.value

    res_3, hw_3 = exam_service.activate_exam(db, exam_a.exam_id)
    assert res_3.status == ExamStatus.ACTIVE.value

    assert hw_1 == hw_2 == hw_3


def test_scenario_6_two_simultaneous_exams_second_one_remains_blocked(db: Session):
    """Scenario 6: Two genuinely simultaneous exams targeting the same device -> second one remains blocked."""
    dev = _create_device(db, "PC-06")
    exam_1 = _create_exam(db, "Exam-Concurrent-1", status="active")
    exam_2 = _create_exam(db, "Exam-Concurrent-2", status="pending")

    # Device is active in Exam 1
    sess_1 = session_service.start_session(
        db=db,
        device_id=dev.device_id,
        exam_id=exam_1.exam_id,
        student_roll_number="STUDENT-1",
    )
    assert sess_1.status == "active"

    # Attempting to assign and start an active session for Exam 2 on the same device must fail
    ed2 = ExamDevice(exam_id=exam_2.exam_id, device_id=dev.device_id)
    db.add(ed2)
    db.commit()

    # 1. Starting session fails closed
    with pytest.raises(ValueError, match="already has an active exam session"):
        session_service.start_session(
            db=db,
            device_id=dev.device_id,
            exam_id=exam_2.exam_id,
            student_roll_number="STUDENT-2",
        )

    # 2. Activating Exam 2 fails closed because device is genuinely active in Exam 1
    with pytest.raises(ValueError, match="currently active in another exam"):
        exam_service.activate_exam(db, exam_2.exam_id)

    # Invariant preserved: only Exam 1 session exists and remains active
    active_sessions = db.query(ExamSession).filter(
        ExamSession.device_id == dev.device_id, ExamSession.status == "active"
    ).all()
    assert len(active_sessions) == 1
    assert active_sessions[0].session_id == sess_1.session_id
