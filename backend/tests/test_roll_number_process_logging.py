"""Test roll number session verification and process event attribution end-to-end."""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.database import SessionLocal
from backend.app.main import app
from backend.models.alert import Alert
from backend.models.device import Device
from backend.models.lab_device import LabDevice
from backend.models.event import Event
from backend.models.exam import Exam, ExamDevice, ExamStatus
from backend.models.lab import Lab
from backend.models.session import ExamSession
from backend.websocket.manager import realtime_manager

client = TestClient(app)

REGISTER = "/api/v1/devices/register"
EVENTS = "/api/v1/events"
SESSIONS_START = "/api/v1/sessions/start"
SESSIONS_VERIFY = "/api/v1/sessions/verify-student"


@pytest.fixture()
def lab():
    db = SessionLocal()
    lab_id = uuid.uuid4()
    row = Lab(lab_id=lab_id, building_id="Block-Roll", lab_name="Roll Flow Lab",
              capacity=30, spemcs_enabled=True)
    try:
        db.add(row)
        db.commit()
        yield row
    finally:
        db.query(LabDevice).filter(LabDevice.lab_id == lab_id).delete(synchronize_session=False)
        db.query(Lab).filter(Lab.lab_id == lab_id).delete(synchronize_session=False)
        db.commit()
        db.close()


@pytest.fixture()
def enrolled(lab):
    device_name = f"RollLab-PC{uuid.uuid4().hex[:6]}"
    hw_uuid = f"HW-UUID-{uuid.uuid4().hex[:8]}"
    resp = client.post(REGISTER, headers={"X-Enrollment-Key": settings.ENROLLMENT_BOOTSTRAP_KEY}, json={
        "deviceName": device_name,
        "ipAddress": "192.168.11.59",
        "hardwareUuid": hw_uuid,
        "labId": str(lab.lab_id),
        "pcNumber": "01",
        "hostname": "STUDENT-VM-01",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()

    try:
        yield body
    finally:
        db = SessionLocal()
        try:
            dev = db.query(Device).filter(Device.hardware_uuid == hw_uuid).first()
            if dev:
                dev_id = dev.device_id
                for m in (Alert, Event, ExamSession, ExamDevice, LabDevice):
                    db.query(m).filter(m.device_id == dev_id).delete(synchronize_session=False)
                db.query(Device).filter(Device.device_id == dev_id).delete(synchronize_session=False)
                db.commit()
        finally:
            db.close()


def test_roll_number_and_process_event_attribution_flow(enrolled, lab):
    """Verify that:
    1. Pre-session process events without roll number are ingested with N/A roll number.
    2. Student roll number verification creates/binds an active ExamSession.
    3. Subsequent process events with studentRollNumber are attributed to the active session.
    """
    db = SessionLocal()
    exam_id = uuid.uuid4()
    session_id = uuid.uuid4()
    device_name = enrolled["deviceName"]
    pre_event_id = str(uuid.uuid4())
    post_event_id = str(uuid.uuid4())
    expected_roll = "2301921540174"

    try:
        device = db.query(Device).filter(Device.hardware_uuid == enrolled["hardwareUuid"]).first()
        db.add(Exam(
            exam_id=exam_id,
            exam_name="Roll Number Flow Exam",
            approved_browser="chrome",
            status=ExamStatus.ACTIVE.value,
            started_at=datetime.now(timezone.utc),
        ))
        db.add(ExamDevice(id=uuid.uuid4(), exam_id=exam_id, device_id=device.device_id))
        db.commit()
        realtime_manager.set_exam_active(str(exam_id), [device_name, enrolled["hardwareUuid"]])

        # ── Step A: Process event BEFORE roll number entry ────────────────────────
        pre_resp = client.post(
            EVENTS,
            headers={"X-Device-Token": enrolled["deviceToken"]},
            json={
                "eventId": pre_event_id,
                "deviceName": device_name,
                "eventType": "APPLICATION_OPENED",
                "processId": 101,
                "processName": "unauthorized_tool.exe",
                "timestampUtc": datetime.now(timezone.utc).isoformat(),
                "reason": "Unauthorized process detected",
            },
        )
        assert pre_resp.status_code == 200, pre_resp.text
        pre_stored = db.query(Event).filter(Event.event_id == uuid.UUID(pre_event_id)).first()
        assert pre_stored is not None
        assert pre_stored.student_roll_number == "N/A", "Pre-session event must record N/A when roll number is not set"
        assert pre_stored.session_id is None, "Pre-session event has no session_id"

        # ── Step B: Student verification flow ─────────────────────────────────────
        start_resp = client.post(
            SESSIONS_START,
            headers={"X-Device-Token": enrolled["deviceToken"]},
            json={
                "sessionId": str(session_id),
                "studentRollNumber": expected_roll,
                "approvedBrowser": "chrome",
            },
        )
        assert start_resp.status_code == 200, start_resp.text

        verify_resp = client.post(
            SESSIONS_VERIFY,
            headers={"X-Device-Token": enrolled["deviceToken"]},
            json={
                "sessionId": str(session_id),
                "rollNumber": expected_roll,
            },
        )
        assert verify_resp.status_code == 200, verify_resp.text
        assert verify_resp.json()["valid"] is True

        # Verify session in database is active with roll number
        session_row = db.query(ExamSession).filter(ExamSession.session_id == session_id).first()
        assert session_row is not None
        assert session_row.status == "active"
        assert session_row.student_roll_number == expected_roll
        assert session_row.exam_id == exam_id
        assert session_row.device_id == device.device_id

        # ── Step C: Process event AFTER roll number entry ────────────────────────
        post_resp = client.post(
            EVENTS,
            headers={"X-Device-Token": enrolled["deviceToken"]},
            json={
                "eventId": post_event_id,
                "deviceName": device_name,
                "studentRollNumber": expected_roll,
                "eventType": "APPLICATION_OPENED",
                "processId": 202,
                "processName": "calc.exe",
                "timestampUtc": datetime.now(timezone.utc).isoformat(),
                "reason": "Unauthorized process detected: calc.exe",
            },
        )
        assert post_resp.status_code == 200, post_resp.text

        # ── Step D: Verify Event is attributed to the active session and roll ──────
        post_stored = db.query(Event).filter(Event.event_id == uuid.UUID(post_event_id)).first()
        assert post_stored is not None
        assert post_stored.session_id == session_id, "Event must be linked to active session_id"
        assert post_stored.student_roll_number == expected_roll, "Event must have student roll number"
        assert post_stored.device_id == device.device_id
        assert post_stored.process_name == "calc.exe"

    finally:
        realtime_manager.set_exam_inactive(str(exam_id))
        db.query(Alert).filter(Alert.event_id.in_([uuid.UUID(pre_event_id), uuid.UUID(post_event_id)])).delete(
            synchronize_session=False
        )
        db.query(Event).filter(Event.event_id.in_([uuid.UUID(pre_event_id), uuid.UUID(post_event_id)])).delete(
            synchronize_session=False
        )
        db.query(ExamSession).filter(ExamSession.session_id == session_id).delete(synchronize_session=False)
        db.query(ExamDevice).filter(ExamDevice.exam_id == exam_id).delete(synchronize_session=False)
        db.query(Exam).filter(Exam.exam_id == exam_id).delete(synchronize_session=False)
        db.commit()
        db.close()
