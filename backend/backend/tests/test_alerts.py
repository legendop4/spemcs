"""Alerts raised outside an exam.

This file was an empty placeholder, and that emptiness is the reason a schema defect survived: no
test in the suite had ever inserted an ``Alert`` row, so ``Alert.exam_id``'s ``nullable=False``
was never once executed. It was wrong. ``event_service.ingest_event`` writes
``exam_id=exam.exam_id if exam else None`` and the deployed database has always had the column
nullable, holding a real ``PROHIBITED_DOMAIN_ACCESS`` alert that depends on it.

``alembic check`` against the live database found it. What follows is what would have found it
first, and what will fail if anyone tightens the column again.

The failure mode is worth stating precisely, because it is worse than a lost alert. The
``db.add(alert)`` in ``ingest_event`` is followed immediately by ``db.flush()``, inside the same
transaction that just persisted the ``Event``. Under NOT NULL that flush raises ``IntegrityError``
and takes the event down with the alert - so a device reporting AnyDesk while it is not in an
ACTIVE exam would leave no trace at all.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest
from sqlalchemy.exc import IntegrityError

from backend.app.database import SessionLocal
from backend.models.alert import Alert
from backend.models.device import Device
from backend.models.event import Classification, Event


def _device(db, name: str) -> Device:
    device = Device(device_name=name, hardware_uuid=str(uuid.uuid4()), status="online")
    db.add(device)
    db.flush()
    return device


def _event(db, device: Device) -> Event:
    event = Event(
        device_id=device.device_id,
        device_name=device.device_name,
        event_type="PROHIBITED_DOMAIN_ACCESS",
        timestamp=datetime.utcnow(),
        classification=Classification.UNAUTHORIZED.value,
    )
    db.add(event)
    db.flush()
    return event


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def test_an_alert_with_no_exam_can_be_persisted(db):
    """The schema-level claim: `alerts.exam_id` accepts NULL.

    This is the exact row shape production holds - severity high, an unauthorized event, no exam.
    """
    device = _device(db, "TestTower:Lab-01:PC-001")
    event = _event(db, device)

    alert = Alert(
        event_id=event.event_id,
        exam_id=None,
        device_id=device.device_id,
        severity="high",
        message="HIGH: Prohibited AI assistant (Microsoft Edge) detected",
        status="open",
    )
    db.add(alert)
    db.flush()

    stored = db.get(Alert, alert.alert_id)
    assert stored is not None
    assert stored.exam_id is None


def test_the_nullability_check_is_not_vacuous(db):
    """Falsifier for the test above.

    SQLite silently ignores several constraints unless configured otherwise, so "the insert did not
    raise" is only evidence if a genuinely NOT NULL column in the same table *does* raise. If this
    test ever starts failing, the one above has stopped proving anything.
    """
    device = _device(db, "TestTower:Lab-01:PC-002")
    event = _event(db, device)

    alert = Alert(
        event_id=event.event_id,
        exam_id=None,
        device_id=None,  # NOT NULL, and must stay that way - an alert always has a device
        severity="high",
        message="should not persist",
        status="open",
    )
    db.add(alert)
    with pytest.raises(IntegrityError):
        db.flush()


def test_ingest_event_records_a_violation_from_a_device_with_no_active_exam(db, monkeypatch):
    """The production path, end to end, for the disagreement that actually produced the live row.

    ``ingest_event`` resolves the exam twice by two independent mechanisms: an in-memory cache
    (``realtime_manager.get_active_exam_for_device``) gates the whole function, and a database
    query joining ``ExamDevice`` to an ``Exam`` with status ACTIVE supplies ``exam_id``. Those two
    can disagree - a stopped exam still cached, an assignment made through another path - and when
    they do, this is the result: the event is ingested, the alert is raised, and it has no exam.

    Nothing here is contrived to reach the NULL. The cache is primed because that is what the gate
    reads; no ``ExamDevice`` row is created because that is the state under test.
    """
    from backend.websocket.manager import realtime_manager

    device = _device(db, "TestTower:Lab-01:PC-003")
    db.commit()

    monkeypatch.setitem(realtime_manager._device_exam_map, device.device_name, str(uuid.uuid4()))

    from backend.services import event_service

    event, alert = event_service.ingest_event(
        db=db,
        event_id=str(uuid.uuid4()),
        device_name=device.device_name,
        event_type="BLOCKED_PROCESS",
        process_name="AnyDesk.exe",
        process_id=4242,
        timestamp_utc=datetime.utcnow().isoformat() + "Z",
        reason="Remote desktop tool detected",
    )

    assert alert is not None, "an off-exam violation must still raise an alert"
    assert alert.exam_id is None
    assert alert.severity == "critical"
    # The event survives too. Under NOT NULL the flush would have aborted this transaction.
    assert db.get(Event, event.event_id) is not None
