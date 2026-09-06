"""End-to-end device credential lifecycle: enrol, receive a token, use it, be refused without it.

WHAT THIS FILE ADDS THAT THE OTHER SUITES DO NOT
------------------------------------------------
``test_auth_security.py`` proves the *gates*, hermetically and without a database. ``test_lab_
registration.py`` proves that registration returns 200. Neither follows one credential from the
moment enrolment issues it to the moment an agent endpoint accepts it, and that whole chain is what
broke in the field: the wizard never reached registration, so no token was ever issued, so every
``POST /api/v1/events`` was answered 401 and the dashboard read as "nothing happened".

So these tests run against the real (hermetic SQLite) database and use real rows:

* enrolment is performed through ``POST /api/v1/devices/register``, not stubbed;
* the token asserted on is the one that response returned, not one minted by the test;
* the endpoint it is presented to resolves a real ``Device`` row, so a 200 means the whole path
  worked rather than that a dependency happened not to raise.

The "wrong device" cases are the ones worth keeping honest. Two devices are really enrolled, and each
has a real token, so a refusal is attributable to the ownership check rather than to a lookup miss.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.database import SessionLocal
from backend.app.main import app
from backend.models.alert import Alert
from backend.models.device import Device
from backend.models.event import Event
from backend.models.exam import Exam, ExamDevice, ExamStatus
from backend.models.lab import Lab
from backend.models.lab_device import LabDevice
from backend.models.session import ExamSession
from backend.services.auth_service import create_device_token
from backend.websocket.manager import realtime_manager

REGISTER = "/api/v1/devices/register"
SESSIONS_START = "/api/v1/sessions/start"
EVENTS = "/api/v1/events"
VERIFY_STUDENT = "/api/v1/sessions/verify-student"

client = TestClient(app)


def _key_header() -> dict:
    return {"X-Enrollment-Key": settings.ENROLLMENT_BOOTSTRAP_KEY}


@pytest.fixture()
def lab():
    db = SessionLocal()
    lab_id = uuid.uuid4()
    row = Lab(lab_id=lab_id, building_id="Block-Cred", lab_name="Credential Lab",
              capacity=30, spemcs_enabled=True)
    try:
        db.add(row)
        db.commit()
        yield row
    finally:
        # lab_devices references the lab as well as the device, and foreign keys are enforced.
        db.query(LabDevice).filter(LabDevice.lab_id == lab_id).delete(synchronize_session=False)
        db.query(Lab).filter(Lab.lab_id == lab_id).delete(synchronize_session=False)
        db.commit()
        db.close()


def _enrol(lab_row: Lab, pc_number: str) -> dict:
    """Enrol a workstation the way the setup wizard does, and return the response body."""
    device_name = f"CredentialLab-PC{pc_number}"
    response = client.post(REGISTER, headers=_key_header(), json={
        "deviceName": device_name,
        "ipAddress": "192.0.2.50",
        "hardwareUuid": device_name,
        "labId": str(lab_row.lab_id),
        "pcNumber": pc_number,
        "hostname": f"STUDENT-VM-{pc_number}",
    })
    assert response.status_code == 200, response.text
    return response.json()


def _forget_devices(*hardware_uuids: str) -> None:
    """Delete enrolled workstations and everything that references them.

    ``conftest.py`` turns on ``PRAGMA foreign_keys=ON``, and registration does not create a bare
    ``Device`` row - ``device_service`` also links it into ``lab_devices``. So deleting the device
    alone fails with a FOREIGN KEY violation, and the child rows have to go first. Written as one
    helper rather than repeated per fixture because the ordering is the whole content of it.
    """
    db = SessionLocal()
    try:
        device_ids = [row.device_id for row in db.query(Device.device_id).filter(
            Device.hardware_uuid.in_(hardware_uuids)).all()]
        if not device_ids:
            return
        for model in (Alert, Event, ExamSession, ExamDevice, LabDevice):
            db.query(model).filter(model.device_id.in_(device_ids)).delete(
                synchronize_session=False)
        db.query(Device).filter(Device.device_id.in_(device_ids)).delete(
            synchronize_session=False)
        db.commit()
    finally:
        db.close()


@pytest.fixture()
def enrolled(lab):
    """One really-enrolled workstation, cleaned up afterwards."""
    body = _enrol(lab, "01")
    try:
        yield body
    finally:
        _forget_devices(body["hardwareUuid"])


# ── 1. An unenrolled workstation is refused everywhere it matters ──────────────


def test_an_unenrolled_workstation_cannot_fetch_the_lab_list_without_the_key(lab):
    """The originating symptom, stated as a requirement.

    The agent's own credential (a device token) does not exist yet at this point, and the enrolment
    key is the only thing it can present. Absent both, the answer is 401.
    """
    assert client.get("/api/v1/enrollment/labs").status_code == 401


def test_an_unenrolled_workstation_cannot_file_events(lab):
    response = client.post(EVENTS, json={
        "eventId": str(uuid.uuid4()), "deviceName": "CredentialLab-PC99",
        "eventType": "BLOCKED_PROCESS", "processId": 1234, "processName": "anydesk.exe",
        "timestampUtc": datetime.utcnow().isoformat(),
    })
    assert response.status_code == 401
    assert response.json()["detail"] == "Device authentication required"


def test_an_unenrolled_workstation_cannot_start_a_session(lab):
    response = client.post(SESSIONS_START, json={"deviceName": "CredentialLab-PC99"})
    assert response.status_code == 401


def test_the_enrollment_key_is_not_a_substitute_for_a_device_token(lab):
    """Holding the bootstrap key does not let a caller act AS a workstation.

    The key identifies an installation, not a machine - every workstation holds the same one - so
    accepting it here would let any one of them file violations under any other's name.
    """
    response = client.post(EVENTS, headers=_key_header(), json={
        "eventId": str(uuid.uuid4()), "deviceName": "CredentialLab-PC01",
        "eventType": "BLOCKED_PROCESS", "processId": 1234, "processName": "anydesk.exe",
        "timestampUtc": datetime.utcnow().isoformat(),
    })
    assert response.status_code == 401


# ── 2. Registration issues a credential that actually works ───────────────────


def test_registration_issues_a_device_token(enrolled):
    assert enrolled["deviceToken"], "registration must issue a device token"
    # Both spellings are returned for compatibility with two generations of agent. They must be the
    # same token; two different values would mean two credentials issued per enrolment.
    assert enrolled["device_token"] == enrolled["deviceToken"]
    assert enrolled["registered"] is True


def test_the_issued_token_is_accepted_by_an_agent_endpoint(enrolled):
    """The positive control for the whole file.

    A 404 ("no active exam is assigned to this device") is the CORRECT answer here and is what makes
    this a proof: the request got past ``require_device``, past ``_authenticated_device``'s real
    database lookup, and past the ownership check, and stopped in the route body. Anything in
    (401, 403) would mean the credential was refused.
    """
    response = client.post(SESSIONS_START, headers={"X-Device-Token": enrolled["deviceToken"]},
                           json={"hardwareUuid": enrolled["hardwareUuid"]})
    assert response.status_code not in (401, 403), response.text
    assert response.status_code == 404
    assert "no active exam" in response.json()["detail"].lower()


def test_the_issued_token_is_accepted_as_a_bearer_token_too(enrolled):
    response = client.post(SESSIONS_START,
                           headers={"Authorization": f"Bearer {enrolled['deviceToken']}"},
                           json={"hardwareUuid": enrolled["hardwareUuid"]})
    assert response.status_code not in (401, 403)


def test_the_token_carries_the_hardware_uuid_registration_resolved(enrolled):
    """``hw_uuid = req.hardwareUuid or req.deviceName`` on the server side.

    The agent sends its workstation identifier as both, so the two agree here - but the token's
    subject is the *resolved* value, and an agent that sent only ``deviceName`` would still be issued
    a usable token. Asserted so that a change to that fallback cannot silently issue tokens whose
    subject no longer matches any device row.
    """
    from backend.services.auth_service import verify_device_token

    payload = verify_device_token(enrolled["deviceToken"])
    assert payload is not None
    assert payload["hardware_uuid"] == enrolled["hardwareUuid"]
    assert payload["roles"] == ["endpoint"]


def test_the_issued_token_lives_long_enough_to_survive_an_exam(enrolled):
    """TTL is 30 days (``auth_service.create_device_token``, ``ttl_seconds=2592000``).

    Asserted as a floor rather than an exact value: what matters is that the credential outlives a
    workstation's reboot cycle, because a token that expires between enrolment and the next exam puts
    the deployment back in the state this whole change exists to fix. The M8/M9 documents claimed
    7 days; nothing ever issued that.
    """
    from backend.services.auth_service import verify_device_token

    payload = verify_device_token(enrolled["deviceToken"])
    lifetime = datetime.utcfromtimestamp(payload["exp"]) - datetime.utcfromtimestamp(payload["iat"])
    assert lifetime >= timedelta(days=7)


# ── 3. Re-enrolment and restart ────────────────────────────────────────────────


def test_a_restart_can_reuse_the_stored_token_without_re_enrolling(enrolled):
    """The agent persists the token in config.json and presents it after a reboot.

    Modelled here as "the same token, presented again in a second request, is still accepted", which
    is the property that matters: the credential is not bound to a connection or a process. If it
    were, every restart would have to re-enrol, and re-enrolment needs the bootstrap key present on
    disk permanently.
    """
    headers = {"X-Device-Token": enrolled["deviceToken"]}
    first = client.post(SESSIONS_START, headers=headers, json={})
    second = client.post(SESSIONS_START, headers=headers, json={})
    assert first.status_code == second.status_code
    assert second.status_code not in (401, 403)


def test_re_enrolling_the_same_workstation_is_not_a_conflict(enrolled, lab):
    """Registration is an upsert on hardware_uuid, so a reinstall does not need an admin to clear
    the old row - and it issues a fresh token rather than replaying the old one."""
    again = _enrol(lab, "01")
    assert again["hardwareUuid"] == enrolled["hardwareUuid"]
    assert again["deviceId"] == enrolled["deviceId"]
    assert again["deviceToken"] != enrolled["deviceToken"], (
        "each enrolment must mint a new token; a replayed one cannot be rotated"
    )
    # And the older token still verifies - there is no revocation list, which is a known property of
    # this design rather than an oversight, and is why the TTL matters.
    assert client.post(SESSIONS_START, headers={"X-Device-Token": enrolled["deviceToken"]},
                       json={}).status_code not in (401, 403)


def test_a_second_workstation_on_the_same_pc_number_is_refused(enrolled, lab):
    """Two machines claiming PC-01 in one lab is an estate error an invigilator cannot resolve from
    the dashboard, so it is refused at enrolment with 409."""
    response = client.post(REGISTER, headers=_key_header(), json={
        "deviceName": "CredentialLab-PC01-Impostor",
        "hardwareUuid": "CredentialLab-PC01-Impostor",
        "labId": str(lab.lab_id),
        "pcNumber": "01",
    })
    assert response.status_code == 409
    assert "already registered" in response.json()["detail"].lower()


# ── 4. Bad credentials ─────────────────────────────────────────────────────────


def test_a_garbage_token_is_refused(enrolled):
    response = client.post(SESSIONS_START, headers={"X-Device-Token": "not-a-token"}, json={})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired device token"


def test_an_expired_token_is_refused(enrolled):
    expired = create_device_token(hardware_uuid=enrolled["hardwareUuid"], ttl_seconds=-60)
    response = client.post(SESSIONS_START, headers={"X-Device-Token": expired}, json={})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired device token"


def test_a_token_for_a_device_that_no_longer_exists_is_refused(enrolled):
    """A credential for a deleted enrolment identifies nobody.

    401 rather than 404, deliberately: "no such device" would turn this endpoint into an oracle for
    which workstations are enrolled.
    """
    orphan = create_device_token(hardware_uuid="CredentialLab-PC-Never-Enrolled")
    response = client.post(SESSIONS_START, headers={"X-Device-Token": orphan}, json={})
    assert response.status_code == 401


def test_a_tampered_token_is_refused(enrolled):
    """One flipped character in the signature segment.

    The falsifier for every positive test above: if the HMAC were not actually checked, the token
    would still parse and would still name a real device.
    """
    token = enrolled["deviceToken"]
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    response = client.post(SESSIONS_START, headers={"X-Device-Token": tampered}, json={})
    assert response.status_code == 401


def test_the_refusal_never_echoes_the_token_or_the_key(enrolled):
    response = client.post(SESSIONS_START,
                           headers={"X-Device-Token": "a-distinctive-invalid-token"}, json={})
    body = response.text
    assert "a-distinctive-invalid-token" not in body
    assert enrolled["deviceToken"] not in body
    assert settings.ENROLLMENT_BOOTSTRAP_KEY not in body
    assert settings.DEVICE_TOKEN_SECRET not in body


# ── 5. Ownership: a valid token for the wrong workstation ──────────────────────


@pytest.fixture()
def two_enrolled(lab):
    """Two really-enrolled workstations, each with its own real token."""
    first = _enrol(lab, "01")
    second = _enrol(lab, "02")
    try:
        yield first, second
    finally:
        _forget_devices(first["hardwareUuid"], second["hardwareUuid"])


def test_a_workstation_cannot_start_a_session_naming_another(two_enrolled):
    first, second = two_enrolled
    response = client.post(SESSIONS_START, headers={"X-Device-Token": first["deviceToken"]},
                           json={"hardwareUuid": second["hardwareUuid"]})
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"].lower()


def test_a_workstation_cannot_file_events_against_another(two_enrolled):
    first, second = two_enrolled
    response = client.post(EVENTS, headers={"X-Device-Token": first["deviceToken"]}, json={
        "eventId": str(uuid.uuid4()), "deviceName": second["deviceName"],
        "eventType": "BLOCKED_PROCESS", "processId": 4242, "processName": "anydesk.exe",
        "timestampUtc": datetime.utcnow().isoformat(),
    })
    assert response.status_code == 403


def test_each_workstation_can_act_as_itself(two_enrolled):
    """The positive control for the two refusals above.

    Without it, both would pass against an endpoint that refuses every device - which is
    indistinguishable from the bug being fixed.
    """
    for body in two_enrolled:
        response = client.post(SESSIONS_START, headers={"X-Device-Token": body["deviceToken"]},
                               json={"hardwareUuid": body["hardwareUuid"]})
        assert response.status_code not in (401, 403), response.text


def test_a_workstation_cannot_bind_a_student_onto_another_devices_session(two_enrolled):
    """The subtler ownership case: ``sessionId`` references a row belonging to some device, and
    nothing in the request body says which. Binding a roll number onto another candidate's live
    session attributes one student's later violations to another."""
    first, second = two_enrolled
    db = SessionLocal()
    exam_id, session_id = uuid.uuid4(), uuid.uuid4()
    try:
        second_device = db.query(Device).filter(
            Device.hardware_uuid == second["hardwareUuid"]).first()
        db.add(Exam(exam_id=exam_id, exam_name="Ownership Exam",
                    approved_browser="chrome", status=ExamStatus.ACTIVE.value,
                    started_at=datetime.utcnow()))
        db.add(ExamSession(session_id=session_id, exam_id=exam_id,
                           device_id=second_device.device_id,
                           student_roll_number="R-0001", started_at=datetime.utcnow()))
        db.commit()

        response = client.post(VERIFY_STUDENT, headers={"X-Device-Token": first["deviceToken"]},
                               json={"sessionId": str(session_id), "rollNumber": "R-1234"})
        assert response.status_code == 403
        assert "not authorized" in response.json()["detail"].lower()
    finally:
        db.query(ExamSession).filter(ExamSession.session_id == session_id).delete(
            synchronize_session=False)
        db.query(Exam).filter(Exam.exam_id == exam_id).delete(synchronize_session=False)
        db.commit()
        db.close()


# ── 6. The full path: an authenticated event actually lands ────────────────────


def test_an_authenticated_violation_is_ingested_end_to_end(enrolled, lab):
    """The whole chain, with an exam really assigned.

    This is the test that would have failed in the field: the agent's ``POST /api/v1/events`` carried
    no ``X-Device-Token`` at all, so it never got as far as ingestion, and the dashboard showed an
    empty alert list during a live exam.

    ``realtime_manager`` must be primed because ``ingest_event`` gates on its cache before touching
    the database - an event for a device with no cached active exam is discarded and returns no
    alert, which is correct behaviour and would make this test silently vacuous.
    """
    db = SessionLocal()
    exam_id = uuid.uuid4()
    device_name = enrolled["deviceName"]
    event_id = str(uuid.uuid4())
    try:
        device = db.query(Device).filter(Device.hardware_uuid == enrolled["hardwareUuid"]).first()
        db.add(Exam(exam_id=exam_id, exam_name="Ingestion Exam", approved_browser="chrome",
                    status=ExamStatus.ACTIVE.value, started_at=datetime.utcnow()))
        db.add(ExamDevice(id=uuid.uuid4(), exam_id=exam_id, device_id=device.device_id))
        db.commit()
        realtime_manager.set_exam_active(str(exam_id), [device_name, enrolled["hardwareUuid"]])

        response = client.post(EVENTS, headers={"X-Device-Token": enrolled["deviceToken"]}, json={
            "eventId": event_id, "deviceName": device_name,
            "eventType": "BLOCKED_PROCESS", "processId": 8080, "processName": "anydesk.exe",
            "timestampUtc": datetime.utcnow().isoformat(),
            "reason": "Prohibited remote access tool",
        })

        assert response.status_code == 200, response.text
        assert response.json()["status"] == "Ingested"

        stored = db.query(Event).filter(Event.event_id == uuid.UUID(event_id)).first()
        assert stored is not None, "an accepted event must actually be persisted"
        assert stored.device_id == device.device_id
    finally:
        realtime_manager.set_exam_inactive(str(exam_id))
        db.query(Alert).filter(Alert.event_id == uuid.UUID(event_id)).delete(
            synchronize_session=False)
        db.query(Event).filter(Event.event_id == uuid.UUID(event_id)).delete(
            synchronize_session=False)
        db.query(ExamDevice).filter(ExamDevice.exam_id == exam_id).delete(synchronize_session=False)
        db.query(Exam).filter(Exam.exam_id == exam_id).delete(synchronize_session=False)
        db.commit()
        db.close()
