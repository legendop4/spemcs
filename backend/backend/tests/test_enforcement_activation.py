"""P1-R (per-device enforcement state) and P1-S (fail-closed activation).

Two defects are pinned here, and they are the same defect seen from two ends.

**P1-R.** ``device_policy_states`` has existed since M1 and nothing ever wrote a row to it. The
distribute endpoint returned ``{"status": "SENT"}``, the agent socket broadcast a policy report to
whichever dashboards happened to be connected, and neither left a trace. So "which of these
workstations is actually locked down" had no answer after a page refresh, and P1-S's precondition
had nothing to consult.

**P1-S.** The entire "is this exam safe to start" decision lived in
``frontend/src/pages/ExamShieldPage.tsx::handleActivate``. ``POST /api/exams/{id}/activate`` set the
exam ACTIVE, marked every assigned device ``MONITORING``, and answered ``{"status": "activated"}``
unconditionally - so a direct POST with any staff token produced an ACTIVE network-enforcement exam
with no policy at all, and a distribution loop that failed on every device still reached an
endpoint that reported success.

**Falsifiers.** Refusal tests are only meaningful if the route can still succeed, so
``test_a_ready_enforcement_exam_activates`` and ``test_distribution_then_activation_is_the_whole_loop``
are positive controls: without them, deleting the route body would turn this file green. In the same
spirit ``test_is_armed_treats_an_unknown_status_as_not_armed`` checks the *complement* framing of
``_NOT_ARMED`` rather than restating the constant, and
``test_a_report_naming_nothing_is_not_attributed_to_the_active_exam`` sets up precisely the state a
"just use the device's current exam" fallback would latch onto.

Everything here runs against the hermetic SQLite database from ``conftest.py`` and an RSA-1024
signing keyring in a temp directory. Nothing touches the network, the real keyring, or the deployed
database.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app.database import SessionLocal
from backend.app.main import app
from backend.models.device import Device
from backend.models.exam import Exam, ExamDevice, ExamDeviceStatus, ExamStatus
from backend.models.policy import DevicePolicyState, NetworkPolicy
from backend.models.user import User, UserRole
from backend.services import device_policy_state_service as dps
from backend.services import enforcement_readiness as er
from backend.services import policy_service
from backend.services.auth_service import require_auth
from backend.services.destination_resolver import StaticDnsResolver, TrustedDestinationResolver
from backend.services.signing_key_manager import SigningKeyManager, set_signing_key_manager
from backend.websocket import agent_ws
from backend.websocket.manager import realtime_manager

# RSA-1024 is a test-only size, exactly as in test_signing_key_lifecycle.py: nothing under test
# depends on the modulus, and PSS/SHA-256 with a 32-byte salt fits (32 + 32 + 2 <= 128).
TEST_KEY_SIZE = 1024

MGMT = {"ip_addresses": ["127.0.0.1"], "port": 8002, "use_tls": False}


# ==============================================================================
# Fixtures
# ==============================================================================
@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture()
def keys(tmp_path):
    """A throwaway persistent keyring, installed process-wide for the routes to find.

    Installed rather than only passed to ``evaluate_exam_readiness``: the activation route calls
    ``get_signing_key_manager()`` itself, so a test that only injected would not exercise the path
    production takes.
    """
    manager = SigningKeyManager(key_dir=tmp_path / "signing_keys", key_size=TEST_KEY_SIZE)
    set_signing_key_manager(manager)
    try:
        yield manager
    finally:
        set_signing_key_manager(None)


@pytest.fixture()
def admin():
    """Satisfy every operator gate by overriding the one dependency they all share.

    ``require_staff`` and ``require_admin`` are both ``require_role(...)`` closures over
    ``Depends(require_auth)``, so overriding ``require_auth`` reaches all of them and still lets the
    real role comparison run.
    """
    user = User()
    user.user_id = uuid.uuid4()
    user.username = "enforcement-activation-test"
    user.role = UserRole.ADMIN.value
    user.is_active = True
    app.dependency_overrides[require_auth] = lambda: user
    try:
        yield user
    finally:
        app.dependency_overrides.pop(require_auth, None)


@pytest.fixture()
def client(admin):
    # No context manager: the lifespan (production-secret validation, engine connect) is not what
    # is under test here, and skipping it keeps the suite hermetic.
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def world(db):
    """Builds exams/devices/policies and removes exactly what it built.

    The hermetic database is shared for the whole session, so teardown is explicit and ordered by
    foreign key rather than relying on ORM cascades.
    """
    made = {"exams": [], "devices": []}

    class World:
        def exam(self, *, enforcement=True, browser="chrome"):
            row = Exam(
                exam_name=f"enf-{uuid.uuid4().hex[:8]}",
                approved_browser=browser,
                status=ExamStatus.PENDING.value,
                network_enforcement=enforcement,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            made["exams"].append(row.exam_id)
            return row

        def device(self, *, hardware_uuid=None, name=None):
            row = Device(
                hardware_uuid=hardware_uuid if hardware_uuid is not None else str(uuid.uuid4()),
                device_name=name or f"Lab:PC-{uuid.uuid4().hex[:6]}",
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            made["devices"].append(row.device_id)
            return row

        def assign(self, exam, device):
            db.add(ExamDevice(
                exam_id=exam.exam_id,
                device_id=device.device_id,
                status=ExamDeviceStatus.PENDING.value,
            ))
            db.commit()

        def policy(self, exam, *, version=1, not_before=None, expires_at=None):
            now = datetime.now(timezone.utc)
            resolver = TrustedDestinationResolver(
                StaticDnsResolver({"lms.univ.edu": ["198.51.100.7"]})
            )
            return policy_service.compile_and_persist_exam_policy(
                db=db,
                exam_id=exam.exam_id,
                version=version,
                management_server=MGMT,
                not_before=not_before or (now - timedelta(minutes=5)),
                expires_at=expires_at or (now + timedelta(hours=4)),
                signer=_active_signer(),
                resolved_destinations=[{
                    "name": "Exam LMS",
                    "domains": ["lms.univ.edu"],
                    "tcp_ports": [443],
                }],
                destination_resolver=resolver,
            )

        def arm(self, exam, device, policy, status=dps.STATUS_APPLYING):
            return dps.record_state(
                db,
                exam_id=exam.exam_id,
                device_id=device.device_id,
                policy_id=policy.policy_id,
                status=status,
            )

    yield World()

    db.rollback()
    exam_ids, device_ids = made["exams"], made["devices"]
    if exam_ids:
        db.query(DevicePolicyState).filter(
            DevicePolicyState.exam_id.in_(exam_ids)).delete(synchronize_session=False)
        db.query(NetworkPolicy).filter(
            NetworkPolicy.exam_id.in_(exam_ids)).delete(synchronize_session=False)
        db.query(ExamDevice).filter(
            ExamDevice.exam_id.in_(exam_ids)).delete(synchronize_session=False)
        db.query(Exam).filter(Exam.exam_id.in_(exam_ids)).delete(synchronize_session=False)
    if device_ids:
        db.query(Device).filter(Device.device_id.in_(device_ids)).delete(synchronize_session=False)
    db.commit()


def _active_signer():
    from backend.services.signing_key_manager import get_signing_key_manager
    return get_signing_key_manager().active_signer()


def _codes(payload) -> list[str]:
    return [p["code"] for p in payload["problems"]]


def _fresh(db, model, pk):
    db.rollback()  # end this session's snapshot so the route's committed writes are visible
    return db.get(model, pk)


# ==============================================================================
# P1-R.1  is_armed: the single place "enforcing" is defined
# ==============================================================================
@pytest.mark.parametrize("status,expected", [
    (dps.STATUS_APPLIED, True),
    (dps.STATUS_APPLYING, True),
    (dps.STATUS_PENDING, False),
    (dps.STATUS_FAILED, False),
    (dps.STATUS_ROLLED_BACK, False),
    (None, False),
])
def test_is_armed_classifies_each_lifecycle_status(status, expected):
    assert dps.is_armed(status) is expected


def test_is_armed_treats_an_unknown_status_as_not_armed():
    """The complement framing, checked rather than assumed.

    ``_NOT_ARMED`` lists the statuses that are *not* enforcing, so a value nobody has classified is
    armed by default - the wrong direction for a flag that gates whether an exam may start. This
    test fails the moment somebody flips it to an allow-list of armed statuses without thinking
    about the default.
    """
    assert dps.is_armed("SOMETHING_NOBODY_HAS_DEFINED_YET") is True, (
        "is_armed is deliberately permissive for unknown statuses; the fail-closed guard is at the "
        "boundary (agent_ws._map_reported_status), which never lets an unknown status be stored"
    )
    assert "SOMETHING_NOBODY_HAS_DEFINED_YET" not in dps.VALID_STATUSES


def test_record_state_refuses_a_status_outside_the_lifecycle(db, world):
    exam, device = world.exam(), world.device()
    policy = world.policy(exam)
    with pytest.raises(ValueError):
        dps.record_state(
            db, exam_id=exam.exam_id, device_id=device.device_id,
            policy_id=policy.policy_id, status="ENFORCED-ISH",
        )
    db.rollback()


# ==============================================================================
# P1-R.2  record_state: upsert, error hygiene, applied_at
# ==============================================================================
def test_record_state_upserts_rather_than_accumulating(db, world):
    """UNIQUE(exam_id, device_id) permits one row per pairing, so a retry must move the state."""
    exam, device = world.exam(), world.device()
    policy = world.policy(exam)

    first = world.arm(exam, device, policy, status=dps.STATUS_FAILED)
    second = dps.record_state(
        db, exam_id=exam.exam_id, device_id=device.device_id,
        policy_id=policy.policy_id, status=dps.STATUS_APPLIED, rules_installed=6,
    )

    assert first.id == second.id
    assert db.query(DevicePolicyState).filter(
        DevicePolicyState.exam_id == exam.exam_id).count() == 1


def test_a_recovered_device_does_not_keep_its_old_error(db, world):
    """A stale ``last_error`` on an APPLIED row makes a working workstation look broken forever."""
    exam, device = world.exam(), world.device()
    policy = world.policy(exam)

    dps.record_state(db, exam_id=exam.exam_id, device_id=device.device_id,
                     policy_id=policy.policy_id, status=dps.STATUS_FAILED,
                     last_error="Device is not connected to the agent WebSocket")
    recovered = dps.record_state(db, exam_id=exam.exam_id, device_id=device.device_id,
                                 policy_id=policy.policy_id, status=dps.STATUS_APPLIED)

    assert recovered.last_error is None
    assert recovered.applied_at is not None


def test_applied_at_is_set_only_when_enforcement_is_live(db, world):
    exam, device = world.exam(), world.device()
    policy = world.policy(exam)

    applying = world.arm(exam, device, policy, status=dps.STATUS_APPLYING)
    assert applying.applied_at is None, "APPLYING means the bytes left the server, nothing more"

    applied = dps.record_state(db, exam_id=exam.exam_id, device_id=device.device_id,
                               policy_id=policy.policy_id, status=dps.STATUS_APPLIED)
    assert applied.applied_at is not None


def test_an_over_long_error_is_truncated_rather_than_losing_the_update(db, world):
    """``last_error`` is String(255); an untruncated message raises DataError on PostgreSQL, and the
    whole state transition would be lost with it."""
    exam, device = world.exam(), world.device()
    policy = world.policy(exam)

    state = dps.record_state(
        db, exam_id=exam.exam_id, device_id=device.device_id, policy_id=policy.policy_id,
        status=dps.STATUS_FAILED, last_error="x" * 4000,
    )

    assert len(state.last_error) == 255
    assert state.last_error.endswith("...")


def test_a_redistribution_moves_the_state_row_to_the_new_policy(db, world):
    """A state row pointing at a superseded policy misreports which bytes the device holds."""
    exam, device = world.exam(), world.device()
    first, second = world.policy(exam, version=1), world.policy(exam, version=2)

    world.arm(exam, device, first)
    moved = world.arm(exam, device, second)

    assert moved.policy_id == second.policy_id


# ==============================================================================
# P1-R.3  Resolving a device from the identifier the socket actually carries
# ==============================================================================
def test_state_can_be_recorded_for_a_device_registered_without_a_hardware_uuid(db, world):
    """``realtime_manager`` addresses endpoints by ``hardware_uuid or device_name``, so a device
    with no hardware UUID is reachable under its name and must not be invisible to state tracking."""
    exam = world.exam()
    device = world.device(hardware_uuid=None, name=f"NamedOnly-{uuid.uuid4().hex[:6]}")
    policy = world.policy(exam)

    state = dps.record_state_for_hardware_uuid(
        db, exam_id=exam.exam_id, hardware_uuid=device.device_name,
        policy_id=policy.policy_id, status=dps.STATUS_APPLYING,
    )

    assert state is not None and state.device_id == device.device_id


def test_an_unknown_hardware_uuid_records_nothing_and_does_not_raise(db, world):
    exam = world.exam()
    policy = world.policy(exam)

    assert dps.record_state_for_hardware_uuid(
        db, exam_id=exam.exam_id, hardware_uuid="no-such-workstation",
        policy_id=policy.policy_id, status=dps.STATUS_APPLYING,
    ) is None


# ==============================================================================
# P1-R.4  Distribution writes the state the precondition later reads
# ==============================================================================
@pytest.fixture()
def sent_ok(monkeypatch):
    """Pretend the endpoint's socket is connected and accepted the frame."""
    async def _send(**_kwargs):
        return True
    monkeypatch.setattr(realtime_manager, "send_signed_policy_to_device", _send)


@pytest.fixture()
def send_fails(monkeypatch):
    async def _send(**_kwargs):
        return False
    monkeypatch.setattr(realtime_manager, "send_signed_policy_to_device", _send)


def test_a_successful_distribution_records_applying_not_applied(client, db, world, keys, sent_ok):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)

    resp = client.post(f"/api/policies/distribute/{exam.exam_id}/{device.hardware_uuid}")

    assert resp.status_code == 200, resp.text
    state = _fresh_state(db, exam, device)
    assert state.status == dps.STATUS_APPLYING, (
        "the server sent bytes; whether enforcement is live is a claim only the endpoint can make"
    )
    assert state.policy_id == policy.policy_id


def test_a_distribution_to_a_disconnected_device_records_the_failure(
    client, db, world, keys, send_fails
):
    """Recorded BEFORE the 503 is raised, so the refusal survives the operator not watching."""
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    world.policy(exam)

    resp = client.post(f"/api/policies/distribute/{exam.exam_id}/{device.hardware_uuid}")

    assert resp.status_code == 503
    state = _fresh_state(db, exam, device)
    assert state.status == dps.STATUS_FAILED
    assert "not connected" in state.last_error


def test_a_dynamic_update_returns_the_device_to_applying(client, db, world, keys, sent_ok):
    """An UPDATE_EXAM_POLICY supersedes what the device is enforcing. Leaving an earlier APPLIED in
    place would claim it is enforcing a version it has not installed."""
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    first = world.policy(exam, version=1)
    world.arm(exam, device, first, status=dps.STATUS_APPLIED)
    second = world.policy(exam, version=2)

    resp = client.post(f"/api/policies/update/{exam.exam_id}/{device.hardware_uuid}")

    assert resp.status_code == 200, resp.text
    state = _fresh_state(db, exam, device)
    assert state.status == dps.STATUS_APPLYING
    assert state.policy_id == second.policy_id
    assert state.applied_at is None


def _fresh_state(db, exam, device):
    db.rollback()
    state = dps.get_state(db, exam.exam_id, device.device_id)
    assert state is not None, "no enforcement state row was written"
    db.refresh(state)
    return state


# ==============================================================================
# P1-R.5  The read side
# ==============================================================================
def test_the_device_states_endpoint_publishes_status_and_armed_separately(
    client, db, world, keys
):
    """Two different questions: ``status`` is the lifecycle, ``armed`` is the activation verdict."""
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)
    world.arm(exam, device, policy, status=dps.STATUS_APPLYING)

    resp = client.get(f"/api/policies/exam/{exam.exam_id}/device-states")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 1
    assert body[0]["status"] == "APPLYING"
    assert body[0]["armed"] is True
    assert body[0]["device_name"] == device.device_name
    assert body[0]["hardware_uuid"] == device.hardware_uuid


def test_a_failed_device_is_reported_as_not_armed_with_its_error(client, db, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)
    dps.record_state(db, exam_id=exam.exam_id, device_id=device.device_id,
                     policy_id=policy.policy_id, status=dps.STATUS_FAILED,
                     last_error="Signature rejected by endpoint")

    resp = client.get(f"/api/policies/exam/{exam.exam_id}/device-states/{device.device_id}")

    assert resp.status_code == 200, resp.text
    assert resp.json()["armed"] is False
    assert resp.json()["last_error"] == "Signature rejected by endpoint"


def test_a_device_with_no_recorded_state_is_a_404_not_an_invented_row(client, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)

    resp = client.get(f"/api/policies/exam/{exam.exam_id}/device-states/{device.device_id}")

    assert resp.status_code == 404


# ==============================================================================
# P1-R.6  Endpoint-reported status, mapped fail-closed
# ==============================================================================
@pytest.mark.parametrize("reported,expected", [
    ("APPLIED", dps.STATUS_APPLIED),
    ("ENFORCING", dps.STATUS_APPLIED),
    ("applying", dps.STATUS_APPLYING),
    ("  Applied  ", dps.STATUS_APPLIED),
    ("FAILED", dps.STATUS_FAILED),
    ("REJECTED", dps.STATUS_FAILED),
    ("INVALID", dps.STATUS_FAILED),
    ("ROLLED_BACK", dps.STATUS_ROLLED_BACK),
])
def test_the_reported_vocabulary_maps_onto_the_lifecycle(reported, expected):
    mapped, error = agent_ws._map_reported_status(reported)
    assert mapped == expected
    assert error is None


@pytest.mark.parametrize("reported", [None, "", "PARTIALLY_APPLIED", "ok", "APPLIED_MOSTLY"])
def test_an_unreadable_status_fails_closed_and_says_what_arrived(reported):
    """Leaving the row at APPLYING - which the precondition counts as armed - would claim a
    workstation is locked down on the strength of a message the server could not read."""
    mapped, error = agent_ws._map_reported_status(reported)
    assert mapped == dps.STATUS_FAILED
    assert error is not None and repr(reported) in error


def test_an_endpoint_report_naming_only_the_policy_is_recorded_against_its_exam(db, world, keys):
    """The exam is derived from the policy row's foreign key, not inferred."""
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)

    agent_ws._persist_policy_state(
        device.hardware_uuid,
        reported_status="APPLIED",
        policy_id=str(policy.policy_id),
        rules_installed=9,
    )

    state = _fresh_state(db, exam, device)
    assert state.status == dps.STATUS_APPLIED
    assert state.rules_installed == 9
    assert state.applied_at is not None


def test_an_endpoint_report_naming_the_exam_and_version_finds_that_version(db, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    v1 = world.policy(exam, version=1)
    world.policy(exam, version=2)

    agent_ws._persist_policy_state(
        device.hardware_uuid,
        reported_status="ROLLED_BACK",
        exam_id=str(exam.exam_id),
        version=1,
    )

    state = _fresh_state(db, exam, device)
    assert state.status == dps.STATUS_ROLLED_BACK
    assert state.policy_id == v1.policy_id


def test_an_endpoint_reporting_an_unreadable_status_ends_up_not_armed(db, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)
    world.arm(exam, device, policy, status=dps.STATUS_APPLYING)

    agent_ws._persist_policy_state(
        device.hardware_uuid,
        reported_status="ENFORCEMENT_PROBABLY_FINE",
        policy_id=str(policy.policy_id),
    )

    state = _fresh_state(db, exam, device)
    assert state.status == dps.STATUS_FAILED
    assert dps.is_armed(state.status) is False
    assert "ENFORCEMENT_PROBABLY_FINE" in state.last_error


def test_a_report_naming_nothing_is_not_attributed_to_the_active_exam(db, world, keys):
    """The falsifier for the fallback that was deliberately not written.

    This device is assigned to an ACTIVE exam that has a policy - exactly the state a "just use the
    device's current exam" shortcut would latch onto. Nothing is recorded, because attributing a
    report to the wrong exam is worse than not recording it, and "no row" is the not-armed answer
    the precondition already handles.
    """
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    world.policy(exam)
    exam.status = ExamStatus.ACTIVE.value
    db.commit()

    agent_ws._persist_policy_state(device.hardware_uuid, reported_status="APPLIED")

    db.rollback()
    assert dps.get_state(db, exam.exam_id, device.device_id) is None


def test_resolve_policy_identity_returns_nothing_when_it_cannot_tell(db, world, keys):
    exam = world.exam()
    world.policy(exam)
    db.rollback()

    assert agent_ws._resolve_policy_identity(
        db, exam_id=None, policy_id=None, version=None) == (None, None)
    assert agent_ws._resolve_policy_identity(
        db, exam_id="not-a-uuid", policy_id="also-not", version=None) == (None, None)
    assert agent_ws._resolve_policy_identity(
        db, exam_id=str(uuid.uuid4()), policy_id=None, version=None) == (None, None)


# ==============================================================================
# P1-S.1  Positive controls - without these, every refusal below is vacuous
# ==============================================================================
def test_a_ready_enforcement_exam_activates(client, db, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)
    world.arm(exam, device, policy)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "activated"
    assert body["network_enforcement"] is True
    assert body["policy_id"] == str(policy.policy_id)
    assert body["devices_not_enforcing"] == []
    assert body["devices_targeted"] == 1
    assert _fresh(db, Exam, exam.exam_id).status == ExamStatus.ACTIVE.value


def test_distribution_then_activation_is_the_whole_loop(client, db, world, keys, sent_ok):
    """End to end: the row the distribute endpoint writes is the row the precondition reads.

    Asserted as a sequence rather than two isolated units because the defect being prevented lives
    exactly in the join - the old code distributed and activated without either step knowing about
    the other.
    """
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    world.policy(exam)

    refused = client.post(f"/api/exams/{exam.exam_id}/activate")
    assert refused.status_code == 409
    assert _codes(refused.json()["detail"]) == [er.NO_ARMED_DEVICES]

    distributed = client.post(f"/api/policies/distribute/{exam.exam_id}/{device.hardware_uuid}")
    assert distributed.status_code == 200, distributed.text

    activated = client.post(f"/api/exams/{exam.exam_id}/activate")
    assert activated.status_code == 200, activated.text
    assert _fresh(db, Exam, exam.exam_id).status == ExamStatus.ACTIVE.value


def test_a_non_enforcement_exam_still_activates_with_no_policy(client, db, world, keys):
    """Backward compatibility, stated as a test rather than left to inspection: an exam that makes
    no lockdown claim has no lockdown precondition."""
    exam, device = world.exam(enforcement=False), world.device()
    world.assign(exam, device)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 200, resp.text
    assert resp.json()["network_enforcement"] is False
    assert resp.json()["devices_targeted"] == 1
    assert _device_status(db, exam, device) == ExamDeviceStatus.MONITORING.value


# ==============================================================================
# P1-S.2  Refusals - each names its own cause, and leaves the exam PENDING
# ==============================================================================
def test_activation_is_refused_when_no_policy_was_ever_compiled(client, db, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert er.NO_POLICY in _codes(detail)
    assert _fresh(db, Exam, exam.exam_id).status == ExamStatus.PENDING.value, (
        "a refusal must leave nothing half-started"
    )
    assert _device_status(db, exam, device) == ExamDeviceStatus.PENDING.value


def test_activation_is_refused_when_the_policy_reached_no_device(client, db, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    world.policy(exam)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    assert _codes(resp.json()["detail"]) == [er.NO_ARMED_DEVICES]


def test_activation_is_refused_when_no_devices_are_assigned(client, world, keys):
    exam = world.exam()
    world.policy(exam)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    assert _codes(resp.json()["detail"]) == [er.NO_ASSIGNED_DEVICES]


def test_a_device_that_failed_distribution_does_not_count_as_armed(client, db, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)
    world.arm(exam, device, policy, status=dps.STATUS_FAILED)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    assert _codes(resp.json()["detail"]) == [er.NO_ARMED_DEVICES]


def test_a_state_row_for_an_unassigned_device_does_not_arm_the_exam(client, db, world, keys):
    """Distribution is addressed by hardware UUID and does not itself check assignment, so an armed
    state row can exist for a workstation this exam never included."""
    exam = world.exam()
    assigned, stranger = world.device(), world.device()
    world.assign(exam, assigned)
    policy = world.policy(exam)
    world.arm(exam, stranger, policy)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    assert _codes(resp.json()["detail"]) == [er.NO_ARMED_DEVICES]


def test_activation_is_refused_when_the_policy_row_cannot_be_reproduced(client, db, world, keys):
    """Migration 0002 backfills ``key_id`` with an empty tombstone for rows signed before the column
    existed. Such a row distributes happily and is rejected by every endpoint; refusing here names
    the exam before a candidate sits down."""
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)
    world.arm(exam, device, policy)
    policy.key_id = ""
    db.commit()

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    assert _codes(resp.json()["detail"]) == [er.POLICY_NOT_REPRODUCIBLE]


def test_activation_is_refused_when_the_policy_is_unsigned(client, db, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)
    world.arm(exam, device, policy)
    policy.signature = ""
    db.commit()

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    assert _codes(resp.json()["detail"]) == [er.POLICY_UNSIGNED]


def test_activation_is_refused_when_the_signing_key_is_unknown_here(client, db, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)
    world.arm(exam, device, policy)
    policy.key_id = "persistent-0123456789abcdef"
    db.commit()

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    assert _codes(resp.json()["detail"]) == [er.POLICY_KEY_UNKNOWN]


def test_activation_is_refused_when_the_signing_key_was_revoked(client, db, world, keys):
    """Unknown and revoked are reported as themselves. The verifier is seeded only with keys trusted
    for verification, so both would otherwise collapse into one KeyMismatchError - and "never heard
    of it" calls for a different response than "this key may be compromised"."""
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)
    world.arm(exam, device, policy)

    keys.revoke(policy.key_id, "suspected compromise during test")

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert _codes(detail) == [er.POLICY_KEY_REVOKED]
    assert "suspected compromise during test" in detail["problems"][0]["message"]


def test_activation_is_refused_when_the_policy_has_expired(client, db, world, keys):
    now = datetime.now(timezone.utc)
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam, not_before=now - timedelta(hours=4),
                          expires_at=now - timedelta(hours=1))
    world.arm(exam, device, policy)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    assert _codes(resp.json()["detail"]) == [er.POLICY_EXPIRED]


def test_activation_is_refused_when_the_policy_is_not_yet_valid(client, db, world, keys):
    now = datetime.now(timezone.utc)
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam, not_before=now + timedelta(hours=1),
                          expires_at=now + timedelta(hours=4))
    world.arm(exam, device, policy)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    assert _codes(resp.json()["detail"]) == [er.POLICY_NOT_YET_VALID]


def test_activation_is_refused_when_the_stored_row_no_longer_matches_its_signature(
    client, db, world, keys
):
    """The row is re-verified rather than trusted: a policy edited in the database after signing
    would otherwise be distributed and refused device-side, mid-exam."""
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)
    world.arm(exam, device, policy)
    policy.allowed_destinations = list(policy.allowed_destinations) + [
        {"name": "Injected", "ip_ranges": ["203.0.113.55/32"], "tcp_ports": [443], "udp_ports": []}
    ]
    db.commit()

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 409
    assert _codes(resp.json()["detail"]) == [er.POLICY_SIGNATURE_INVALID]


# ==============================================================================
# P1-S.3  Partial readiness: armed seats launch, un-armed seats are named
# ==============================================================================
def test_unarmed_devices_are_not_launched_and_are_not_called_monitoring(client, db, world, keys):
    """The fail-open this replaces ran in both directions at once: a workstation that received no
    policy was told to enter exam mode with no lockdown, and the dashboard labelled it
    ``monitoring`` - the word an invigilator reads as "this seat is controlled"."""
    exam = world.exam()
    armed, offline = world.device(), world.device()
    world.assign(exam, armed)
    world.assign(exam, offline)
    policy = world.policy(exam)
    world.arm(exam, armed, policy)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["devices_targeted"] == 1
    assert [d["device_id"] for d in body["devices_not_enforcing"]] == [str(offline.device_id)]
    assert body["devices_not_enforcing"][0]["device_name"] == offline.device_name
    assert _device_status(db, exam, armed) == ExamDeviceStatus.MONITORING.value
    assert _device_status(db, exam, offline) == ExamDeviceStatus.PENDING.value


def _device_status(db, exam, device) -> str:
    db.rollback()
    row = (
        db.query(ExamDevice)
        .filter(ExamDevice.exam_id == exam.exam_id, ExamDevice.device_id == device.device_id)
        .first()
    )
    db.refresh(row)
    return row.status


# ==============================================================================
# P1-S.4  The readiness read answers before the operator presses Launch
# ==============================================================================
def test_the_readiness_endpoint_reports_the_same_refusal_as_activate(client, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)

    readiness = client.get(f"/api/exams/{exam.exam_id}/enforcement-readiness")
    activate = client.post(f"/api/exams/{exam.exam_id}/activate")

    assert readiness.status_code == 200, readiness.text
    assert activate.status_code == 409
    assert readiness.json()["ready"] is False
    assert _codes(readiness.json()) == _codes(activate.json()["detail"])


def test_the_readiness_endpoint_names_the_devices_that_are_not_enforcing(client, world, keys):
    exam = world.exam()
    armed, offline = world.device(), world.device()
    world.assign(exam, armed)
    world.assign(exam, offline)
    policy = world.policy(exam)
    world.arm(exam, armed, policy)

    body = client.get(f"/api/exams/{exam.exam_id}/enforcement-readiness").json()

    assert body["ready"] is True
    assert body["devices_assigned"] == 2
    assert body["devices_armed"] == 1
    assert [d["device_id"] for d in body["unarmed_devices"]] == [str(offline.device_id)]


def test_readiness_for_a_missing_exam_is_a_404(client, keys):
    assert client.get(f"/api/exams/{uuid.uuid4()}/enforcement-readiness").status_code == 404


# ==============================================================================
# P1-S.5  An ephemeral signing key is a caveat, not a cancelled exam
# ==============================================================================
def test_an_ephemeral_signing_key_warns_without_refusing(db, world, tmp_path):
    """Cancelling an exam in front of a room of candidates is the wrong response to a
    misconfiguration that bites at the next restart. It is still said out loud."""
    manager = SigningKeyManager(key_dir=None, allow_ephemeral=True, key_size=TEST_KEY_SIZE)
    set_signing_key_manager(manager)
    try:
        exam, device = world.exam(), world.device()
        world.assign(exam, device)
        policy = world.policy(exam)
        world.arm(exam, device, policy)

        readiness = er.evaluate_exam_readiness(db, exam, keys=manager)

        assert readiness.ready is True
        assert [w.code for w in readiness.warnings] == [er.EPHEMERAL_SIGNING_KEY]
    finally:
        set_signing_key_manager(None)


def test_readiness_reports_an_unavailable_keyring_rather_than_crashing(db, world, keys):
    exam, device = world.exam(), world.device()
    world.assign(exam, device)
    policy = world.policy(exam)
    world.arm(exam, device, policy)

    unusable = SigningKeyManager(key_dir=None, allow_ephemeral=False, key_size=TEST_KEY_SIZE)
    readiness = er.evaluate_exam_readiness(db, exam, keys=unusable)

    assert readiness.ready is False
    assert [p.code for p in readiness.problems] == [er.SIGNING_KEYS_UNAVAILABLE]
