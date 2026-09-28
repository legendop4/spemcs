"""Comprehensive regression tests for Issue 1 (Policy Version Scoping),
Issue 2 (Clock Skew Tolerance & Temporal Validation), and Issue 4 (100% Fail-Closed Readiness Gate).
"""

from __future__ import annotations

import copy
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app.database import SessionLocal
from backend.app.main import app
from backend.models.device import Device
from backend.models.exam import ApprovedBrowser, Exam, ExamDevice, ExamDeviceStatus, ExamStatus
from backend.models.policy import DevicePolicyState, NetworkPolicy
from backend.models.user import User, UserRole
from backend.services import device_policy_state_service as dps
from backend.services import enforcement_readiness as er
from backend.services import policy_service
from backend.services.auth_service import require_auth
from backend.services.destination_resolver import StaticDnsResolver, TrustedDestinationResolver
from backend.services.policy_compiler import PolicyCompilationError, compile_exam_policy
from backend.services.policy_signer import (
    CURRENT_SCHEMA_VERSION,
    ExpiredPolicyError,
    InvalidSignatureError,
    NotYetValidPolicyError,
    PolicySigner,
    PolicyVerifier,
    create_canonical_payload,
)
from backend.services.signing_key_manager import SigningKeyManager, set_signing_key_manager
from backend.websocket import agent_ws

TEST_KEY_SIZE = 1024
MGMT = {"ip_addresses": ["127.0.0.1"], "port": 8000, "use_tls": False}


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
    manager = SigningKeyManager(key_dir=tmp_path / "signing_keys", key_size=TEST_KEY_SIZE)
    set_signing_key_manager(manager)
    try:
        yield manager
    finally:
        set_signing_key_manager(None)


@pytest.fixture()
def admin():
    user = User()
    user.user_id = uuid.uuid4()
    user.username = "readiness-gate-test"
    user.role = UserRole.ADMIN.value
    user.is_active = True
    app.dependency_overrides[require_auth] = lambda: user
    try:
        yield user
    finally:
        app.dependency_overrides.pop(require_auth, None)


@pytest.fixture()
def client(admin):
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def sent_ok(monkeypatch):
    """Pretend the endpoint's socket is connected and accepted the frame."""
    from backend.websocket.manager import realtime_manager
    async def _send(*_args, **_kwargs):
        return True
    monkeypatch.setattr(realtime_manager, "send_signed_policy_to_device", _send)
    monkeypatch.setattr(realtime_manager, "send_to_device", _send)


@pytest.fixture()
def world(db, keys):
    made = {"exams": [], "devices": []}

    class World:
        def exam(self, *, name=None, enforcement=True, browser="chrome"):
            row = Exam(
                exam_name=name or f"test-exam-{uuid.uuid4().hex[:8]}",
                approved_browser=browser,
                status=ExamStatus.PENDING.value,
                network_enforcement=enforcement,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            made["exams"].append(row.exam_id)
            return row

        def device(self, *, hardware_uuid=None, name=None, status="online"):
            row = Device(
                hardware_uuid=hardware_uuid or str(uuid.uuid4()),
                device_name=name or f"Lab-PC-{uuid.uuid4().hex[:6]}",
                status=status,
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
                StaticDnsResolver({"examly.io": ["198.51.100.10"]})
            )
            return policy_service.compile_and_persist_exam_policy(
                db=db,
                exam_id=exam.exam_id,
                version=version,
                management_server=MGMT,
                not_before=not_before,  # defaults to now - 5m
                expires_at=expires_at or (now + timedelta(hours=8)),
                signer=keys.active_signer(),
                resolved_destinations=[{
                    "name": "Exam Vendor",
                    "domains": ["examly.io"],
                    "tcp_ports": [80, 443],
                }],
                destination_resolver=resolver,
            )

        def set_device_state(self, exam, device, policy, status, error=None):
            return dps.record_state(
                db,
                exam_id=exam.exam_id,
                device_id=device.device_id,
                policy_id=policy.policy_id,
                status=status,
                last_error=error,
            )

    yield World()

    db.rollback()
    exam_ids, device_ids = made["exams"], made["devices"]
    if exam_ids:
        db.query(DevicePolicyState).filter(DevicePolicyState.exam_id.in_(exam_ids)).delete(synchronize_session=False)
        db.query(NetworkPolicy).filter(NetworkPolicy.exam_id.in_(exam_ids)).delete(synchronize_session=False)
        db.query(ExamDevice).filter(ExamDevice.exam_id.in_(exam_ids)).delete(synchronize_session=False)
        db.query(Exam).filter(Exam.exam_id.in_(exam_ids)).delete(synchronize_session=False)
    if device_ids:
        db.query(Device).filter(Device.device_id.in_(device_ids)).delete(synchronize_session=False)
    db.commit()


# ==============================================================================
# ISSUE 1: Policy Version Scoping & Replay Protection
# ==============================================================================

def test_a_exam_a_version_1_accepted(world):
    """Test A: Exam A policy v1 is created and valid."""
    exam_a = world.exam(name="Exam A")
    policy_a1 = world.policy(exam_a, version=1)
    assert policy_a1.version == 1
    assert policy_a1.exam_id == exam_a.exam_id
    assert policy_a1.signature is not None


def test_b_exam_a_version_1_replay_rejected(client, world, sent_ok):
    """Test B: Distributing Exam A v1 when already APPLIED returns ALREADY_APPLIED and skips redundant re-push."""
    exam_a = world.exam(name="Exam A")
    device = world.device(status="online")
    world.assign(exam_a, device)
    policy_a1 = world.policy(exam_a, version=1)

    # First distribution moves device to APPLYING
    resp1 = client.post(f"/api/policies/distribute/{exam_a.exam_id}/{device.hardware_uuid}")
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "SENT"

    # Endpoint acknowledges APPLIED
    agent_ws._persist_policy_state(
        device.hardware_uuid,
        reported_status="APPLIED",
        exam_id=str(exam_a.exam_id),
        version=1,
    )

    # Second distribution attempt detects it is ALREADY_APPLIED and refuses redundant push
    resp2 = client.post(f"/api/policies/distribute/{exam_a.exam_id}/{device.hardware_uuid}")
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "ALREADY_APPLIED"


def test_c_exam_a_version_0_rejected(world):
    """Test C: Compiling policy with version 0 is strictly rejected as PolicyInvalid."""
    exam_a = world.exam(name="Exam A")
    now = datetime.now(timezone.utc)
    with pytest.raises(PolicyCompilationError) as exc_info:
        compile_exam_policy(
            exam_id=exam_a.exam_id,
            version=0,
            vendor_profile=None,
            management_server=MGMT,
            approved_browser="chrome",
            key_id="test-key",
            allowed_destinations=[],
            not_before=now - timedelta(minutes=5),
            expires_at=now + timedelta(hours=2),
        )
    assert "positive integer" in str(exc_info.value).lower()


def test_d_exam_b_version_1_accepted_after_exam_a(world):
    """Test D: Exam B version 1 is accepted even after Exam A reached version 1.
    Policy version scoping is strictly per exam_id."""
    exam_a = world.exam(name="Exam A")
    policy_a1 = world.policy(exam_a, version=1)

    exam_b = world.exam(name="Exam B")
    policy_b1 = world.policy(exam_b, version=1)

    assert policy_a1.exam_id != policy_b1.exam_id
    assert policy_a1.version == 1
    assert policy_b1.version == 1
    assert policy_a1.policy_id != policy_b1.policy_id


def test_e_exam_b_version_1_replay_rejected(client, world, sent_ok):
    """Test E: Exam B v1 replay after APPLIED is detected and rejected."""
    exam_b = world.exam(name="Exam B")
    device = world.device(status="online")
    world.assign(exam_b, device)
    policy_b1 = world.policy(exam_b, version=1)

    # Device reaches APPLIED for Exam B v1
    world.set_device_state(exam_b, device, policy_b1, dps.STATUS_APPLIED)

    # Redundant distribute call returns ALREADY_APPLIED
    resp = client.post(f"/api/policies/distribute/{exam_b.exam_id}/{device.hardware_uuid}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ALREADY_APPLIED"


def test_f_exam_b_version_2_accepted(world):
    """Test F: Exam B version 2 succeeds as a legitimate version increment."""
    exam_b = world.exam(name="Exam B")
    policy_b1 = world.policy(exam_b, version=1)
    policy_b2 = world.policy(exam_b, version=2)

    assert policy_b2.version == 2
    assert policy_b2.policy_id != policy_b1.policy_id
    assert policy_b2.exam_id == exam_b.exam_id


def test_g_deactivate_exam_a_and_start_exam_b_without_manual_cleanup(client, db, world, sent_ok):
    """Test G: Deactivate Exam A and activate Exam B on the same workstations without manual endpoint cleanup."""
    device = world.device(status="online")

    # Exam A lifecycle
    exam_a = world.exam(name="Exam A")
    world.assign(exam_a, device)
    policy_a = world.policy(exam_a, version=1)
    world.set_device_state(exam_a, device, policy_a, dps.STATUS_APPLIED)

    # Activate Exam A
    act_a = client.post(f"/api/exams/{exam_a.exam_id}/activate")
    assert act_a.status_code == 200
    db.refresh(exam_a)
    assert exam_a.status == ExamStatus.ACTIVE.value

    # Deactivate Exam A
    end_a = client.post(f"/api/exams/{exam_a.exam_id}/deactivate")
    assert end_a.status_code == 200
    db.refresh(exam_a)
    assert exam_a.status == ExamStatus.COMPLETED.value

    # Exam B lifecycle on same device starts clean at version 1
    exam_b = world.exam(name="Exam B")
    world.assign(exam_b, device)
    policy_b = world.policy(exam_b, version=1)
    world.set_device_state(exam_b, device, policy_b, dps.STATUS_APPLIED)

    # Activate Exam B succeeds without error or manual cleanup
    act_b = client.post(f"/api/exams/{exam_b.exam_id}/activate")
    assert act_b.status_code == 200
    db.refresh(exam_b)
    assert exam_b.status == ExamStatus.ACTIVE.value


# ==============================================================================
# ISSUE 2: Clock Skew Tolerance & Temporal Validation
# ==============================================================================

def test_h_policy_compilation_defaults_not_before_to_5_minutes_ago(world):
    """Test that default compiled policy not_before incorporates 5-minute clock-skew tolerance."""
    exam = world.exam()
    before_compile = datetime.now(timezone.utc)
    policy = world.policy(exam)
    after_compile = datetime.now(timezone.utc)

    # not_before must be roughly 5 minutes prior to compile time
    expected_window_start = before_compile - timedelta(minutes=5, seconds=2)
    expected_window_end = after_compile - timedelta(minutes=4, seconds=58)
    nb = policy.not_before
    if nb.tzinfo is None:
        nb = nb.replace(tzinfo=timezone.utc)
    assert expected_window_start <= nb <= expected_window_end


def test_i_small_negative_clock_skew_within_5m_tolerance_accepted(keys):
    """Test A (Issue 2): Workstation clock 27-60 seconds behind server verifies successfully."""
    signer = keys.active_signer()
    verifier = PolicyVerifier()
    verifier.add_trusted_key(signer.key_id, signer.public_key)

    server_now = datetime.now(timezone.utc)
    # Backend sets not_before = server_now - 5 minutes
    not_before = server_now - timedelta(minutes=5)
    expires_at = server_now + timedelta(hours=4)

    payload = create_canonical_payload(
        exam_id=uuid.uuid4(),
        policy_id=uuid.uuid4(),
        version=1,
        vendor_profile_id=uuid.uuid4(),
        allowed_destinations=[],
        management_server=MGMT,
        not_before=not_before,
        expires_at=expires_at,
        approved_browser="chrome",
        key_id=signer.key_id,
        schema_version=CURRENT_SCHEMA_VERSION,
    )
    sig = signer.sign_payload(payload)

    # Workstation clock is 30 seconds behind server
    client_clock_30s_behind = server_now - timedelta(seconds=30)
    verified = verifier.verify_policy(payload, sig, current_time=client_clock_30s_behind)
    assert verified["policy_id"] == payload["policy_id"]


def test_j_clock_skew_beyond_5m_tolerance_rejected(keys):
    """Test B (Issue 2): Client clock or future not_before beyond 5m tolerance is rejected as NotYetValidPolicyError."""
    signer = keys.active_signer()
    verifier = PolicyVerifier()
    verifier.add_trusted_key(signer.key_id, signer.public_key)

    server_now = datetime.now(timezone.utc)
    not_before = server_now - timedelta(minutes=5)
    expires_at = server_now + timedelta(hours=4)

    payload = create_canonical_payload(
        exam_id=uuid.uuid4(),
        policy_id=uuid.uuid4(),
        version=1,
        vendor_profile_id=uuid.uuid4(),
        allowed_destinations=[],
        management_server=MGMT,
        not_before=not_before,
        expires_at=expires_at,
        approved_browser="chrome",
        key_id=signer.key_id,
        schema_version=CURRENT_SCHEMA_VERSION,
    )
    sig = signer.sign_payload(payload)

    # Workstation clock is 6 minutes behind server (exceeding 5-minute tolerance)
    client_clock_6m_behind = server_now - timedelta(minutes=6)
    with pytest.raises(NotYetValidPolicyError):
        verifier.verify_policy(payload, sig, current_time=client_clock_6m_behind)


def test_k_expired_policy_rejected(keys):
    """Test C (Issue 2): Policy whose expires_at is in the past is rejected as ExpiredPolicyError."""
    signer = keys.active_signer()
    verifier = PolicyVerifier()
    verifier.add_trusted_key(signer.key_id, signer.public_key)

    server_now = datetime.now(timezone.utc)
    not_before = server_now - timedelta(hours=5)
    expires_at = server_now - timedelta(minutes=10)

    payload = create_canonical_payload(
        exam_id=uuid.uuid4(),
        policy_id=uuid.uuid4(),
        version=1,
        vendor_profile_id=uuid.uuid4(),
        allowed_destinations=[],
        management_server=MGMT,
        not_before=not_before,
        expires_at=expires_at,
        approved_browser="chrome",
        key_id=signer.key_id,
        schema_version=CURRENT_SCHEMA_VERSION,
    )
    sig = signer.sign_payload(payload)

    with pytest.raises(ExpiredPolicyError):
        verifier.verify_policy(payload, sig, current_time=server_now)


def test_l_tampered_signature_rejected(keys):
    """Test D (Issue 2): Tampered policy payload or signature is rejected as InvalidSignatureError."""
    signer = keys.active_signer()
    verifier = PolicyVerifier()
    verifier.add_trusted_key(signer.key_id, signer.public_key)

    server_now = datetime.now(timezone.utc)
    payload = create_canonical_payload(
        exam_id=uuid.uuid4(),
        policy_id=uuid.uuid4(),
        version=1,
        vendor_profile_id=uuid.uuid4(),
        allowed_destinations=[],
        management_server=MGMT,
        not_before=server_now - timedelta(minutes=5),
        expires_at=server_now + timedelta(hours=4),
        approved_browser="chrome",
        key_id=signer.key_id,
        schema_version=CURRENT_SCHEMA_VERSION,
    )
    sig = signer.sign_payload(payload)

    # Tamper payload
    tampered_payload = copy.deepcopy(payload)
    tampered_payload["version"] = 2

    with pytest.raises(InvalidSignatureError):
        verifier.verify_policy(tampered_payload, sig, current_time=server_now)


# ==============================================================================
# ISSUE 4: 100% Fail-Closed Readiness Gate
# ==============================================================================

def test_m_readiness_all_26_applied_and_online_is_ready(db, world, keys):
    """Test A (Issue 4): 26/26 APPLIED and online -> readiness.ready == True."""
    exam = world.exam()
    policy = world.policy(exam)

    for i in range(26):
        dev = world.device(name=f"PC-{i:02d}", status="online")
        world.assign(exam, dev)
        world.set_device_state(exam, dev, policy, dps.STATUS_APPLIED)

    readiness = er.evaluate_exam_readiness(db, exam, keys=keys)
    assert readiness.ready is True
    assert readiness.total_assigned_devices == 26
    assert readiness.enforcing_count == 26
    assert len(readiness.problems) == 0


def test_n_readiness_25_applied_1_failed_is_not_ready_and_activation_409(client, db, world, keys):
    """Test B (Issue 4): 25/26 APPLIED + 1 FAILED -> ready == False and activation 409 Conflict."""
    exam = world.exam()
    policy = world.policy(exam)

    for i in range(25):
        dev = world.device(name=f"PC-{i:02d}", status="online")
        world.assign(exam, dev)
        world.set_device_state(exam, dev, policy, dps.STATUS_APPLIED)

    failed_dev = world.device(name="PC-25-FAILED", status="online")
    world.assign(exam, failed_dev)
    world.set_device_state(exam, failed_dev, policy, dps.STATUS_FAILED, error="Signature mismatch")

    readiness = er.evaluate_exam_readiness(db, exam, keys=keys)
    assert readiness.ready is False
    assert readiness.total_assigned_devices == 26
    assert readiness.enforcing_count == 25
    assert any(p.code == er.UNARMED_DEVICES for p in readiness.problems)

    # Backend activation independently rejects with 409 Conflict
    resp = client.post(f"/api/exams/{exam.exam_id}/activate")
    assert resp.status_code == 409
    assert any(p["code"] == er.UNARMED_DEVICES for p in resp.json()["detail"]["problems"])


def test_o_readiness_25_applied_1_applying_is_not_ready_and_activation_409(client, db, world, keys):
    """Test C (Issue 4): 25/26 APPLIED + 1 APPLYING -> ready == False and activation 409 Conflict."""
    exam = world.exam()
    policy = world.policy(exam)

    for i in range(25):
        dev = world.device(name=f"PC-{i:02d}", status="online")
        world.assign(exam, dev)
        world.set_device_state(exam, dev, policy, dps.STATUS_APPLIED)

    applying_dev = world.device(name="PC-25-APPLYING", status="online")
    world.assign(exam, applying_dev)
    world.set_device_state(exam, applying_dev, policy, dps.STATUS_APPLYING)

    readiness = er.evaluate_exam_readiness(db, exam, keys=keys)
    assert readiness.ready is False
    assert readiness.total_assigned_devices == 26
    assert readiness.enforcing_count == 25
    assert any(p.code == er.UNARMED_DEVICES for p in readiness.problems)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")
    assert resp.status_code == 409
    assert any(p["code"] == er.UNARMED_DEVICES for p in resp.json()["detail"]["problems"])


def test_p_readiness_25_applied_1_offline_is_not_ready_and_activation_409(client, db, world, keys):
    """Test D (Issue 4): 25/26 APPLIED + 1 OFFLINE -> ready == False and activation 409 Conflict."""
    exam = world.exam()
    policy = world.policy(exam)

    for i in range(25):
        dev = world.device(name=f"PC-{i:02d}", status="online")
        world.assign(exam, dev)
        world.set_device_state(exam, dev, policy, dps.STATUS_APPLIED)

    offline_dev = world.device(name="PC-25-OFFLINE", status="offline")
    world.assign(exam, offline_dev)
    # Even if previous state was applied, device is now offline
    world.set_device_state(exam, offline_dev, policy, dps.STATUS_APPLIED)

    readiness = er.evaluate_exam_readiness(db, exam, keys=keys)
    assert readiness.ready is False
    assert any(p.code == er.UNARMED_DEVICES and "offline" in p.message.lower() for p in readiness.problems)

    resp = client.post(f"/api/exams/{exam.exam_id}/activate")
    assert resp.status_code == 409
    assert any("offline" in p["message"].lower() for p in resp.json()["detail"]["problems"])


def test_q_readiness_all_26_applied_activates_with_200(client, db, world, keys):
    """Test E (Issue 4): 26/26 APPLIED and online -> activation returns 200 OK."""
    exam = world.exam()
    policy = world.policy(exam)

    for i in range(26):
        dev = world.device(name=f"PC-{i:02d}", status="online")
        world.assign(exam, dev)
        world.set_device_state(exam, dev, policy, dps.STATUS_APPLIED)

    readiness_resp = client.get(f"/api/exams/{exam.exam_id}/enforcement-readiness")
    assert readiness_resp.status_code == 200
    assert readiness_resp.json()["ready"] is True
    assert readiness_resp.json()["enforcing_count"] == 26

    act_resp = client.post(f"/api/exams/{exam.exam_id}/activate")
    assert act_resp.status_code == 200
    assert act_resp.json()["status"] == "activated"
    assert act_resp.json()["devices_targeted"] == 26
    db.refresh(exam)
    assert exam.status == ExamStatus.ACTIVE.value


def test_r_activation_endpoint_independently_verifies_fail_closed(client, db, world, keys):
    """Test F (Issue 4): Backend activation endpoint independently validates readiness and rejects unready exams."""
    exam = world.exam()
    # No policy compiled, no devices armed
    dev = world.device(status="online")
    world.assign(exam, dev)

    # Calling POST /api/exams/{id}/activate directly must reject with 409
    resp = client.post(f"/api/exams/{exam.exam_id}/activate")
    assert resp.status_code == 409
    assert resp.json()["detail"]["ready"] is False
    db.refresh(exam)
    assert exam.status == ExamStatus.PENDING.value
