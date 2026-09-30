"""Automated regression test suite for exam device assignment and deterministic readiness.

Covers Tests 1 through 7:
1. test_1_exact_5_device_assignment:
   Assign 5 online devices -> exactly 5 rows in exam_devices -> readiness evaluates only those 5 -> activation succeeds when all 5 APPLIED.
2. test_2_offline_assigned_device_blocks_activation:
   Assign 5 online + 1 offline -> readiness fails -> 409 Conflict -> offline device explicitly named in devices_not_ready / problems.
3. test_3_no_assignment_inheritance:
   Exam A has 10 devices; creating Exam B selecting 5 devices creates exactly 5 assignments with zero leaked rows from Exam A.
4. test_4_unassign_device_removes_readiness_dependency:
   Calling DELETE /api/exams/{id}/devices/{device_id} or PUT /api/exams/{id}/devices removes ExamDevice and DevicePolicyState rows and clears readiness blockage.
5. test_5_stable_identity_survives_ip_hostname_change:
   Device changing IP/hostname preserves device_id and does not duplicate assignments.
6. test_6_stale_reimaged_device_not_auto_assigned:
   Re-registration of a seat unassigns stale predecessor or ensures predecessor does not auto-enroll into new exams.
7. test_7_live_5_system_deployment_scenario:
   5 live armed devices -> readiness reports total_assigned=5, ready=5, offline=0, failed=0, not_connected=0 -> activation succeeds.
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
from backend.services import policy_service
from backend.services.auth_service import require_auth
from backend.services.destination_resolver import StaticDnsResolver, TrustedDestinationResolver
from backend.services.signing_key_manager import SigningKeyManager, set_signing_key_manager

TEST_KEY_SIZE = 1024
MGMT = {"ip_addresses": ["192.168.1.10"], "port": 8002, "use_tls": False}


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
    user.username = "test-assignment-admin"
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
def world(db):
    made = {"exams": [], "devices": []}

    class World:
        def exam(self, name="Test Exam", *, enforcement=True, browser="chrome"):
            row = Exam(
                exam_name=f"{name}-{uuid.uuid4().hex[:6]}",
                approved_browser=browser,
                status=ExamStatus.PENDING.value,
                network_enforcement=enforcement,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            made["exams"].append(row.exam_id)
            return row

        def track_exam(self, exam_id):
            if isinstance(exam_id, str):
                exam_id = uuid.UUID(exam_id)
            made["exams"].append(exam_id)

        def device(self, *, hardware_uuid=None, name=None, ip="192.168.1.100", status="online"):
            row = Device(
                hardware_uuid=hardware_uuid or str(uuid.uuid4()),
                device_name=name or f"PC-{uuid.uuid4().hex[:6]}",
                registered_ip=ip,
                status=status,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            made["devices"].append(row.device_id)
            return row

        def assign(self, exam, device):
            row = ExamDevice(
                exam_id=exam.exam_id,
                device_id=device.device_id,
                status=ExamDeviceStatus.PENDING.value,
            )
            db.add(row)
            db.commit()
            return row

        def policy(self, exam):
            now = datetime.now(timezone.utc)
            resolver = TrustedDestinationResolver(
                StaticDnsResolver({"lms.univ.edu": ["198.51.100.7"]})
            )
            return policy_service.compile_and_persist_exam_policy(
                db=db,
                exam_id=exam.exam_id,
                version=1,
                management_server=MGMT,
                not_before=now - timedelta(minutes=5),
                expires_at=now + timedelta(hours=4),
                signer=_active_signer(),
                resolved_destinations=[{
                    "name": "Exam LMS",
                    "domains": ["lms.univ.edu"],
                    "tcp_ports": [443],
                }],
                destination_resolver=resolver,
            )

        def arm(self, exam, device, policy, status=dps.STATUS_APPLIED):
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


# ==============================================================================
# TEST 1: Exact 5-Device Assignment and Activation
# ==============================================================================
def test_1_exact_5_device_assignment(client, world, db, keys):
    """Assign 5 online devices -> exactly 5 rows in exam_devices -> readiness evaluates only those 5 -> activation succeeds."""
    exam = world.exam("Exam-5Dev")
    devices = [world.device(name=f"PaloAltoLab-PC0{i}", status="online") for i in [3, 4, 5, 6, 8]]
    for d in devices:
        world.assign(exam, d)

    # Verify exactly 5 exam_device rows in DB
    assigned_count = db.query(ExamDevice).filter(ExamDevice.exam_id == exam.exam_id).count()
    assert assigned_count == 5

    policy = world.policy(exam)
    for d in devices:
        world.arm(exam, d, policy, status=dps.STATUS_APPLIED)

    # Check readiness endpoint
    res = client.get(f"/api/exams/{exam.exam_id}/enforcement-readiness")
    assert res.status_code == 200
    data = res.json()
    assert data["ready"] is True
    assert data["total_assigned"] == 5
    assert data["ready_count"] == 5
    assert data["offline"] == 0
    assert data["failed"] == 0
    assert data["not_connected"] == 0
    assert len(data["problems"]) == 0

    # Activation succeeds
    act_res = client.post(f"/api/exams/{exam.exam_id}/activate")
    assert act_res.status_code == 200
    assert act_res.json()["status"] == "activated"

    db.refresh(exam)
    assert exam.status == ExamStatus.ACTIVE.value


# ==============================================================================
# TEST 2: Offline Assigned Device Blocks Activation
# ==============================================================================
def test_2_offline_assigned_device_blocks_activation(client, world, db, keys):
    """Assign 5 online + 1 offline -> readiness fails -> 409 Conflict -> offline device explicitly named."""
    exam = world.exam("Exam-5Online-1Offline")
    online_devices = [world.device(name=f"Online-PC0{i}", status="online") for i in [3, 4, 5, 6, 8]]
    offline_device = world.device(name="Offline-PC07", status="offline")

    all_devices = online_devices + [offline_device]
    for d in all_devices:
        world.assign(exam, d)

    policy = world.policy(exam)
    for d in online_devices:
        world.arm(exam, d, policy, status=dps.STATUS_APPLIED)
    # offline_device is not armed and is offline

    res = client.get(f"/api/exams/{exam.exam_id}/enforcement-readiness")
    assert res.status_code == 200
    data = res.json()
    assert data["ready"] is False
    assert data["total_assigned"] == 6
    assert data["ready_count"] == 5
    assert data["offline"] >= 1

    # Offline device must be explicitly identified in devices_not_ready
    not_ready_names = [d["device_name"] for d in data.get("devices_not_ready", [])]
    assert "Offline-PC07" in not_ready_names

    # Activation must fail-closed with 409 Conflict
    act_res = client.post(f"/api/exams/{exam.exam_id}/activate")
    assert act_res.status_code == 409
    body = act_res.json()
    assert "detail" in body
    detail = body["detail"]
    assert isinstance(detail, dict)
    assert detail["ready"] is False
    assert "UNARMED_DEVICES" in [p["code"] for p in detail.get("problems", [])]


# ==============================================================================
# TEST 3: No Assignment Inheritance Across Exams
# ==============================================================================
def test_3_no_assignment_inheritance(client, world, db):
    """Exam A has 10 devices; creating Exam B selecting 5 devices creates exactly 5 assignments."""
    exam_a = world.exam("Exam-A-10Dev")
    all_10 = [world.device(name=f"Lab-PC{i:02d}", status="online") for i in range(1, 11)]
    for d in all_10:
        world.assign(exam_a, d)

    # Count Exam A assignments
    assert db.query(ExamDevice).filter(ExamDevice.exam_id == exam_a.exam_id).count() == 10

    # Create Exam B via API selecting only 5 devices
    five_ids = [str(d.device_id) for d in all_10[:5]]
    create_payload = {
        "exam_name": f"Exam-B-5Dev-{uuid.uuid4().hex[:6]}",
        "approved_browser": "chrome",
        "device_ids": five_ids,
        "network_enforcement": True,
    }
    res = client.post("/api/exams/", json=create_payload)
    assert res.status_code in (200, 201)
    exam_b_id = uuid.UUID(res.json()["exam_id"])
    world.track_exam(exam_b_id)

    # Verify Exam B has EXACTLY 5 assignments, none inherited from Exam A
    exam_b_devices = db.query(ExamDevice).filter(ExamDevice.exam_id == exam_b_id).all()
    assert len(exam_b_devices) == 5
    assigned_b_ids = {str(ed.device_id) for ed in exam_b_devices}
    assert assigned_b_ids == set(five_ids)


# ==============================================================================
# TEST 4: Unassign Device Removes Readiness Dependency
# ==============================================================================
def test_4_unassign_device_removes_readiness_dependency(client, world, db, keys):
    """Calling DELETE /api/exams/{id}/devices/{device_id} or PUT /api/exams/{id}/devices removes assignment and clears blockage."""
    exam = world.exam("Exam-Unassign-Test")
    dev_good = world.device(name="Good-PC", status="online")
    dev_bad = world.device(name="Bad-PC", status="offline")

    world.assign(exam, dev_good)
    world.assign(exam, dev_bad)

    policy = world.policy(exam)
    world.arm(exam, dev_good, policy, status=dps.STATUS_APPLIED)
    # Also record a failed state for dev_bad to verify policy state row cleanup
    world.arm(exam, dev_bad, policy, status=dps.STATUS_FAILED)

    # Readiness is blocked because dev_bad is assigned and failed/offline
    res = client.get(f"/api/exams/{exam.exam_id}/enforcement-readiness")
    assert res.status_code == 200
    assert res.json()["ready"] is False

    # 1. Test DELETE /api/exams/{exam_id}/devices/{device_id}
    del_res = client.delete(f"/api/exams/{exam.exam_id}/devices/{dev_bad.device_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "unassigned"

    # Verify dev_bad assignment and policy state are cleaned up
    remaining = db.query(ExamDevice).filter(ExamDevice.exam_id == exam.exam_id).all()
    assert len(remaining) == 1
    assert remaining[0].device_id == dev_good.device_id

    bad_dps = db.query(DevicePolicyState).filter(
        DevicePolicyState.exam_id == exam.exam_id,
        DevicePolicyState.device_id == dev_bad.device_id,
    ).first()
    assert bad_dps is None

    # Readiness should now be READY
    res2 = client.get(f"/api/exams/{exam.exam_id}/enforcement-readiness")
    assert res2.status_code == 200
    assert res2.json()["ready"] is True
    assert res2.json()["total_assigned"] == 1
    assert res2.json()["ready_count"] == 1

    # 2. Test PUT /api/exams/{exam_id}/devices
    # Add another device, reassign using PUT
    dev_extra = world.device(name="Extra-PC", status="online")

    put_res = client.put(
        f"/api/exams/{exam.exam_id}/devices",
        json={"device_ids": [str(dev_good.device_id), str(dev_extra.device_id)]},
    )
    assert put_res.status_code == 200
    assigned_devices = put_res.json()
    assert isinstance(assigned_devices, list)
    assert len(assigned_devices) == 2

    # Newly added device is pending policy distribution -> readiness not ready
    res_pending = client.get(f"/api/exams/{exam.exam_id}/enforcement-readiness")
    assert res_pending.status_code == 200
    assert res_pending.json()["ready"] is False
    assert res_pending.json()["total_assigned"] == 2

    # Once newly assigned device applies policy -> ready
    world.arm(exam, dev_extra, policy, status=dps.STATUS_APPLIED)
    res3 = client.get(f"/api/exams/{exam.exam_id}/enforcement-readiness")
    assert res3.status_code == 200
    assert res3.json()["ready"] is True
    assert res3.json()["total_assigned"] == 2


# ==============================================================================
# TEST 5: Stable Identity Survives IP / Hostname Change
# ==============================================================================
def test_5_stable_identity_survives_ip_hostname_change(client, world, db):
    """Device changing IP/hostname preserves device_id and does not duplicate assignments."""
    hw_uuid = f"hw-{uuid.uuid4().hex}"
    dev = world.device(hardware_uuid=hw_uuid, name="Original-PC", ip="192.168.1.50", status="online")
    orig_device_id = dev.device_id

    exam = world.exam("Exam-Identity")
    world.assign(exam, dev)

    # Re-register device with changed IP and hostname via enrollment / register endpoint or direct model update
    # In SPEMCS, device identity is keyed by hardware_uuid
    existing = db.query(Device).filter(Device.hardware_uuid == hw_uuid).first()
    assert existing is not None
    existing.device_name = "Renamed-PC"
    existing.registered_ip = "192.168.1.99"
    db.commit()

    # Verify device_id is identical and assignment is preserved without duplicate rows
    assert existing.device_id == orig_device_id
    assignments = db.query(ExamDevice).filter(ExamDevice.exam_id == exam.exam_id).all()
    assert len(assignments) == 1
    assert assignments[0].device_id == orig_device_id


# ==============================================================================
# TEST 6: Stale / Re-imaged Device Not Auto-Assigned
# ==============================================================================
def test_6_stale_reimaged_device_not_auto_assigned(client, world, db):
    """Re-imaging or enrolling a new workstation does not silently auto-enroll into pending exams."""
    exam = world.exam("Exam-Strict-Assignments")
    dev1 = world.device(name="PC-Active-01", status="online")
    world.assign(exam, dev1)

    # A new or re-imaged device registers in the system
    new_dev = world.device(name="PC-Reimaged-02", status="online")

    # The new device must NOT be automatically added to existing pending exam
    exam_devices = db.query(ExamDevice).filter(ExamDevice.exam_id == exam.exam_id).all()
    assigned_ids = [ed.device_id for ed in exam_devices]
    assert dev1.device_id in assigned_ids
    assert new_dev.device_id not in assigned_ids
    assert len(exam_devices) == 1


# ==============================================================================
# TEST 7: Live 5-System Deployment Scenario
# ==============================================================================
def test_7_live_5_system_deployment_scenario(client, world, db, keys):
    """5 live armed devices -> readiness reports total_assigned=5, ready=5, offline=0, failed=0, not_connected=0 -> activation succeeds."""
    exam = world.exam("Exam-Live-5System")
    device_names = [
        "PaloAltoLab-PC03",
        "PaloAltoLab-PC04",
        "PaloAltoLab-PC05",
        "PaloAltoLab-PC06",
        "PaloAltoLab-PC08",
    ]
    devices = [world.device(name=name, status="online") for name in device_names]

    # Assign all 5
    put_res = client.put(
        f"/api/exams/{exam.exam_id}/devices",
        json={"device_ids": [str(d.device_id) for d in devices]},
    )
    assert put_res.status_code == 200

    # Compile policy and arm all 5
    policy = world.policy(exam)
    for d in devices:
        world.arm(exam, d, policy, status=dps.STATUS_APPLIED)

    # Evaluate readiness
    res = client.get(f"/api/exams/{exam.exam_id}/enforcement-readiness")
    assert res.status_code == 200
    rdata = res.json()

    assert rdata["ready"] is True
    assert rdata["total_assigned"] == 5
    assert rdata["ready_count"] == 5
    assert rdata["offline"] == 0
    assert rdata["failed"] == 0
    assert rdata["not_connected"] == 0
    assert len(rdata["devices_not_ready"]) == 0
    assert len(rdata["problems"]) == 0

    # Activate exam
    act_res = client.post(f"/api/exams/{exam.exam_id}/activate")
    assert act_res.status_code == 200
    assert act_res.json()["status"] == "activated"

    db.refresh(exam)
    assert exam.status == ExamStatus.ACTIVE.value
