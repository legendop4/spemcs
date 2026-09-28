"""Regression tests for SPEMCS NetworkPolicy creation and compilation idempotency.

Validates the 5 required invariants:
1. Create policy once -> succeeds
2. Attach/use that policy to an exam -> succeeds without duplicate INSERT
3. Repeating the same exam/policy operation is idempotent
4. Two different exams using the same vendor/policy template do not collide
5. Double-click/retry from frontend does not create duplicate network_policies rows
"""

from __future__ import annotations

import concurrent.futures
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app.database import SessionLocal
from backend.app.main import app
from backend.models.exam import ApprovedBrowser, Exam, ExamStatus
from backend.models.policy import NetworkPolicy, VendorProfile
from backend.models.user import User, UserRole
from backend.services import policy_service
from backend.services.auth_service import require_auth
from backend.services.destination_resolver import StaticDnsResolver, TrustedDestinationResolver
from backend.services.signing_key_manager import SigningKeyManager, set_signing_key_manager

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
    user.username = "policy-idempotency-test"
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


def _make_vendor_profile(db) -> VendorProfile:
    vp = VendorProfile(
        vendor_name=f"Vendor-{uuid.uuid4().hex[:8]}",
        description="Test Vendor Profile",
        required_domains=[],
        approved_ip_ranges=["198.51.100.0/24"],
        required_tcp_ports=[80, 443],
        required_udp_ports=[],
    )
    db.add(vp)
    db.commit()
    db.refresh(vp)
    return vp


def _make_exam(db, vp_id=None, enforcement=True) -> Exam:
    exam = Exam(
        exam_name=f"Exam-{uuid.uuid4().hex[:8]}",
        approved_browser=ApprovedBrowser.CHROME.value,
        status=ExamStatus.PENDING.value,
        network_enforcement=enforcement,
        vendor_profile_id=vp_id,
    )
    db.add(exam)
    db.commit()
    db.refresh(exam)
    return exam


def test_1_create_policy_once_succeeds(db, keys):
    """1. Create policy once -> succeeds with single row and valid signature."""
    vp = _make_vendor_profile(db)
    exam = _make_exam(db, vp_id=vp.vendor_id)

    now = datetime.now(timezone.utc)
    resolver = TrustedDestinationResolver(StaticDnsResolver({"exam.lms.edu": ["198.51.100.22"]}))

    policy = policy_service.compile_and_persist_exam_policy(
        db=db,
        exam_id=exam.exam_id,
        version=1,
        management_server=MGMT,
        not_before=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=4),
        signer=keys.active_signer(),
        vendor_profile_id=vp.vendor_id,
        destination_resolver=resolver,
    )

    assert policy is not None
    assert policy.policy_id is not None
    assert policy.exam_id == exam.exam_id
    assert policy.version == 1
    assert policy.vendor_profile_id == vp.vendor_id
    assert policy.signature is not None

    rows = db.query(NetworkPolicy).filter(NetworkPolicy.exam_id == exam.exam_id).all()
    assert len(rows) == 1
    assert rows[0].policy_id == policy.policy_id


def test_2_attach_and_use_policy_to_exam_no_duplicate_insert(db, keys, client):
    """2. Attach/use that policy to an exam -> succeeds without duplicate INSERT."""
    vp = _make_vendor_profile(db)

    # Exam created via endpoint with network enforcement enabled (compiles version 1 automatically)
    create_resp = client.post("/api/exams", json={
        "exam_name": f"Exam-Attach-{uuid.uuid4().hex[:6]}",
        "approved_browser": "chrome",
        "network_enforcement": True,
        "vendor_profile_id": str(vp.vendor_id),
    })
    assert create_resp.status_code == 201
    exam_data = create_resp.json()
    exam_id = uuid.UUID(exam_data["exam_id"])

    # Verify policy was compiled
    initial_rows = db.query(NetworkPolicy).filter(NetworkPolicy.exam_id == exam_id).all()
    assert len(initial_rows) == 1
    original_policy_id = initial_rows[0].policy_id

    # Frontend ExamWizard Step 2 requests policy via GET /api/policies/exam/{exam_id}
    get_resp = client.get(f"/api/policies/exam/{exam_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["policy_id"] == str(original_policy_id)

    # Or frontend calls POST /api/policies/compile/{exam_id} with { version: 1 }
    compile_resp = client.post(f"/api/policies/compile/{exam_id}", json={
        "version": 1,
        "vendor_profile_id": str(vp.vendor_id),
    })
    assert compile_resp.status_code == 201
    assert compile_resp.json()["policy_id"] == str(original_policy_id)

    # Must NOT have created a second row
    final_rows = db.query(NetworkPolicy).filter(NetworkPolicy.exam_id == exam_id).all()
    assert len(final_rows) == 1
    assert final_rows[0].policy_id == original_policy_id


def test_3_repeating_same_policy_operation_is_idempotent(db, keys, client):
    """3. Repeating the same exam/policy operation is idempotent."""
    vp = _make_vendor_profile(db)
    exam = _make_exam(db, vp_id=vp.vendor_id)

    now = datetime.now(timezone.utc)
    resolver = TrustedDestinationResolver(StaticDnsResolver({"exam.lms.edu": ["198.51.100.22"]}))

    # Call service 3 times sequentially
    policy1 = policy_service.compile_and_persist_exam_policy(
        db=db,
        exam_id=exam.exam_id,
        version=1,
        management_server=MGMT,
        not_before=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=4),
        signer=keys.active_signer(),
        vendor_profile_id=vp.vendor_id,
        destination_resolver=resolver,
    )
    policy2 = policy_service.compile_and_persist_exam_policy(
        db=db,
        exam_id=exam.exam_id,
        version=1,
        management_server=MGMT,
        not_before=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=4),
        signer=keys.active_signer(),
        vendor_profile_id=vp.vendor_id,
        destination_resolver=resolver,
    )
    policy3 = policy_service.compile_and_persist_exam_policy(
        db=db,
        exam_id=exam.exam_id,
        version=1,
        management_server=MGMT,
        not_before=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=4),
        signer=keys.active_signer(),
        vendor_profile_id=vp.vendor_id,
        destination_resolver=resolver,
    )

    assert policy1.policy_id == policy2.policy_id == policy3.policy_id
    assert policy1.version == policy2.version == policy3.version == 1

    rows = db.query(NetworkPolicy).filter(NetworkPolicy.exam_id == exam.exam_id).all()
    assert len(rows) == 1

    # HTTP endpoint call is also idempotent
    http_resp1 = client.post(f"/api/policies/compile/{exam.exam_id}", json={"version": 1})
    http_resp2 = client.post(f"/api/policies/compile/{exam.exam_id}", json={"version": 1})
    assert http_resp1.status_code == 201
    assert http_resp2.status_code == 201
    assert http_resp1.json()["policy_id"] == str(policy1.policy_id)
    assert http_resp2.json()["policy_id"] == str(policy1.policy_id)


def test_4_different_exams_using_same_vendor_template_do_not_collide(db, keys):
    """4. Two different exams using the same vendor/policy template do not collide."""
    vp = _make_vendor_profile(db)
    exam_a = _make_exam(db, vp_id=vp.vendor_id)
    exam_b = _make_exam(db, vp_id=vp.vendor_id)

    now = datetime.now(timezone.utc)
    resolver = TrustedDestinationResolver(StaticDnsResolver({"exam.lms.edu": ["198.51.100.22"]}))

    policy_a = policy_service.compile_and_persist_exam_policy(
        db=db,
        exam_id=exam_a.exam_id,
        version=1,
        management_server=MGMT,
        not_before=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=4),
        signer=keys.active_signer(),
        vendor_profile_id=vp.vendor_id,
        destination_resolver=resolver,
    )

    policy_b = policy_service.compile_and_persist_exam_policy(
        db=db,
        exam_id=exam_b.exam_id,
        version=1,
        management_server=MGMT,
        not_before=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=4),
        signer=keys.active_signer(),
        vendor_profile_id=vp.vendor_id,
        destination_resolver=resolver,
    )

    # Different exams must have distinct policies
    assert policy_a.policy_id != policy_b.policy_id
    assert policy_a.exam_id == exam_a.exam_id
    assert policy_b.exam_id == exam_b.exam_id
    assert policy_a.version == 1
    assert policy_b.version == 1
    assert policy_a.vendor_profile_id == vp.vendor_id
    assert policy_b.vendor_profile_id == vp.vendor_id

    # Verify both rows exist independently in the database
    all_policies = db.query(NetworkPolicy).filter(
        NetworkPolicy.exam_id.in_([exam_a.exam_id, exam_b.exam_id])
    ).all()
    assert len(all_policies) == 2


def test_5_double_click_concurrent_retry_does_not_create_duplicates(db, keys, client):
    """5. Double-click/retry from frontend does not create duplicate network_policies rows."""
    vp = _make_vendor_profile(db)
    exam = _make_exam(db, vp_id=vp.vendor_id)

    now = datetime.now(timezone.utc)
    resolver = TrustedDestinationResolver(StaticDnsResolver({"exam.lms.edu": ["198.51.100.22"]}))
    signer = keys.active_signer()

    def concurrent_compile():
        local_db = SessionLocal()
        try:
            return policy_service.compile_and_persist_exam_policy(
                db=local_db,
                exam_id=exam.exam_id,
                version=1,
                management_server=MGMT,
                not_before=now - timedelta(minutes=5),
                expires_at=now + timedelta(hours=4),
                signer=signer,
                vendor_profile_id=vp.vendor_id,
                destination_resolver=resolver,
            ).policy_id
        finally:
            local_db.close()

    # Launch 4 concurrent compilation requests simulating rapid clicks
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(concurrent_compile) for _ in range(4)]
        policy_ids = [f.result() for f in futures]

    # All returned policy IDs must be identical
    assert len(set(policy_ids)) == 1

    # Exactly 1 row must exist in the database
    rows = db.query(NetworkPolicy).filter(NetworkPolicy.exam_id == exam.exam_id).all()
    assert len(rows) == 1
    assert str(rows[0].policy_id) == str(policy_ids[0])
