"""Focused tests for M1 Backend Policy Domain Models:
- VendorProfile creation
- NetworkPolicy creation
- unique(exam_id, version) constraint
- DevicePolicyState creation
- unique(exam_id, device_id) constraint
- Exam.network_enforcement default=False
- nullable Exam.vendor_profile_id
- Existing exam compatibility and retrieval
"""

import uuid
from datetime import datetime, timedelta
import pytest
from sqlalchemy.exc import IntegrityError

from backend.app.database import SessionLocal
from backend.models.exam import Exam, ApprovedBrowser
from backend.models.device import Device
from backend.models.policy import VendorProfile, NetworkPolicy, DevicePolicyState


@pytest.fixture
def db_session():
    """Provides a transactional database session for each test, cleaning up created fixtures."""
    db = SessionLocal()
    created_items = []

    yield db, created_items

    # Cleanup in reverse order of foreign key dependencies
    try:
        for item in reversed(created_items):
            try:
                db.delete(item)
                db.commit()
            except Exception:
                db.rollback()
    finally:
        db.close()


def test_vendor_profile_creation(db_session):
    """Verify VendorProfile persists with JSONB fields and auto-generated UUID."""
    db, cleanup = db_session

    unique_vendor_name = f"Moodle-Test-{uuid.uuid4().hex[:8]}"
    profile = VendorProfile(
        vendor_name=unique_vendor_name,
        description="Moodle Examination Server Profile",
        required_domains=["moodle.university.edu", "cdn.university.edu"],
        approved_ip_ranges=["192.168.10.0/24", "10.0.5.0/24"],
        required_tcp_ports=[80, 443],
        required_udp_ports=[],
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    cleanup.append(profile)

    assert profile.vendor_id is not None
    assert profile.vendor_name == unique_vendor_name
    assert "moodle.university.edu" in profile.required_domains
    assert "192.168.10.0/24" in profile.approved_ip_ranges
    assert profile.required_tcp_ports == [80, 443]
    assert isinstance(profile.created_at, datetime)


def test_network_policy_creation(db_session):
    """Verify NetworkPolicy persists correctly with link to Exam and VendorProfile."""
    db, cleanup = db_session

    # 1. Create parent VendorProfile
    vp = VendorProfile(
        vendor_name=f"Canvas-Test-{uuid.uuid4().hex[:8]}",
        required_domains=["canvas.university.edu"],
    )
    db.add(vp)
    db.commit()
    cleanup.append(vp)

    # 2. Create parent Exam
    exam = Exam(
        exam_name=f"Policy-Test-Exam-{uuid.uuid4().hex[:6]}",
        approved_browser=ApprovedBrowser.CHROME.value,
        network_enforcement=True,
        vendor_profile_id=vp.vendor_id,
    )
    db.add(exam)
    db.commit()
    cleanup.append(exam)

    # 3. Create NetworkPolicy
    now = datetime.utcnow()
    policy = NetworkPolicy(
        exam_id=exam.exam_id,
        version=1,
        vendor_profile_id=vp.vendor_id,
        allowed_destinations=[
            {
                "name": "Exam LMS",
                "ip_ranges": ["198.51.100.10/32"],
                "tcp_ports": [443],
                "udp_ports": [],
            }
        ],
        management_server={"ip_addresses": ["192.168.1.100"], "port": 8000},
        not_before=now,
        expires_at=now + timedelta(hours=3),
        signature="SAMPLE-BASE64-RSA-SIGNATURE",
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    cleanup.append(policy)

    assert policy.policy_id is not None
    assert policy.exam_id == exam.exam_id
    assert policy.version == 1
    assert policy.vendor_profile_id == vp.vendor_id
    assert len(policy.allowed_destinations) == 1
    assert policy.allowed_destinations[0]["name"] == "Exam LMS"
    assert policy.signature == "SAMPLE-BASE64-RSA-SIGNATURE"


def test_network_policy_unique_exam_version_constraint(db_session):
    """Verify UNIQUE(exam_id, version) constraint rejects duplicate version for the same exam."""
    db, cleanup = db_session

    exam = Exam(
        exam_name=f"Duplicate-Policy-Exam-{uuid.uuid4().hex[:6]}",
        approved_browser=ApprovedBrowser.CHROME.value,
    )
    db.add(exam)
    db.commit()
    cleanup.append(exam)

    now = datetime.utcnow()
    policy1 = NetworkPolicy(
        exam_id=exam.exam_id,
        version=1,
        allowed_destinations=[],
        management_server={"ip_addresses": ["127.0.0.1"], "port": 8000},
        not_before=now,
        expires_at=now + timedelta(hours=2),
    )
    db.add(policy1)
    db.commit()
    cleanup.append(policy1)

    # Attempt to insert a second policy with the exact same (exam_id, version=1)
    policy2_duplicate = NetworkPolicy(
        exam_id=exam.exam_id,
        version=1,
        allowed_destinations=[],
        management_server={"ip_addresses": ["127.0.0.1"], "port": 8000},
        not_before=now,
        expires_at=now + timedelta(hours=2),
    )
    db.add(policy2_duplicate)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_device_policy_state_creation_and_unique_constraint(db_session):
    """Verify DevicePolicyState creation and UNIQUE(exam_id, device_id) enforcement."""
    db, cleanup = db_session

    # 1. Create Exam
    exam = Exam(
        exam_name=f"Device-Policy-Exam-{uuid.uuid4().hex[:6]}",
        approved_browser=ApprovedBrowser.CHROME.value,
        network_enforcement=True,
    )
    db.add(exam)
    db.commit()
    cleanup.append(exam)

    # 2. Create Device
    device = Device(
        hardware_uuid=f"TEST-HW-{uuid.uuid4().hex[:8]}",
        device_name="Lab-A:PC-01",
    )
    db.add(device)
    db.commit()
    cleanup.append(device)

    # 3. Create Policy
    now = datetime.utcnow()
    policy = NetworkPolicy(
        exam_id=exam.exam_id,
        version=1,
        allowed_destinations=[],
        management_server={"ip_addresses": ["10.0.0.1"], "port": 8000},
        not_before=now,
        expires_at=now + timedelta(hours=2),
    )
    db.add(policy)
    db.commit()
    cleanup.append(policy)

    # 4. Create DevicePolicyState
    dev_state = DevicePolicyState(
        exam_id=exam.exam_id,
        device_id=device.device_id,
        policy_id=policy.policy_id,
        status="APPLIED",
        rules_installed=5,
    )
    db.add(dev_state)
    db.commit()
    db.refresh(dev_state)
    cleanup.append(dev_state)

    assert dev_state.id is not None
    assert dev_state.status == "APPLIED"
    assert dev_state.rules_installed == 5

    # 5. Attempt duplicate DevicePolicyState for same (exam_id, device_id)
    duplicate_state = DevicePolicyState(
        exam_id=exam.exam_id,
        device_id=device.device_id,
        policy_id=policy.policy_id,
        status="PENDING",
    )
    db.add(duplicate_state)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_exam_network_enforcement_default_false(db_session):
    """Verify Exam.network_enforcement defaults to False when omitted."""
    db, cleanup = db_session

    exam = Exam(
        exam_name=f"Default-False-Exam-{uuid.uuid4().hex[:6]}",
        approved_browser=ApprovedBrowser.CHROME.value,
    )
    db.add(exam)
    db.commit()
    db.refresh(exam)
    cleanup.append(exam)

    assert exam.network_enforcement is False
    assert exam.vendor_profile_id is None


def test_existing_exam_compatibility_and_reading(db_session):
    """Verify pre-existing exams in the database can be read and enriched without errors."""
    from backend.routes.exams import _enrich_exam

    db, _ = db_session
    existing_exams = db.query(Exam).limit(5).all()

    for exam in existing_exams:
        assert hasattr(exam, "network_enforcement")
        assert exam.network_enforcement is False or exam.network_enforcement is True
        enriched = _enrich_exam(db, exam)
        assert "network_enforcement" in enriched
        assert "vendor_profile_id" in enriched
        assert "exam_id" in enriched
