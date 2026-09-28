"""Regression tests for timezone correctness in policy validity windows (Part 2).

Verifies that:
1. When policy is created at local IST time T (+05:30), the serialized not_before represents
   the SAME instant in UTC (e.g., 11:29:49 IST -> 05:59:49Z, NOT 11:29:49Z).
2. Works for arbitrary operator/server timezones including DST (e.g. US/Eastern EDT UTC-4, Europe/London BST UTC+1).
3. Policy compilation, signing, database persistence, and signature verification all preserve
   the canonical UTC instant without timezone drift.
4. Backend readiness evaluation does not fail due to local machine time vs UTC interpretation.
"""

import uuid
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import text

from backend.app.database import SessionLocal, engine
from backend.models.exam import Exam, ExamDevice, ExamStatus
from backend.models.policy import NetworkPolicy, VendorProfile
from backend.services import policy_service
from backend.services.policy_compiler import compile_exam_policy, validate_validity_window
from backend.services.policy_signer import create_canonical_payload, PolicySigner, generate_development_keypair
from backend.services.signing_key_manager import get_signing_key_manager
from backend.services import enforcement_readiness


# Explicit timezone definitions (independent of OS tzdata)
IST = timezone(timedelta(hours=5, minutes=30), name="IST")
EDT = timezone(timedelta(hours=-4), name="EDT")
BST = timezone(timedelta(hours=1), name="BST")


def test_ist_compilation_and_serialization():
    """Verify that an IST timestamp passed to compile_exam_policy produces canonical UTC with trailing 'Z'."""
    local_ist_time = datetime(2026, 9, 24, 11, 29, 49, tzinfo=IST)
    local_ist_exp = local_ist_time + timedelta(hours=8)

    nb_str, exp_str = validate_validity_window(local_ist_time, local_ist_exp)

    # 11:29:49 IST (+05:30) is 05:59:49 UTC
    assert nb_str == "2026-09-24T05:59:49Z"
    assert exp_str == "2026-09-24T13:59:49Z"
    assert nb_str != "2026-09-24T11:29:49Z"


def test_dst_timezones_compilation():
    """Verify that DST-sensitive timezones (EDT, BST) are normalized to the correct UTC instant."""
    # EDT (UTC-4)
    edt_time = datetime(2026, 7, 15, 14, 30, 0, tzinfo=EDT)  # Summer DST (UTC-4)
    nb_str, exp_str = validate_validity_window(edt_time, edt_time + timedelta(hours=2))
    assert nb_str == "2026-07-15T18:30:00Z"  # 14:30 EDT = 18:30 UTC

    # BST (UTC+1)
    bst_time = datetime(2026, 7, 15, 14, 30, 0, tzinfo=BST)  # Summer DST (UTC+1)
    nb_str, exp_str = validate_validity_window(bst_time, bst_time + timedelta(hours=2))
    assert nb_str == "2026-07-15T13:30:00Z"  # 14:30 BST = 13:30 UTC


def test_ist_policy_signing_and_verification():
    """Verify that signing a policy with IST inputs produces valid signatures that verify in UTC."""
    priv, _ = generate_development_keypair(key_size=2048)
    signer = PolicySigner(private_key=priv, key_id="test-tz-key-1")
    local_ist_time = datetime(2026, 9, 24, 11, 29, 49, tzinfo=IST)
    local_ist_exp = local_ist_time + timedelta(hours=4)

    test_dest = [{
        "name": "TestService",
        "domains": ["test.example.com"],
        "ip_ranges": ["192.168.1.0/24"],
        "tcp_ports": [443],
        "udp_ports": [],
    }]

    payload = compile_exam_policy(
        exam_id=uuid.uuid4(),
        version=1,
        vendor_profile=None,
        management_server={"ip_addresses": ["127.0.0.1"], "port": 8000},
        not_before=local_ist_time,
        expires_at=local_ist_exp,
        approved_browser="chrome",
        key_id=signer.key_id,
        allowed_destinations=test_dest,
    )

    assert payload["not_before"] == "2026-09-24T05:59:49Z"
    sig = signer.sign_payload(payload)

    # Verification against UTC current time (06:00:00 UTC) must succeed
    from backend.services.policy_signer import PolicyVerifier
    verifier = PolicyVerifier()
    verifier.add_trusted_key("test-tz-key-1", priv.public_key())
    current_utc = datetime(2026, 9, 24, 6, 0, 0, tzinfo=timezone.utc)
    verified = verifier.verify_policy(payload, sig, current_time=current_utc)
    assert verified["not_before"] == "2026-09-24T05:59:49Z"


def test_persistence_under_different_session_timezones():
    """Verify that database persistence and payload reconstruction does NOT shift timestamps,
    even when creating a policy with IST datetime.
    """
    db = SessionLocal()
    signer = get_signing_key_manager().active_signer()

    # Create test exam
    exam_id = uuid.uuid4()
    exam = Exam(
        exam_id=exam_id,
        exam_name=f"TZ-Test-Exam-{uuid.uuid4().hex[:6]}",
        status=ExamStatus.PENDING.value,
        network_enforcement=True,
        approved_browser="chrome",
    )
    db.add(exam)
    db.commit()

    try:
        # Create policy with IST time (11:29:49 IST -> 05:59:49 UTC)
        nb_ist = datetime(2026, 9, 24, 11, 29, 49, tzinfo=IST)
        exp_ist = nb_ist + timedelta(hours=6)

        # Static destination resolver for test
        from backend.services.destination_resolver import TrustedDestinationResolver, StaticDnsResolver
        resolver = TrustedDestinationResolver(
            StaticDnsResolver({"lms.univ.edu": ["198.51.100.7"]})
        )

        policy = policy_service.compile_and_persist_exam_policy(
            db=db,
            exam_id=exam_id,
            version=1,
            management_server={"ip_addresses": ["127.0.0.1"], "port": 8000},
            not_before=nb_ist,
            expires_at=exp_ist,
            signer=signer,
            vendor_profile_id=None,
            approved_browser="chrome",
            resolved_destinations=[{
                "name": "Exam LMS",
                "domains": ["lms.univ.edu"],
                "tcp_ports": [443],
                "udp_ports": [],
            }],
            destination_resolver=resolver,
        )

        # 1. Verify DB row values (stored as naive UTC)
        assert policy.not_before.hour == 5
        assert policy.not_before.minute == 59
        assert policy.not_before.second == 49

        # 2. Rebuild payload and verify canonical formatting
        rebuilt = policy_service.rebuild_signed_payload(policy)
        assert rebuilt["not_before"] == "2026-09-24T05:59:49Z"
        assert rebuilt["expires_at"] == "2026-09-24T11:59:49Z"

        # 3. Verify cryptographic signature matches rebuilt payload
        verifier = get_signing_key_manager().verifier()
        current_utc = datetime(2026, 9, 24, 6, 0, 0, tzinfo=timezone.utc)
        verifier.verify_policy(rebuilt, policy.signature, current_time=current_utc)

        # 4. Check backend readiness evaluation
        readiness = enforcement_readiness.evaluate_exam_readiness(
            db, exam, now=current_utc
        )
        # Problems should NOT include POLICY_NOT_YET_VALID or signature invalid
        problem_codes = [p.code for p in readiness.problems]
        assert enforcement_readiness.POLICY_NOT_YET_VALID not in problem_codes
        assert enforcement_readiness.POLICY_SIGNATURE_INVALID not in problem_codes

    finally:
        db.query(NetworkPolicy).filter(NetworkPolicy.exam_id == exam_id).delete()
        db.query(ExamDevice).filter(ExamDevice.exam_id == exam_id).delete()
        db.query(Exam).filter(Exam.exam_id == exam_id).delete()
        db.commit()
        db.close()
