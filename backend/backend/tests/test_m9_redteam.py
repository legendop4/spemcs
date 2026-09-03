"""M9 Adversarial Security Validation — Backend Red-Team Test Suite.
Exercises Attack Classes A, B, C, E, and N against the SPEMCS management server.
DOES NOT MODIFY PRODUCTION CODE.
"""

import base64
import hashlib
import hmac
import copy
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.database import SessionLocal
from backend.app.main import app
from backend.models.user import User
from backend.services.auth_service import (
    create_access_token,
    create_device_token,
    verify_device_token,
)
from backend.services.policy_signer import (
    PolicySigner,
    PolicyVerifier,
)

client = TestClient(app)


@pytest.fixture
def redteam_users():
    """Setup admin, proctor, and student users for authorization testing."""
    db = SessionLocal()
    admin_id = uuid.uuid4()
    proctor_id = uuid.uuid4()
    student_id = uuid.uuid4()

    admin_user = User(
        user_id=admin_id,
        name="Redteam Admin",
        username=f"rt_admin_{admin_id.hex[:6]}",
        email=f"rt_admin_{admin_id.hex[:6]}@example.com",
        password="fakepassword",
        password_hash="fakehash",
        avatar_color="#4F46E5",
        role="admin",
        is_active=True,
    )
    proctor_user = User(
        user_id=proctor_id,
        name="Redteam Proctor",
        username=f"rt_proctor_{proctor_id.hex[:6]}",
        email=f"rt_proctor_{proctor_id.hex[:6]}@example.com",
        password="fakepassword",
        password_hash="fakehash",
        avatar_color="#4F46E5",
        role="proctor",
        is_active=True,
    )
    student_user = User(
        user_id=student_id,
        name="Redteam Student",
        username=f"rt_student_{student_id.hex[:6]}",
        email=f"rt_student_{student_id.hex[:6]}@example.com",
        password="fakepassword",
        password_hash="fakehash",
        avatar_color="#4F46E5",
        role="student",
        is_active=True,
    )
    db.add(admin_user)
    db.add(proctor_user)
    db.add(student_user)
    db.commit()

    admin_tok = create_access_token(
        data={"sub": str(admin_id), "username": admin_user.username, "role": "admin"}
    )
    proctor_tok = create_access_token(
        data={"sub": str(proctor_id), "username": proctor_user.username, "role": "proctor"}
    )
    student_tok = create_access_token(
        data={"sub": str(student_id), "username": student_user.username, "role": "student"}
    )

    yield {
        "admin": admin_tok,
        "proctor": proctor_tok,
        "student": student_tok,
        "admin_id": admin_id,
        "proctor_id": proctor_id,
    }

    db.query(User).filter(
        User.user_id.in_([admin_id, proctor_id, student_id])
    ).delete(synchronize_session=False)
    db.commit()
    db.close()


# ==============================================================================
# ATTACK CLASS A: REST Authentication & Authorization Matrix
# ==============================================================================

def test_class_a_malformed_jwt():
    """Verify that malformed, truncated, or garbage JWTs return 401."""
    malformed_tokens = [
        "not-a-token",
        "header.payload",
        "a.b.c.d",
        "Bearer",
        "",
    ]
    for bad_tok in malformed_tokens:
        res = client.get("/api/exams", headers={"Authorization": f"Bearer {bad_tok}"})
        assert res.status_code == 401, f"Failed on token '{bad_tok}': got {res.status_code}"


def test_class_a_forged_signature_jwt(redteam_users):
    """Verify that a JWT signed with an untrusted/wrong secret key is rejected with 401."""
    from jose import jwt
    untrusted_secret = "attacker-compromised-secret-key-12345"
    payload = {
        "sub": str(uuid.uuid4()),
        "username": "attacker",
        "role": "admin",
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    forged_token = jwt.encode(payload, untrusted_secret, algorithm="HS256")

    res = client.get("/api/exams", headers={"Authorization": f"Bearer {forged_token}"})
    assert res.status_code == 401


def test_class_a_expired_jwt():
    """Verify that an expired JWT is rejected with 401."""
    from jose import jwt
    payload = {
        "sub": str(uuid.uuid4()),
        "username": "expired_user",
        "role": "admin",
        "exp": datetime.utcnow() - timedelta(minutes=5),  # Expired
    }
    expired_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

    res = client.get("/api/exams", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401


def test_class_a_proctor_privilege_escalation(redteam_users):
    """Attempt admin-only operations using proctor credentials. All must return 403."""
    proctor_headers = {"Authorization": f"Bearer {redteam_users['proctor']}"}
    fake_id = str(uuid.uuid4())

    # 1. Create exam
    res = client.post("/api/exams", json={"exam_name": "Proctor Created"}, headers=proctor_headers)
    assert res.status_code == 403

    # 2. Update exam
    res = client.put(f"/api/exams/{fake_id}", json={"exam_name": "Hacked"}, headers=proctor_headers)
    assert res.status_code == 403

    # 3. Delete exam
    res = client.delete(f"/api/exams/{fake_id}", headers=proctor_headers)
    assert res.status_code == 403

    # 4. Compile policy
    res = client.post(f"/api/policies/compile/{fake_id}", json={"version": 1}, headers=proctor_headers)
    assert res.status_code == 403

    # 5. Distribute dynamic policy update
    res = client.post(f"/api/policies/update/{fake_id}/DEVICE-1", headers=proctor_headers)
    assert res.status_code == 403

    # 6. Create device
    res = client.post("/api/devices", json={"device_name": "Proctor Dev"}, headers=proctor_headers)
    assert res.status_code == 403


def test_class_a_unauthorized_role_rejected(redteam_users):
    """Verify that non-admin/non-proctor roles (e.g. 'student') cannot access exam/device APIs."""
    student_headers = {"Authorization": f"Bearer {redteam_users['student']}"}

    # Reading exams requires admin or proctor
    res = client.get("/api/exams", headers=student_headers)
    assert res.status_code == 403

    # Reading devices requires admin or proctor
    res = client.get("/api/devices", headers=student_headers)
    assert res.status_code == 403


# ==============================================================================
# ATTACK CLASS B: Device Token & Enrollment Attacks
# ==============================================================================

def test_class_b_bootstrap_enrollment_rejections():
    """Attempt device registration without or with invalid enrollment secret."""
    # 1. No secret
    res = client.post("/api/v1/devices/register", json={"deviceName": "AttackerPC"})
    assert res.status_code == 401

    # 2. Wrong secret
    res = client.post(
        "/api/v1/devices/register",
        json={"deviceName": "AttackerPC"},
        headers={"X-Enrollment-Key": "wrong-bootstrap-key-999"},
    )
    assert res.status_code == 401


def test_class_b_device_token_signature_tampering():
    """Modify signature byte of an authentic device token and verify rejection."""
    valid_token = create_device_token("HW-UUID-TEST-1")
    parts = valid_token.split(".")
    payload_b64, sig_b64 = parts[0], parts[1]

    # Tamper with signature
    tampered_sig = "A" + sig_b64[1:] if sig_b64[0] != "A" else "B" + sig_b64[1:]
    tampered_token = f"{payload_b64}.{tampered_sig}"

    res = verify_device_token(tampered_token, expected_hardware_uuid="HW-UUID-TEST-1")
    assert res is None, "Tampered device token signature was accepted!"


def test_class_b_cross_device_token_theft():
    """Verify that a valid token issued for Device A cannot authenticate Device B."""
    token_a = create_device_token("HARDWARE-UUID-VICTIM")

    # Present Token A claiming to be Attacker UUID
    res = verify_device_token(token_a, expected_hardware_uuid="HARDWARE-UUID-ATTACKER")
    assert res is None, "Token for Victim device was accepted for Attacker device!"


def test_class_b_expired_device_token():
    """Verify that an expired device token is rejected."""
    # Create token expired 10 seconds ago
    expired_token = create_device_token("HW-UUID-EXPIRED", ttl_seconds=-10)

    res = verify_device_token(expired_token, expected_hardware_uuid="HW-UUID-EXPIRED")
    assert res is None, "Expired device token was accepted!"


# ==============================================================================
# ATTACK CLASS C: WebSocket Red-Team Attacks
# ==============================================================================

def test_class_c_websocket_unauthenticated_registration():
    """Attempt WebSocket REGISTER without token or with forged token."""
    # 1. Missing token
    with client.websocket_connect("/api/v1/ws/agent") as ws:
        ws.send_json({"action": "REGISTER", "hardware_uuid": "ROGUE-PC"})
        resp = ws.receive_json()
        assert resp.get("type") == "ERROR"
        assert resp.get("error_code") == "AUTH_REQUIRED"

    # 2. Invalid token
    with client.websocket_connect("/api/v1/ws/agent") as ws:
        ws.send_json({
            "action": "REGISTER",
            "hardware_uuid": "ROGUE-PC",
            "device_token": "fake.invalid.token",
        })
        resp = ws.receive_json()
        assert resp.get("type") == "ERROR"
        assert resp.get("error_code") == "AUTH_FAILED"

    # 3. Valid token with mismatched hardware UUID
    victim_token = create_device_token("GENUINE-LAB-PC-1")
    with client.websocket_connect("/api/v1/ws/agent") as ws:
        ws.send_json({
            "action": "REGISTER",
            "hardware_uuid": "IMPOSTOR-PC",
            "device_token": victim_token,
        })
        resp = ws.receive_json()
        assert resp.get("type") == "ERROR"
        assert resp.get("error_code") == "AUTH_FAILED"


def test_class_c_websocket_genuine_registration_succeeds():
    """Verify that an authentic token bound to the matching hardware UUID succeeds."""
    hw_id = f"VALID-AGENT-{uuid.uuid4().hex[:6]}"
    token = create_device_token(hw_id)

    with client.websocket_connect("/api/v1/ws/agent") as ws:
        ws.send_json({
            "action": "REGISTER",
            "hardware_uuid": hw_id,
            "device_token": token,
        })
        resp = ws.receive_json()
        assert resp.get("type") == "REGISTERED"
        assert resp.get("hardware_uuid") == hw_id


# ==============================================================================
# ATTACK CLASS E: Policy Tampering & RSA-PSS Signature Verification
# ==============================================================================

def test_class_e_policy_signature_tamper_detection():
    """Tamper with destinations and management server; verify signature rejection."""
    from backend.services.policy_signer import (
        generate_development_keypair,
        create_canonical_payload,
        InvalidSignatureError,
    )

    priv_key, pub_key = generate_development_keypair(key_size=2048)
    signer = PolicySigner(private_key=priv_key, key_id="redteam-key-1")
    verifier = PolicyVerifier()
    verifier.add_trusted_key("redteam-key-1", pub_key)

    now = datetime.now(timezone.utc)
    exam_id = uuid.uuid4()
    policy_id = uuid.uuid4()
    destinations = [
        {"name": "AuthVendor", "domains": ["vendor.com"], "ip_ranges": ["1.2.3.4"], "tcp_ports": [443], "udp_ports": []}
    ]
    management = {"ip_addresses": ["192.168.1.100"], "port": 8000}

    payload = create_canonical_payload(
        exam_id=exam_id,
        policy_id=policy_id,
        version=1,
        vendor_profile_id=None,
        allowed_destinations=destinations,
        management_server=management,
        not_before=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=2),
        key_id="redteam-key-1",
        schema_version="1.0",
    )

    sig = signer.sign_payload(payload)

    # 1. Genuine message validates
    verified = verifier.verify_policy(payload, sig, current_time=now)
    assert verified["exam_id"] == str(exam_id)

    # 2. Tamper destination IP
    tampered_payload = copy.deepcopy(payload)
    tampered_payload["allowed_destinations"][0]["ip_ranges"] = ["9.9.9.9"]
    with pytest.raises(InvalidSignatureError):
        verifier.verify_policy(tampered_payload, sig, current_time=now)

    # 3. Tamper management server port
    tampered_payload2 = copy.deepcopy(payload)
    tampered_payload2["management_server"]["port"] = 9999
    with pytest.raises(InvalidSignatureError):
        verifier.verify_policy(tampered_payload2, sig, current_time=now)


# ==============================================================================
# ATTACK CLASS N: Input & Resource Abuse
# ==============================================================================

def test_class_n_invalid_uuid_route_parameters(redteam_users):
    """Test malformed UUID string inputs in URL path parameters."""
    headers = {"Authorization": f"Bearer {redteam_users['admin']}"}
    malformed_uuids = [
        "not-a-uuid",
        "../../etc/passwd",
        "' OR 1=1 --",
        "00000000-0000-0000-0000-00000000000G",
    ]

    for bad_id in malformed_uuids:
        res = client.get(f"/api/exams/{bad_id}", headers=headers)
        # Should return 422 (validation error) or 404 (not found), never 500
        assert res.status_code in [404, 422], f"Path with '{bad_id}' returned unexpected code {res.status_code}"
