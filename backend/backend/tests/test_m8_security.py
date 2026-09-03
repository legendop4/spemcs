import hmac
import uuid
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.config import settings
from backend.services.auth_service import create_access_token, create_device_token, verify_device_token

from backend.app.database import SessionLocal
from backend.models.user import User

client = TestClient(app)

@pytest.fixture
def auth_users():
    db = SessionLocal()
    admin_id = uuid.uuid4()
    proctor_id = uuid.uuid4()

    admin_user = User(
        user_id=admin_id,
        name="Admin User",
        username=f"admin_{admin_id.hex[:6]}",
        email=f"admin_{admin_id.hex[:6]}@example.com",
        password="fakepassword",
        password_hash="fakehash",
        avatar_color="#4F46E5",
        role="admin",
        is_active=True,
    )
    proctor_user = User(
        user_id=proctor_id,
        name="Proctor User",
        username=f"proctor_{proctor_id.hex[:6]}",
        email=f"proctor_{proctor_id.hex[:6]}@example.com",
        password="fakepassword",
        password_hash="fakehash",
        avatar_color="#4F46E5",
        role="proctor",
        is_active=True,
    )
    db.add(admin_user)
    db.add(proctor_user)
    db.commit()

    admin_tok = create_access_token(data={"sub": str(admin_id), "username": admin_user.username, "role": "admin"})
    proctor_tok = create_access_token(data={"sub": str(proctor_id), "username": proctor_user.username, "role": "proctor"})

    yield {"admin": admin_tok, "proctor": proctor_tok}

    db.query(User).filter(User.user_id.in_([admin_id, proctor_id])).delete(synchronize_session=False)
    db.commit()
    db.close()


# ==============================================================================
# 1. Unauthenticated Access Tests (Gate 3)
# ==============================================================================

def test_unauthenticated_api_calls_return_401():
    fake_id = str(uuid.uuid4())

    # Exam endpoints
    res = client.get("/api/exams")
    assert res.status_code == 401

    res = client.post("/api/exams", json={"exam_name": "Test Exam"})
    assert res.status_code == 401

    res = client.post(f"/api/exams/{fake_id}/activate")
    assert res.status_code == 401

    res = client.post(f"/api/exams/{fake_id}/deactivate")
    assert res.status_code == 401

    # Policy endpoints
    res = client.post(f"/api/policies/compile/{fake_id}", json={"version": 1})
    assert res.status_code == 401

    res = client.post(f"/api/policies/distribute/{fake_id}/DEVICE-1")
    assert res.status_code == 401

    res = client.post(f"/api/policies/update/{fake_id}/DEVICE-1")
    assert res.status_code == 401

    # Device endpoints
    res = client.get("/api/devices")
    assert res.status_code == 401


# ==============================================================================
# 2. Role-Based Authorization Matrix Tests (Gate 4)
# ==============================================================================

def test_role_based_authorization_matrix(auth_users):
    fake_id = str(uuid.uuid4())
    proctor_headers = {"Authorization": f"Bearer {auth_users['proctor']}"}
    admin_headers = {"Authorization": f"Bearer {auth_users['admin']}"}

    # 1. Proctors cannot create, update, or delete exams (403 Forbidden)
    res = client.post("/api/exams", headers=proctor_headers, json={"exam_name": "Proctor Exam"})
    assert res.status_code == 403

    res = client.put(f"/api/exams/{fake_id}", headers=proctor_headers, json={"exam_name": "Updated"})
    assert res.status_code == 403

    res = client.delete(f"/api/exams/{fake_id}", headers=proctor_headers)
    assert res.status_code == 403

    # 2. Proctors cannot compile policies or push dynamic updates (403 Forbidden)
    res = client.post(f"/api/policies/compile/{fake_id}", headers=proctor_headers, json={"version": 1})
    assert res.status_code == 403

    res = client.post(f"/api/policies/update/{fake_id}/DEV1", headers=proctor_headers)
    assert res.status_code == 403

    # 3. Proctors cannot create devices (403 Forbidden)
    res = client.post("/api/devices", headers=proctor_headers, json={"device_name": "NewDev"})
    assert res.status_code == 403

    # 4. Proctors CAN view exams and devices (200 OK)
    res = client.get("/api/exams", headers=proctor_headers)
    assert res.status_code == 200

    res = client.get("/api/devices", headers=proctor_headers)
    assert res.status_code == 200

    # 5. Admins are authorized for exam creation (not 401 or 403)
    res = client.post("/api/exams", headers=admin_headers, json={"exam_name": "Admin Exam"})
    assert res.status_code in (200, 201)


# ==============================================================================
# 3. Device Bootstrap Enrollment & Token Binding (Gate 5 & 6)
# ==============================================================================

def test_device_enrollment_bootstrap_and_token():
    hw_uuid_a = f"TEST-DEV-A-{uuid.uuid4().hex[:6]}"
    hw_uuid_b = f"TEST-DEV-B-{uuid.uuid4().hex[:6]}"

    # Registration with wrong bootstrap key: 401
    res_bad = client.post(
        "/api/v1/devices/register",
        headers={"X-Enrollment-Key": "wrong-secret-key"},
        json={"deviceName": hw_uuid_a, "hardwareUuid": hw_uuid_a}
    )
    assert res_bad.status_code == 401

    # Registration with valid bootstrap key: 200 OK and returns device_token
    res_ok = client.post(
        "/api/v1/devices/register",
        headers={"X-Enrollment-Key": settings.ENROLLMENT_BOOTSTRAP_KEY},
        json={"deviceName": hw_uuid_a, "hardwareUuid": hw_uuid_a}
    )
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert "device_token" in data
    token_a = data["device_token"]

    # Verify device token valid for Device A
    payload_a = verify_device_token(token_a, expected_hardware_uuid=hw_uuid_a)
    assert payload_a is not None
    assert payload_a["hardware_uuid"] == hw_uuid_a

    # Gate 5: Device A's token CANNOT authenticate as Device B
    payload_b = verify_device_token(token_a, expected_hardware_uuid=hw_uuid_b)
    assert payload_b is None

    # Tampered token fails
    tampered = token_a[:-5] + "XXXXX"
    assert verify_device_token(tampered, expected_hardware_uuid=hw_uuid_a) is None

    # Expired token fails
    expired_token = create_device_token(hw_uuid_a, ttl_seconds=-10)
    assert verify_device_token(expired_token, expected_hardware_uuid=hw_uuid_a) is None


# ==============================================================================
# 4. Management Application Health Endpoint
# ==============================================================================

def test_management_application_health():
    res = client.get("/api/v1/management/health")
    assert res.status_code == 200
    data = res.json()
    assert data["service"] == "SPEMCS"
    assert data["status"] in ("ok", "degraded")
    assert data["version"] == "1.0"
    assert "server_time_utc" in data
