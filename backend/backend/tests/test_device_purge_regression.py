"""Regression tests for POST /api/v1/devices/purge.

Verifies that the purge endpoint:
1. Validates the bootstrap enrollment key (via body or X-Enrollment-Key header).
2. Does NOT raise NameError (fixes undefined DEFAULT_ENROLLMENT_KEY reference).
3. Refuses requests with 503 when ENROLLMENT_BOOTSTRAP_KEY is unconfigured.
4. Refuses requests with 401 when the enrollment key is invalid or missing.
5. Successfully purges existing device registrations when authorized.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.database import SessionLocal
from backend.app.main import app
from backend.models.device import Device, DeviceStatus

client = TestClient(app)

BOOTSTRAP_KEY = "test-purge-bootstrap-key-12345"


@pytest.fixture(autouse=True)
def configure_bootstrap_key(monkeypatch):
    """Ensure ENROLLMENT_BOOTSTRAP_KEY is consistently set for test runs."""
    monkeypatch.setattr(settings, "ENROLLMENT_BOOTSTRAP_KEY", BOOTSTRAP_KEY)


def test_purge_device_no_key_returns_401():
    """Omitting the enrollment key rejects with HTTP 401 without raising NameError."""
    resp = client.post(
        "/api/v1/devices/purge",
        json={
            "deviceName": "LabPC-99",
            "hardwareUuid": "hw-uuid-99",
        },
    )
    assert resp.status_code == 401
    assert "enrollment" in resp.json()["detail"].lower()


def test_purge_device_wrong_key_returns_401():
    """Supplying an incorrect enrollment key rejects with HTTP 401."""
    resp = client.post(
        "/api/v1/devices/purge",
        json={
            "deviceName": "LabPC-99",
            "hardwareUuid": "hw-uuid-99",
            "enrollmentKey": "wrong-key-value",
        },
    )
    assert resp.status_code == 401
    assert "enrollment" in resp.json()["detail"].lower()


def test_purge_device_unconfigured_key_returns_503(monkeypatch):
    """When ENROLLMENT_BOOTSTRAP_KEY is unset, the endpoint fails closed with 503."""
    monkeypatch.setattr(settings, "ENROLLMENT_BOOTSTRAP_KEY", "")
    resp = client.post(
        "/api/v1/devices/purge",
        json={
            "deviceName": "LabPC-99",
            "hardwareUuid": "hw-uuid-99",
            "enrollmentKey": BOOTSTRAP_KEY,
        },
    )
    assert resp.status_code == 503
    assert "not configured" in resp.json()["detail"].lower()


def test_purge_device_valid_key_in_body_executes_cleanly():
    """Valid enrollment key in JSON body purges matching device and returns 200 without NameError."""
    db = SessionLocal()
    try:
        dev = Device(
            hardware_uuid="hw-uuid-purge-body-1",
            device_name="PurgeTestPC-1",
            registered_ip="10.0.0.51",
            status=DeviceStatus.ONLINE.value,
        )
        db.add(dev)
        db.commit()
    finally:
        db.close()

    resp = client.post(
        "/api/v1/devices/purge",
        json={
            "deviceName": "PurgeTestPC-1",
            "hardwareUuid": "hw-uuid-purge-body-1",
            "ipAddress": "10.0.0.51",
            "enrollmentKey": BOOTSTRAP_KEY,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "purged"
    assert data["count"] >= 1

    # Verify device record is eradicated
    db = SessionLocal()
    try:
        remaining = db.query(Device).filter(Device.hardware_uuid == "hw-uuid-purge-body-1").first()
        assert remaining is None
    finally:
        db.close()


def test_purge_device_valid_key_in_header_executes_cleanly():
    """Valid enrollment key in X-Enrollment-Key header purges matching device and returns 200."""
    db = SessionLocal()
    try:
        dev = Device(
            hardware_uuid="hw-uuid-purge-header-1",
            device_name="PurgeTestPC-2",
            registered_ip="10.0.0.52",
            status=DeviceStatus.ONLINE.value,
        )
        db.add(dev)
        db.commit()
    finally:
        db.close()

    resp = client.post(
        "/api/v1/devices/purge",
        headers={"X-Enrollment-Key": BOOTSTRAP_KEY},
        json={
            "deviceName": "PurgeTestPC-2",
            "hardwareUuid": "hw-uuid-purge-header-1",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "purged"
    assert data["count"] >= 1
