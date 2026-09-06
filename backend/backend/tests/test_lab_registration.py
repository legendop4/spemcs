"""Tests for Lab listing, Setup Wizard registration, and conflict validation."""

import uuid
import pytest
from fastapi.testclient import TestClient
from backend.app.dependencies import require_staff
from backend.app.main import app
from backend.app.database import SessionLocal
from backend.models.lab import Lab
from backend.models.device import Device
from backend.models.lab_device import LabDevice
from backend.models.user import User, UserRole

client = TestClient(app)


@pytest.fixture()
def as_staff():
    """Present an authenticated invigilator to the labs router.

    ``/api/labs`` is staff-only: anonymous access to the lab list was a way to enumerate every
    monitored room, and ``PATCH /{lab_id}/status`` was a one-request way to switch invigilation off
    for one. This test asserts the LISTING behaviour, so it supplies an identity rather than
    reopening the endpoint - overriding the gate here changes nothing about who the deployment
    admits. Refusals are covered in test_auth_security.py.
    """
    staff = User()
    staff.user_id = uuid.uuid4()
    staff.username = "lab-registration-test"
    staff.role = UserRole.PROCTOR.value
    staff.is_active = True
    app.dependency_overrides[require_staff] = lambda: staff
    yield staff
    app.dependency_overrides.pop(require_staff, None)


@pytest.fixture(scope="module")
def setup_test_data():
    db = SessionLocal()
    try:
        # Create a test lab
        test_lab_id = uuid.uuid4()
        test_lab = Lab(
            lab_id=test_lab_id,
            building_id="Block-Z",
            lab_name="Automated Test Lab 99",
            capacity=25,
            spemcs_enabled=True,
        )
        db.add(test_lab)
        db.commit()
        yield str(test_lab_id)
    finally:
        # Clean up
        db.query(LabDevice).filter(LabDevice.lab_id == test_lab_id).delete()
        db.query(Device).filter(Device.lab_name == "Automated Test Lab 99").delete()
        db.query(Lab).filter(Lab.lab_id == test_lab_id).delete()
        db.commit()
        db.close()


def test_get_labs_endpoint(as_staff, setup_test_data):
    """Verify GET /api/labs returns a valid list of labs to an authenticated invigilator."""
    # `setup_test_data` is requested for its side effect: it inserts the lab this assertion needs.
    # Without it the test asserted `len(data) >= 1` against whatever happened to be in the
    # database it was pointed at, which passed on the deployed instance and says nothing about the
    # endpoint - a listing route that returns rows somebody else created is not evidence that this
    # one works. Against the hermetic database (see conftest.py) the table starts empty, so the
    # test now supplies its own row.
    response = client.get("/api/labs")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert "lab_id" in data[0]
    assert "lab_name" in data[0]
    assert "building_id" in data[0]


from backend.app.config import settings


def test_device_registration_with_lab(setup_test_data):
    """Verify registering a device with lab_id and pc_number succeeds."""
    lab_id = setup_test_data
    payload = {
        "deviceName": "TestLab99-PC01",
        "ipAddress": "192.168.1.150",
        "hardwareUuid": "TEST-HW-UUID-001",
        "labId": lab_id,
        "pcNumber": "01",
        "hostname": "TEST-HOST-01",
    }
    response = client.post(
        "/api/v1/devices/register",
        headers={"X-Enrollment-Key": settings.ENROLLMENT_BOOTSTRAP_KEY},
        json=payload
    )
    assert response.status_code == 200
    data = response.json()
    assert data["deviceName"] == "TestLab99-PC01"
    assert data["hardwareUuid"] == "TEST-HW-UUID-001"
    assert data["pcNumber"] == "01"
    assert data["registered"] is True


def test_device_registration_duplicate_pc_conflict(setup_test_data):
    """Verify duplicate PC number registration in the same lab raises 409 Conflict."""
    lab_id = setup_test_data
    # Attempt to register a second device on the same PC number '01' with different hardware UUID
    payload = {
        "deviceName": "TestLab99-PC01-Duplicate",
        "ipAddress": "192.168.1.151",
        "hardwareUuid": "TEST-HW-UUID-002",
        "labId": lab_id,
        "pcNumber": "01",
        "hostname": "TEST-HOST-02",
    }
    response = client.post(
        "/api/v1/devices/register",
        headers={"X-Enrollment-Key": settings.ENROLLMENT_BOOTSTRAP_KEY},
        json=payload
    )
    assert response.status_code == 409
    data = response.json()
    assert "already registered" in data["detail"].lower()
