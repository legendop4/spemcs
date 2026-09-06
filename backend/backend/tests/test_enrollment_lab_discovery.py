"""Enrolment-time lab discovery, and the credential boundary around it.

WHAT THIS FILE IS FOR
---------------------
A workstation that has not enrolled yet holds no operator JWT and no device token - a device token is
what enrolment *issues*. The setup wizard nevertheless needs a lab list before it can register,
because the lab is part of the registration request. That ordering is what produced the observed
failure: the wizard called the staff-gated ``GET /api/labs``, was answered 401, left its lab
dropdown empty, and therefore never enabled its Register button, so ``POST
/api/v1/devices/register`` was never reached and no device token was ever issued.

``GET /api/v1/enrollment/labs`` is the narrow door that closes that gap. The tests here are mostly
about what it must NOT become, because the ways this regresses are all wideningѕ:

* it must not accept an absent or wrong enrolment key;
* it must not accept a *device* token in place of one (that would make it reachable by an enrolled
  candidate machine and would blur two credential types the design keeps apart);
* it must not disclose more per lab than the wizard needs;
* it must not list labs that are not under SPEMCS;
* and ``/api/labs`` itself must stay exactly as staff-gated as it was.

The last one has its own test rather than being left to ``test_auth_security.py``: the realistic
regression is somebody "simplifying" the two endpoints into one, and that would be invisible here
without an assertion that the staff-only door is still shut.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.database import SessionLocal
from backend.app.main import app
from backend.models.lab import Lab, LabStatus
from backend.models.user import User, UserRole
from backend.services.auth_service import create_access_token, create_device_token

ENROLLMENT_LABS = "/api/v1/enrollment/labs"

client = TestClient(app)


def _key_header() -> dict:
    """The correct enrolment key header.

    Reads the configured value rather than a literal, so this file contains no secret and keeps
    working after rotation.
    """
    return {"X-Enrollment-Key": settings.ENROLLMENT_BOOTSTRAP_KEY}


@pytest.fixture()
def labs():
    """Three labs: two enrollable, one not.

    The disabled lab is the whole point of the fixture. A filter test needs a row the filter must
    exclude, or it asserts nothing - and "returns every lab" would pass just as happily.
    """
    db = SessionLocal()
    enabled_a = Lab(lab_id=uuid.uuid4(), building_id="Block-A", lab_name="Enrol Lab A",
                    capacity=30, spemcs_enabled=True, status=LabStatus.ACTIVE.value,
                    description="internal note A")
    enabled_b = Lab(lab_id=uuid.uuid4(), building_id="Block-B", lab_name="Enrol Lab B",
                    capacity=40, spemcs_enabled=True, status=LabStatus.ACTIVE.value)
    disabled = Lab(lab_id=uuid.uuid4(), building_id="Block-C", lab_name="Unmonitored Lab C",
                   capacity=20, spemcs_enabled=False, status=LabStatus.ACTIVE.value)
    ids = [enabled_a.lab_id, enabled_b.lab_id, disabled.lab_id]
    try:
        db.add_all([enabled_a, enabled_b, disabled])
        db.commit()
        yield {"enabled_a": enabled_a, "enabled_b": enabled_b, "disabled": disabled}
    finally:
        db.query(Lab).filter(Lab.lab_id.in_(ids)).delete(synchronize_session=False)
        db.commit()
        db.close()


def _operator(role: str, username: str) -> dict:
    """Insert a real operator row and return its Authorization header.

    A real row and a real JWT rather than a ``dependency_overrides`` stub, because the thing under
    test on ``POST /api/labs`` is the difference between two roles. Overriding ``require_admin``
    replaces exactly the gate that is supposed to refuse a proctor, so an override-based test cannot
    observe a 403 at all - it was the reason an earlier draft of this file asserted 403 and got 401.
    """
    db = SessionLocal()
    try:
        user = User(
            user_id=uuid.uuid4(),
            name=username,
            username=username,
            email=f"{username}@example.invalid",
            password="not-a-real-hash",
            password_hash="not-a-real-hash",
            role=role,
            avatar_color="#000000",
            is_active=True,
        )
        db.add(user)
        db.commit()
        return {"Authorization": f"Bearer {create_access_token({'sub': str(user.user_id)})}"}
    finally:
        db.close()


def _delete_operator(username: str) -> None:
    db = SessionLocal()
    try:
        db.query(User).filter(User.username == username).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


@pytest.fixture()
def as_admin():
    username = "enrollment-lab-admin"
    try:
        yield _operator(UserRole.ADMIN.value, username)
    finally:
        _delete_operator(username)


@pytest.fixture()
def as_proctor():
    username = "enrollment-lab-proctor"
    try:
        yield _operator(UserRole.PROCTOR.value, username)
    finally:
        _delete_operator(username)


# ── 1. The credential the endpoint requires ───────────────────────────────────


def test_enrollment_labs_refuses_a_caller_with_no_key(labs):
    response = client.get(ENROLLMENT_LABS)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing enrollment bootstrap key"


def test_enrollment_labs_refuses_a_wrong_key(labs):
    response = client.get(ENROLLMENT_LABS, headers={"X-Enrollment-Key": "not-the-configured-key"})
    assert response.status_code == 401


def test_enrollment_labs_refuses_an_empty_key(labs):
    """An empty header value must not read as "no check applies".

    ``hmac.compare_digest(b"", b"<key>")`` is False, so this is already correct - the test exists
    because the falsy-value shape is exactly what the pre-existing ``if
    settings.ENROLLMENT_BOOTSTRAP_KEY:`` bug got wrong on the server side, and the same reflex
    applied to the request side would reopen it.
    """
    response = client.get(ENROLLMENT_LABS, headers={"X-Enrollment-Key": ""})
    assert response.status_code == 401


def test_enrollment_labs_admits_the_configured_key(labs):
    """The positive control.

    Without this, every assertion above passes against an endpoint that refuses everyone - which is
    indistinguishable from the 401 this whole change exists to remove.
    """
    response = client.get(ENROLLMENT_LABS, headers=_key_header())
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_enrollment_labs_refuses_a_device_token(labs):
    """A device token must not open this endpoint.

    Not because an enrolled machine reading the lab list is catastrophic, but because accepting two
    credential types on one route is how the distinction between them decays. This route's job is to
    serve a machine that has *no* device identity yet; a caller presenting one is either enrolled
    already or forging, and both should use the doors meant for them.
    """
    token = create_device_token(hardware_uuid="Lab-PC01")
    for headers in ({"X-Device-Token": token}, {"Authorization": f"Bearer {token}"}):
        response = client.get(ENROLLMENT_LABS, headers=headers)
        assert response.status_code == 401, f"a device token opened {ENROLLMENT_LABS}"


def test_enrollment_labs_refuses_a_staff_jwt_without_the_key(labs, as_admin):
    """An operator JWT is also not this route's credential.

    A real administrator token is presented, so the refusal is attributable to the enrolment-key
    check rather than to an absent operator identity. The same token opens ``/api/labs``, which the
    positive control below asserts - otherwise this passes against a token that is simply invalid.
    """
    assert client.get("/api/labs", headers=as_admin).status_code == 200, (
        "the administrator token must be genuinely valid, or this test proves nothing"
    )
    response = client.get(ENROLLMENT_LABS, headers=as_admin)
    assert response.status_code == 401


def test_enrollment_refused_when_the_server_has_no_key_configured(labs, monkeypatch):
    """Unset key means closed, not open - and 503, not 401.

    503 rather than 401 because the caller did nothing wrong: the *server* is unconfigured, and
    answering 401 would send an operator to check the workstation's key when the fix is on the
    backend. This mirrors ``register_device``, whose earlier form wrapped the comparison in ``if
    settings.ENROLLMENT_BOOTSTRAP_KEY:`` - so clearing the variable disabled the check rather than
    the feature.
    """
    monkeypatch.setattr(settings, "ENROLLMENT_BOOTSTRAP_KEY", "")
    response = client.get(ENROLLMENT_LABS, headers={"X-Enrollment-Key": "anything"})
    assert response.status_code == 503
    assert response.json()["detail"] == "Device enrollment is not configured on this server"


def test_enrollment_refusal_never_echoes_the_key(labs):
    """No refusal body contains the configured key or the value that was sent."""
    sent = "a-distinctive-wrong-key-value"
    response = client.get(ENROLLMENT_LABS, headers={"X-Enrollment-Key": sent})
    body = response.text
    assert sent not in body
    assert settings.ENROLLMENT_BOOTSTRAP_KEY not in body


# ── 2. What the endpoint discloses ────────────────────────────────────────────


def test_enrollment_labs_lists_only_spemcs_enabled_labs(labs):
    names = {lab["lab_name"] for lab in client.get(ENROLLMENT_LABS, headers=_key_header()).json()}
    assert "Enrol Lab A" in names
    assert "Enrol Lab B" in names
    assert "Unmonitored Lab C" not in names, (
        "a lab that is not under SPEMCS is not enrollable and must not be disclosed here"
    )


def test_enrollment_labs_exposes_exactly_the_four_fields_the_wizard_needs(labs):
    """The response shape is part of the security boundary, so it is pinned exactly.

    An equality assertion rather than a set of ``in`` checks: the failure being guarded against is a
    later change swapping ``LabEnrollmentRead`` back to ``LabRead`` for convenience, which adds
    fields without removing any and would pass every ``in`` assertion.
    """
    payload = client.get(ENROLLMENT_LABS, headers=_key_header()).json()
    assert payload, "fixture labs should be present"
    for lab in payload:
        assert set(lab) == {"lab_id", "building_id", "lab_name", "capacity"}


def test_enrollment_labs_does_not_leak_lab_descriptions(labs):
    body = client.get(ENROLLMENT_LABS, headers=_key_header()).text
    assert "internal note A" not in body


def test_enrollment_labs_are_ordered_for_a_human_picking_from_a_dropdown(labs):
    payload = client.get(ENROLLMENT_LABS, headers=_key_header()).json()
    keys = [(lab["building_id"], lab["lab_name"]) for lab in payload]
    assert keys == sorted(keys)


# ── 3. The endpoint this one does NOT replace ─────────────────────────────────


def test_api_labs_is_still_staff_gated():
    """The counter-test. ``/api/labs`` must not have been widened by this change."""
    response = client.get("/api/labs")
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_the_enrollment_key_does_not_open_api_labs():
    """The enrolment key is scoped to enrolment. It is held by every workstation in the deployment,
    so accepting it on the staff lab list would put full ``LabRead`` behind a secret that must be
    assumed readable by anyone who can copy an agent binary."""
    response = client.get("/api/labs", headers=_key_header())
    assert response.status_code == 401


# ── 4. Admin lab creation (the other half of an empty database) ───────────────


def test_admin_can_create_a_lab(as_admin):
    created_id = None
    db = SessionLocal()
    try:
        response = client.post("/api/labs", headers=as_admin, json={
            "building_id": "Block-New",
            "lab_name": "Freshly Created Lab",
            "capacity": 24,
            "spemcs_enabled": True,
        })
        assert response.status_code == 201, response.text
        body = response.json()
        created_id = body["lab_id"]
        assert body["lab_name"] == "Freshly Created Lab"
        assert body["spemcs_enabled"] is True
        assert db.query(Lab).filter(Lab.lab_id == uuid.UUID(created_id)).first() is not None
    finally:
        if created_id:
            db.query(Lab).filter(Lab.lab_id == uuid.UUID(created_id)).delete()
            db.commit()
        db.close()


def test_lab_creation_refuses_an_anonymous_caller():
    response = client.post("/api/labs", json={
        "building_id": "Block-X", "lab_name": "Should Not Exist", "capacity": 10,
    })
    assert response.status_code == 401


def test_lab_creation_refuses_a_proctor(as_proctor):
    """Creating a room is estate configuration, and ``spemcs_enabled`` on the create body is the
    same switch ``PATCH /{lab_id}/status`` guards at admin level. Accepting it from a proctor would
    route around that gate.

    403, not 401: the proctor's token is valid and the identity is known, it is simply insufficient.
    The lab-list read below proves the token really is valid, so a 403 here cannot be a broken token
    in disguise.
    """
    assert client.get("/api/labs", headers=as_proctor).status_code == 200, (
        "a proctor must still be able to READ labs, or this test's 403 proves nothing"
    )

    response = client.post("/api/labs", headers=as_proctor, json={
        "building_id": "Block-Y", "lab_name": "Proctor Lab", "capacity": 10,
    })
    assert response.status_code == 403


def test_a_new_lab_is_not_monitored_unless_asked(as_admin):
    """``spemcs_enabled`` defaults to False.

    Defaulting it True would mean creating a room silently opts every workstation in it into
    enforcement - and, given the filter above, immediately publishes it to any holder of the
    enrolment key.
    """
    created_id = None
    db = SessionLocal()
    try:
        response = client.post("/api/labs", headers=as_admin, json={
            "building_id": "Block-Default", "lab_name": "Default Flags Lab", "capacity": 12,
        })
        assert response.status_code == 201
        created_id = response.json()["lab_id"]
        assert response.json()["spemcs_enabled"] is False

        listed = client.get(ENROLLMENT_LABS, headers=_key_header()).json()
        assert "Default Flags Lab" not in {lab["lab_name"] for lab in listed}
    finally:
        if created_id:
            db.query(Lab).filter(Lab.lab_id == uuid.UUID(created_id)).delete()
            db.commit()
        db.close()


def test_lab_creation_refuses_a_duplicate_room(as_admin):
    created_id = None
    db = SessionLocal()
    try:
        first = client.post("/api/labs", headers=as_admin, json={
            "building_id": "Block-Dup", "lab_name": "Duplicated Lab", "capacity": 15,
        })
        assert first.status_code == 201
        created_id = first.json()["lab_id"]

        second = client.post("/api/labs", headers=as_admin, json={
            "building_id": "Block-Dup", "lab_name": "Duplicated Lab", "capacity": 30,
        })
        assert second.status_code == 409
    finally:
        if created_id:
            db.query(Lab).filter(Lab.lab_id == uuid.UUID(created_id)).delete()
            db.commit()
        db.close()


def test_lab_creation_rejects_a_caller_chosen_primary_key(as_admin):
    """``lab_id`` is server-assigned. A caller-supplied one is ignored, not honoured.

    ``LabCreate`` does not declare the field and pydantic's default is to ignore extras, so the
    server generates its own. Honouring it would let one request target another lab's row.
    """
    attempted = uuid.uuid4()
    created_id = None
    db = SessionLocal()
    try:
        response = client.post("/api/labs", headers=as_admin, json={
            "lab_id": str(attempted),
            "building_id": "Block-Key", "lab_name": "Server Assigned Id Lab", "capacity": 8,
        })
        assert response.status_code == 201
        created_id = response.json()["lab_id"]
        assert created_id != str(attempted)
    finally:
        if created_id:
            db.query(Lab).filter(Lab.lab_id == uuid.UUID(created_id)).delete()
            db.commit()
        db.close()


@pytest.mark.parametrize("capacity", [0, -5])
def test_lab_creation_rejects_a_nonsensical_capacity(as_admin, capacity):
    response = client.post("/api/labs", headers=as_admin, json={
        "building_id": "Block-Cap", "lab_name": f"Capacity {capacity} Lab", "capacity": capacity,
    })
    assert response.status_code == 422


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_lab_creation_rejects_a_blank_name(as_admin, blank):
    """A whitespace-only name is refused, not stored.

    ``min_length=1`` counts characters, so it admits ``"   "`` - which reaches the wizard's dropdown
    as a blank entry the candidate cannot identify. The refusal comes from ``LabCreate``'s
    ``_reject_whitespace_only`` validator.
    """
    response = client.post("/api/labs", headers=as_admin, json={
        "building_id": "Block-Blank", "lab_name": blank, "capacity": 10,
    })
    assert response.status_code == 422


def test_lab_names_are_stored_trimmed(as_admin):
    """The other half of that validator, and the reason it trims rather than only refusing.

    Untrimmed, ``"Lab 101"`` and ``"Lab 101 "`` are two different rooms as far as ``create_lab``'s
    duplicate check is concerned, and identical as far as an operator reading the dropdown is
    concerned.
    """
    created_id = None
    db = SessionLocal()
    try:
        first = client.post("/api/labs", headers=as_admin, json={
            "building_id": " Block-Trim ", "lab_name": "  Padded Lab  ", "capacity": 10,
        })
        assert first.status_code == 201
        created_id = first.json()["lab_id"]
        assert first.json()["lab_name"] == "Padded Lab"
        assert first.json()["building_id"] == "Block-Trim"

        duplicate = client.post("/api/labs", headers=as_admin, json={
            "building_id": "Block-Trim", "lab_name": "Padded Lab", "capacity": 20,
        })
        assert duplicate.status_code == 409
    finally:
        if created_id:
            db.query(Lab).filter(Lab.lab_id == uuid.UUID(created_id)).delete()
            db.commit()
        db.close()
