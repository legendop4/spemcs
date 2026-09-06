"""Phase 19 authentication and authorization coverage for the SPEMCS management API.

WHY THESE TESTS ARE HERMETIC, AND HOW
-------------------------------------
The repository has no test database and no ``conftest.py``; the module-level engine in
``backend.app.database`` points at a remote Postgres instance, and the existing suites take about
five minutes because they really talk to it. Nothing in this file does.

Three facts make that work, and all three are load-bearing rather than incidental:

1. ``TestClient(app)`` used as a plain object - NOT as a context manager - never runs the app's
   lifespan. Lifespan is what connects to the database, runs ``create_all`` and seeds the demo
   admin. Constructing the client and calling ``client.get(...)`` skips all of it.
2. ``get_db`` yields a ``Session`` without connecting; SQLAlchemy connects lazily on first use.
   Every refusal asserted here comes from a dependency that raises BEFORE the route body runs, so
   no query is ever issued.
3. Where a test needs an *accepted* identity, ``get_db`` is overridden with an in-memory stub and
   ``SessionLocal`` is monkeypatched for the WebSocket path, which builds its own session rather
   than receiving one by injection.

Making the whole backend suite hermetic means giving the project a test database, which is the P1-Q
work item, not this phase's. This file is scoped to what can be proven without one, and what it
proves is the part that matters: which callers are refused, and which are not.

WHAT IS DELIBERATELY NOT DONE HERE
----------------------------------
No test asserts a secret VALUE and no test prints one. The leakage tests assert the ABSENCE of
configured secret material in responses and log records, which is the direction that fails safe: an
assertion comparing against the real secret would put it in this file.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.main import app
from backend.models.device import Device
from backend.models.session import ExamSession
from backend.models.user import User, UserRole
from backend.services.auth_service import create_access_token, create_device_token


# ── In-memory stand-ins for the ORM session ───────────────────────────────────


class _StubQuery:
    """A Query that answers from a fixed row list and ignores every filter.

    Filters are ignored on purpose. This file asserts on *gates*, and a stub that tried to
    reimplement SQLAlchemy's filtering would be asserting on the stub. Where a test needs a
    specific row to be found or not found, it supplies exactly that row list.
    """

    def __init__(self, rows):
        self._rows = list(rows)

    def first(self):
        return self._rows[0] if self._rows else None

    def one_or_none(self):
        return self.first()

    def all(self):
        return list(self._rows)

    def count(self):
        return len(self._rows)

    def scalar(self):
        return len(self._rows)

    def __getattr__(self, _name):
        # filter / filter_by / order_by / join / offset / limit / options / ... all chain.
        def _chain(*_args, **_kwargs):
            return self

        return _chain


class _StubSession:
    """Enough Session surface for the auth dependencies, and for a read body to return empty."""

    def __init__(self, rows: dict | None = None):
        self._rows = rows or {}

    def query(self, *entities):
        key = entities[0] if entities else None
        return _StubQuery(self._rows.get(key, []))

    # Writes are accepted and discarded. Nothing in this file asserts on persistence, and a stub
    # that raised here would turn "the gate opened" into a test error rather than a pass.
    def add(self, _obj):
        pass

    def flush(self):
        pass

    def refresh(self, _obj):
        pass

    def delete(self, _obj):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def _make_user(role: str, *, is_active: bool = True, username: str = "tester") -> User:
    """An unsaved User.

    ``is_active`` is set explicitly because the column default is applied at INSERT, so an
    in-memory instance would otherwise carry ``None`` and read as disabled.
    """
    user = User()
    user.user_id = uuid.uuid4()
    user.name = username
    user.username = username
    user.email = f"{username}@example.invalid"
    user.role = role
    user.is_active = is_active
    return user


def _make_device(hardware_uuid: str, *, device_name: str | None = None) -> Device:
    device = Device()
    device.device_id = uuid.uuid4()
    device.hardware_uuid = hardware_uuid
    device.device_name = device_name or hardware_uuid
    return device


def _make_session_row(device_id) -> ExamSession:
    row = ExamSession()
    row.session_id = uuid.uuid4()
    row.device_id = device_id
    row.exam_id = uuid.uuid4()
    return row


def _token_for(user: User) -> str:
    return create_access_token(
        data={"sub": str(user.user_id), "username": user.username, "role": user.role}
    )


def _auth(user: User) -> dict:
    return {"Authorization": f"Bearer {_token_for(user)}"}


class _rows:
    """Context manager installing a stub session for the duration of a request.

    Overrides ``get_db`` (dependency injection) *and* ``backend.app.database.SessionLocal``, which
    the dashboard WebSocket calls directly because a WebSocket handler cannot receive an injected
    session. Both are needed; overriding only the first leaves the socket talking to Postgres.
    """

    def __init__(self, monkeypatch, **by_model):
        self._monkeypatch = monkeypatch
        self._session = _StubSession({
            User: by_model.get("users", []),
            Device: by_model.get("devices", []),
            ExamSession: by_model.get("sessions", []),
        })

    def __enter__(self):
        app.dependency_overrides[get_db] = lambda: self._session
        self._monkeypatch.setattr(
            "backend.app.database.SessionLocal", lambda: self._session, raising=True
        )
        return self._session

    def __exit__(self, *_exc):
        app.dependency_overrides.pop(get_db, None)
        return False


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def client() -> TestClient:
    """A TestClient that never triggers lifespan (see the module docstring)."""
    return TestClient(app)


@pytest.fixture()
def lenient_client() -> TestClient:
    """As above, but a route-body explosion surfaces as 500 rather than a test error.

    Used only by the positive-role tests. Those assert "the gate opened", and a body that then
    fails for want of a real database is the expected, documented outcome - it must not be
    confused with a refusal, and it must not abort the test.
    """
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _no_leftover_overrides():
    yield
    app.dependency_overrides.clear()


# ── The endpoint inventory ────────────────────────────────────────────────────
# Kept as data so a new route cannot be added to the API without a deliberate decision about which
# list it belongs in. Verified against app.routes, not against the previous audit.

STAFF_READ_ENDPOINTS = [
    ("get", "/api/alerts"),
    ("get", f"/api/alerts/{uuid.uuid4()}"),
    ("get", "/api/dashboard/summary"),
    ("get", "/api/devices"),
    ("get", "/api/devices/online"),
    ("get", "/api/devices/tree"),
    ("get", f"/api/devices/{uuid.uuid4()}"),
    ("get", f"/api/devices/{uuid.uuid4()}/status"),
    ("get", "/api/events"),
    ("get", f"/api/events/{uuid.uuid4()}"),
    ("get", "/api/exam-devices"),
    ("get", f"/api/exam-devices/{uuid.uuid4()}"),
    ("get", "/api/exams"),
    ("get", f"/api/exams/{uuid.uuid4()}"),
    ("get", f"/api/exams/{uuid.uuid4()}/alerts"),
    ("get", f"/api/exams/{uuid.uuid4()}/devices"),
    ("get", f"/api/exams/{uuid.uuid4()}/enforcement-readiness"),
    ("get", f"/api/exams/{uuid.uuid4()}/sessions"),
    ("get", f"/api/exams/{uuid.uuid4()}/timeline"),
    ("get", "/api/labs"),
    ("get", f"/api/labs/{uuid.uuid4()}"),
    ("get", f"/api/labs/{uuid.uuid4()}/devices"),
    ("get", f"/api/policies/exam/{uuid.uuid4()}"),
    ("get", f"/api/policies/exam/{uuid.uuid4()}/device-states"),
    ("get", f"/api/policies/exam/{uuid.uuid4()}/device-states/{uuid.uuid4()}"),
    ("get", "/api/policies/vendors"),
    ("get", f"/api/policies/vendors/{uuid.uuid4()}"),
    ("get", "/api/reports"),
    ("get", f"/api/reports/{uuid.uuid4()}"),
    ("get", f"/api/reports/{uuid.uuid4()}/export/csv"),
    ("get", f"/api/reports/{uuid.uuid4()}/timeline/device/{uuid.uuid4()}"),
    ("get", f"/api/reports/{uuid.uuid4()}/timeline/student/R1"),
    ("get", "/api/sessions"),
    ("get", f"/api/sessions/{uuid.uuid4()}"),
]

#: Endpoints a proctor's valid token must NOT open. Every one either changes privileged state or
#: exposes the record of who did what.
ADMIN_ONLY_ENDPOINTS = [
    ("get", "/api/audit-logs"),
    ("post", "/api/auth/register"),
    ("delete", f"/api/alerts/{uuid.uuid4()}"),
    ("post", "/api/devices"),
    ("put", f"/api/devices/{uuid.uuid4()}"),
    ("delete", f"/api/devices/{uuid.uuid4()}"),
    ("post", "/api/events"),
    ("put", f"/api/events/{uuid.uuid4()}"),
    ("delete", f"/api/events/{uuid.uuid4()}"),
    ("post", "/api/exam-devices"),
    ("put", f"/api/exam-devices/{uuid.uuid4()}"),
    ("delete", f"/api/exam-devices/{uuid.uuid4()}"),
    ("post", "/api/exams"),
    ("put", f"/api/exams/{uuid.uuid4()}"),
    ("delete", f"/api/exams/{uuid.uuid4()}"),
    ("post", "/api/labs"),
    ("patch", f"/api/labs/{uuid.uuid4()}/status"),
    ("post", f"/api/policies/compile/{uuid.uuid4()}"),
    ("post", f"/api/policies/update/{uuid.uuid4()}/LAB1-PC01"),
    ("post", "/api/policies/signing-key/rotate"),
    ("post", f"/api/policies/signing-key/{uuid.uuid4()}/revoke"),
    ("post", "/api/policies/vendors"),
    ("put", f"/api/policies/vendors/{uuid.uuid4()}"),
    ("delete", f"/api/policies/vendors/{uuid.uuid4()}"),
    ("post", "/api/reports"),
    ("put", f"/api/reports/{uuid.uuid4()}"),
    ("delete", f"/api/reports/{uuid.uuid4()}"),
    ("post", f"/api/reports/generate/{uuid.uuid4()}"),
    ("post", "/api/sessions"),
    ("put", f"/api/sessions/{uuid.uuid4()}"),
    ("delete", f"/api/sessions/{uuid.uuid4()}"),
    ("post", "/deployment/push"),
]

#: Staff-reachable endpoints that change exam state. Separate from the admin-only set because a
#: proctor legitimately activates an exam and triages an alert.
STAFF_MUTATION_ENDPOINTS = [
    ("post", "/api/alerts"),
    ("put", f"/api/alerts/{uuid.uuid4()}"),
    ("post", f"/api/exams/{uuid.uuid4()}/activate"),
    ("post", f"/api/exams/{uuid.uuid4()}/deactivate"),
    ("post", f"/api/policies/distribute/{uuid.uuid4()}/LAB1-PC01"),
]

DEVICE_ONLY_ENDPOINTS = [
    ("post", "/api/v1/events"),
    ("post", "/api/v1/sessions/start"),
    ("post", "/api/v1/sessions/verify-student"),
]

#: Public BY DESIGN, listed explicitly so "protect everything" cannot be applied here by reflex.
#: /health is what a load balancer probes; the two signing-key GETs serve PUBLIC key material to
#: endpoint agents that hold no operator credential (the decision is recorded in routes/policies.py,
#: and ControlPipeWorker.cs fetches both unauthenticated).
INTENTIONALLY_PUBLIC = [
    "/",
    "/health",
    "/api/health",
    "/api/v1/management/health",
    "/api/policies/signing-key/public",
    "/api/policies/signing-key/keyring",
]

_BODY_METHODS = {"post", "put", "patch"}

ALL_GATED = STAFF_READ_ENDPOINTS + STAFF_MUTATION_ENDPOINTS + ADMIN_ONLY_ENDPOINTS


def _call(client: TestClient, method: str, path: str, **kwargs):
    if method in _BODY_METHODS and "json" not in kwargs:
        kwargs["json"] = {}
    return getattr(client, method)(path, **kwargs)


# ── 1. Unauthenticated access ─────────────────────────────────────────────────


@pytest.mark.parametrize("method,path", ALL_GATED)
def test_management_endpoint_refuses_anonymous_caller(client, method, path):
    """Every management endpoint answers 401 without credentials.

    401 rather than 403 is correct here and the distinction is not pedantic: 403 means "your
    identity is known and insufficient", which would tell an anonymous scanner that the resource
    exists and is merely out of reach.
    """
    response = _call(client, method, path)
    assert response.status_code == 401, (
        f"{method.upper()} {path} answered {response.status_code} to an anonymous caller"
    )
    assert response.json()["detail"] == "Authentication required"


@pytest.mark.parametrize("method,path", DEVICE_ONLY_ENDPOINTS)
def test_agent_endpoint_refuses_caller_without_device_token(client, method, path):
    response = _call(client, method, path)
    assert response.status_code == 401
    assert response.json()["detail"] == "Device authentication required"


@pytest.mark.parametrize("path", INTENTIONALLY_PUBLIC)
def test_intentionally_public_endpoint_is_still_reachable(lenient_client, path):
    """The counter-test to everything above, and the one that fails if somebody later "fixes" the
    remaining open routes by gating them: a health probe that starts answering 401 takes the
    deployment down, and an agent that cannot fetch the signing keyring cannot verify a policy and
    therefore cannot start an exam."""
    response = lenient_client.get(path)
    assert response.status_code != 401, f"{path} is meant to be public but demanded credentials"
    assert response.status_code != 403, f"{path} is meant to be public but refused the caller"


def test_every_route_is_either_gated_or_on_the_public_list(client):
    """No route escapes classification.

    Walks the LIVE route table and asserts that anything not on the public list refuses an
    anonymous caller. This is the test that catches a new route added later without a gate, which
    is the realistic way this regresses - the inventory lists above are maintained by hand, so a
    new route simply would not appear in them.
    """
    from fastapi.routing import APIRoute

    public = set(INTENTIONALLY_PUBLIC)
    # Self-authenticating or in-band-authenticating routes that a request-level probe cannot
    # classify: enrolment presents a bootstrap key in its body, and login IS the credential
    # exchange. Both are covered by their own tests below.
    #
    # /api/v1/enrollment/labs is exempted for a narrower reason: it IS gated (401 without the
    # bootstrap key), but its refusal status depends on server configuration - an unset
    # ENROLLMENT_BOOTSTRAP_KEY answers 503, deliberately, so that clearing the variable disables the
    # feature rather than the check. 503 is neither 401 nor 403, so this walk would report a
    # correctly-closed door as an open one on a box where the key is not configured. The credential
    # boundary for that route is proven directly, and in both configurations, by
    # test_enrollment_lab_discovery.py.
    public |= {
        "/api/auth/login",
        "/api/v1/devices/register",
        "/api/v1/enrollment/labs",
    }

    unguarded = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or route.path in public:
            continue
        method = next(
            (m.lower() for m in ("GET", "POST", "PUT", "PATCH", "DELETE") if m in route.methods),
            None,
        )
        if method is None:
            continue
        # Path parameters are left as literal text: the gate runs before path conversion, before
        # the body and before the handler, so an unparseable UUID cannot mask a missing gate.
        path = route.path.replace("{", "").replace("}", "")
        response = _call(client, method, path)
        if response.status_code not in (401, 403):
            unguarded.append(f"{method.upper()} {route.path} -> {response.status_code}")

    assert not unguarded, "routes reachable without credentials: " + "; ".join(unguarded)


# ── 2. Authenticated access with the right role ───────────────────────────────


@pytest.mark.parametrize("method,path", STAFF_READ_ENDPOINTS)
def test_staff_read_endpoint_admits_an_administrator(lenient_client, monkeypatch, method, path):
    """An administrator gets past the gate.

    The assertion is "not refused", not "200": the route body then needs a real database, which
    this suite deliberately does not provide. What is being proven is that the gate OPENS - a suite
    that only ever saw 401s would pass just as happily against an endpoint nobody can use.
    """
    admin = _make_user(UserRole.ADMIN.value)
    with _rows(monkeypatch, users=[admin]):
        response = _call(lenient_client, method, path, headers=_auth(admin))
    assert response.status_code not in (401, 403), (
        f"{method.upper()} {path} refused an administrator with {response.status_code}"
    )


@pytest.mark.parametrize("method,path", STAFF_READ_ENDPOINTS)
def test_staff_read_endpoint_admits_a_proctor(lenient_client, monkeypatch, method, path):
    proctor = _make_user(UserRole.PROCTOR.value)
    with _rows(monkeypatch, users=[proctor]):
        response = _call(lenient_client, method, path, headers=_auth(proctor))
    assert response.status_code not in (401, 403), (
        f"{method.upper()} {path} refused a proctor with {response.status_code}"
    )


@pytest.mark.parametrize("method,path", ADMIN_ONLY_ENDPOINTS)
def test_admin_only_endpoint_admits_an_administrator(lenient_client, monkeypatch, method, path):
    admin = _make_user(UserRole.ADMIN.value)
    with _rows(monkeypatch, users=[admin]):
        response = _call(lenient_client, method, path, headers=_auth(admin))
    assert response.status_code not in (401, 403), (
        f"{method.upper()} {path} refused an administrator with {response.status_code}"
    )


@pytest.mark.parametrize("method,path", STAFF_MUTATION_ENDPOINTS)
def test_staff_mutation_admits_a_proctor(lenient_client, monkeypatch, method, path):
    """A proctor invigilates, so activating an exam and triaging an alert must remain possible.

    Without this, "hardened the API" and "broke invigilation" are indistinguishable outcomes.
    """
    proctor = _make_user(UserRole.PROCTOR.value)
    with _rows(monkeypatch, users=[proctor]):
        response = _call(lenient_client, method, path, headers=_auth(proctor))
    assert response.status_code not in (401, 403)


# ── 3. Wrong-role access ──────────────────────────────────────────────────────


@pytest.mark.parametrize("method,path", ADMIN_ONLY_ENDPOINTS)
def test_admin_only_endpoint_refuses_a_proctor(client, monkeypatch, method, path):
    """Authentication is not authorization.

    A proctor holds a perfectly valid token. Every endpoint here must still refuse it with 403 -
    the status that says "we know who you are and it is not enough" - rather than admitting it
    because the token verified.
    """
    proctor = _make_user(UserRole.PROCTOR.value)
    with _rows(monkeypatch, users=[proctor]):
        response = _call(client, method, path, headers=_auth(proctor))
    assert response.status_code == 403, (
        f"{method.upper()} {path} answered {response.status_code} to a proctor's token"
    )


@pytest.mark.parametrize("method,path", ALL_GATED)
def test_management_endpoint_refuses_an_unknown_role(client, monkeypatch, method, path):
    """A role string outside the allow-list grants nothing anywhere.

    ``users.role`` is a plain varchar, so a row can hold any string; what must not happen is such a
    row being treated as privileged by an endpoint that spells its allow-list differently.
    """
    outsider = _make_user("student")
    with _rows(monkeypatch, users=[outsider]):
        response = _call(client, method, path, headers=_auth(outsider))
    assert response.status_code == 403


@pytest.mark.parametrize("method,path", ALL_GATED)
def test_management_endpoint_refuses_a_device_token(client, method, path):
    """Device identity must not open a management endpoint.

    Device tokens and operator JWTs are different formats keyed by different secrets, but both
    arrive as ``Authorization: Bearer``. This proves the management gate does not accept one for
    the other - an endpoint agent's 30-day token must not read the invigilation record.
    """
    device_token = create_device_token(hardware_uuid="LAB1-PC01")
    response = _call(client, method, path, headers={"Authorization": f"Bearer {device_token}"})
    assert response.status_code == 401


@pytest.mark.parametrize("method,path", DEVICE_ONLY_ENDPOINTS)
def test_agent_endpoint_refuses_an_operator_jwt(client, method, path):
    """And the converse: an admin's JWT must not let a human file violation events.

    Events attributed to a workstation are evidence about a candidate. An operator credential
    being usable to manufacture them would corrupt the record in the direction nobody audits.
    """
    admin = _make_user(UserRole.ADMIN.value)
    response = _call(client, method, path, headers=_auth(admin))
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired device token"


# ── 4. Expired, revoked and malformed credentials ─────────────────────────────


def test_expired_operator_token_is_refused(client, monkeypatch):
    admin = _make_user(UserRole.ADMIN.value)
    expired = create_access_token(
        data={"sub": str(admin.user_id), "username": admin.username, "role": admin.role},
        expires_delta=timedelta(minutes=-5),
    )
    with _rows(monkeypatch, users=[admin]):
        response = client.get("/api/alerts", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401


def test_disabled_account_is_refused_on_the_rest_api(client, monkeypatch):
    """Disabling an account must end its REST access immediately.

    Tokens last eight hours and there is no revocation list, so if only the signature were checked
    a revoked operator would keep working for the rest of the token's life. Login already refused
    disabled accounts, which is exactly what made this easy to miss: the account cannot get a NEW
    token, but the one it already holds kept working.
    """
    disabled = _make_user(UserRole.ADMIN.value, is_active=False)
    with _rows(monkeypatch, users=[disabled]):
        response = client.get("/api/alerts", headers=_auth(disabled))
    assert response.status_code == 401


def test_disabled_account_is_refused_on_the_dashboard_socket(client, monkeypatch):
    disabled = _make_user(UserRole.ADMIN.value, is_active=False)
    with _rows(monkeypatch, users=[disabled]):
        with client.websocket_connect("/api/v1/ws/dashboard") as ws:
            ws.send_json({"action": "AUTHENTICATE", "token": _token_for(disabled)})
            first = ws.receive_json()
    assert first["type"] == "ERROR"
    assert first["error_code"] == "AUTH_FAILED"


def test_token_naming_an_account_that_no_longer_exists_is_refused(client, monkeypatch):
    """A validly signed token for a deleted user grants nothing."""
    ghost = _make_user(UserRole.ADMIN.value)
    with _rows(monkeypatch, users=[]):
        response = client.get("/api/alerts", headers=_auth(ghost))
    assert response.status_code == 401


@pytest.mark.parametrize("bad_token", [
    "",
    "not-a-jwt",
    "a.b.c",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.",            # no signature
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",             # alg=none
])
def test_malformed_operator_token_is_refused(client, bad_token):
    """Including alg=none, the classic JWT bypass.

    python-jose refuses it because ``jwt.decode`` is called with an explicit algorithms list - but
    that is a property of one call site, and call sites get edited.
    """
    response = client.get("/api/alerts", headers={"Authorization": f"Bearer {bad_token}"})
    assert response.status_code == 401


def test_operator_token_signed_with_the_wrong_key_is_refused(client, monkeypatch):
    """The signature is actually verified.

    Minting under a substituted SECRET_KEY is how that is proven; if the check were absent, every
    forgery in this phase's threat model would succeed. Both substitutes are literals in this file
    and neither is any deployment's key.
    """
    admin = _make_user(UserRole.ADMIN.value)
    monkeypatch.setattr(settings, "SECRET_KEY", "a-substitute-signing-key-used-only-by-this-test")
    forged = _token_for(admin)
    monkeypatch.setattr(settings, "SECRET_KEY", "a-different-substitute-key-for-the-server-side")

    with _rows(monkeypatch, users=[admin]):
        response = client.get("/api/alerts", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_device_token_signed_with_the_wrong_secret_is_refused(client, lenient_client, monkeypatch):
    """The HMAC is actually verified.

    A device row is stubbed and the positive control asserted in the same test, because without
    them a 401 also arrives from the device LOOKUP failing - so the test would pass identically
    whether the signature was checked or not.
    """
    device = _make_device("LAB1-PC01")
    body = {"hardwareUuid": "LAB1-PC01", "deviceName": "LAB1-PC01"}

    # Positive control: the same request with a correctly signed token gets past the gate.
    with _rows(monkeypatch, devices=[device]):
        control = lenient_client.post(
            "/api/v1/sessions/start", json=body,
            headers={"X-Device-Token": create_device_token(hardware_uuid="LAB1-PC01")},
        )
    assert control.status_code not in (401, 403), (
        "the positive control was refused, so the negative case below proves nothing"
    )

    monkeypatch.setattr(settings, "DEVICE_TOKEN_SECRET", "a-substitute-device-secret-for-tests")
    forged = create_device_token(hardware_uuid="LAB1-PC01")
    monkeypatch.setattr(settings, "DEVICE_TOKEN_SECRET", "a-different-substitute-device-secret")

    with _rows(monkeypatch, devices=[device]):
        response = client.post(
            "/api/v1/sessions/start", json=body, headers={"X-Device-Token": forged}
        )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired device token"


def test_expired_device_token_is_refused(client, monkeypatch):
    """The device row exists, so only the expiry can produce this refusal."""
    expired = create_device_token(hardware_uuid="LAB1-PC01", ttl_seconds=-60)
    with _rows(monkeypatch, devices=[_make_device("LAB1-PC01")]):
        response = client.post(
            "/api/v1/sessions/start",
            json={"hardwareUuid": "LAB1-PC01"},
            headers={"X-Device-Token": expired},
        )
    assert response.status_code == 401


def test_device_token_with_no_hardware_uuid_is_refused(client, monkeypatch):
    """An empty subject is not an identity.

    A token whose ``hardware_uuid`` is blank would otherwise authenticate, then look up a device row
    on the empty string, and the ownership comparison against it would be meaningless.
    """
    blank = create_device_token(hardware_uuid="")
    with _rows(monkeypatch, devices=[_make_device("")]):
        response = client.post(
            "/api/v1/sessions/start", json={"hardwareUuid": ""},
            headers={"X-Device-Token": blank},
        )
    assert response.status_code == 401


# ── 5. Registration abuse ─────────────────────────────────────────────────────


REGISTRATION_ESCALATION_PAYLOADS = [
    pytest.param({"username": "x", "email": "x@e.invalid", "password": "password123",
                  "role": "admin"}, id="explicit-admin"),
    pytest.param({"username": "x", "email": "x@e.invalid", "password": "password123",
                  "role": "superadmin"}, id="invented-superadmin"),
    pytest.param({"username": "x", "email": "x@e.invalid", "password": "password123",
                  "role": "ADMIN"}, id="case-variant-admin"),
    pytest.param({"username": "x", "email": "x@e.invalid", "password": "password123",
                  "role": ""}, id="empty-role"),
    pytest.param({"username": "x", "email": "x@e.invalid", "password": "password123",
                  "role": None}, id="null-role"),
    pytest.param({"username": "x", "email": "x@e.invalid", "password": "password123"},
                 id="role-omitted"),
    pytest.param({"username": "x", "email": "x@e.invalid", "password": "password123",
                  "role": ["admin"]}, id="role-as-list"),
    pytest.param({"username": "x", "email": "x@e.invalid", "password": "password123",
                  "role": {"role": "admin"}}, id="role-as-object"),
    pytest.param({"username": "x", "email": "x@e.invalid", "password": "password123",
                  "role": "proctor", "is_active": True,
                  "user_id": str(uuid.uuid4())}, id="extra-fields-injected"),
]


@pytest.mark.parametrize("payload", REGISTRATION_ESCALATION_PAYLOADS)
def test_anonymous_registration_creates_nothing(client, payload):
    """The headline requirement: an unauthenticated request cannot create an account at all.

    ``role-omitted`` is the case that used to BE the exploit rather than an edge case. The schema
    defaulted ``role`` to ``"admin"``, so the smallest valid body - the one any client sends by
    accident - produced a full administrator. Nothing had to be manipulated.
    """
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 401


@pytest.mark.parametrize("payload", REGISTRATION_ESCALATION_PAYLOADS)
def test_proctor_cannot_register_anyone(client, monkeypatch, payload):
    """A valid non-admin token does not create accounts either - including proctor accounts.

    Self-replication is the escalation that matters: a proctor who could create proctors could hand
    out invigilation access, and one who could create admins owns the system.
    """
    proctor = _make_user(UserRole.PROCTOR.value)
    with _rows(monkeypatch, users=[proctor]):
        response = client.post("/api/auth/register", json=payload, headers=_auth(proctor))
    assert response.status_code == 403


@pytest.mark.parametrize("role_value", ["superadmin", "root", "ADMIN ", "admin;proctor", "",
                                        None, ["admin"], {"r": "admin"}, 1])
def test_admin_cannot_store_a_role_outside_the_enum(lenient_client, monkeypatch, role_value):
    """Even an administrator cannot invent a role.

    ``role`` used to be an unconstrained ``str`` written straight to the column. An invented value
    grants nothing against today's allow-lists, but it also means the account silently bypasses
    every role check instead of being rejected, and the next allow-list added anywhere decides
    retroactively what that stored string means. 422 at the boundary is the fix.
    """
    admin = _make_user(UserRole.ADMIN.value)
    payload = {"username": "x", "email": "x@e.invalid", "password": "password123",
               "role": role_value}
    with _rows(monkeypatch, users=[admin]):
        response = lenient_client.post("/api/auth/register", json=payload, headers=_auth(admin))
    assert response.status_code == 422, (
        f"role={role_value!r} was not rejected at the schema boundary"
    )


def test_registration_rejects_a_short_password(lenient_client, monkeypatch):
    admin = _make_user(UserRole.ADMIN.value)
    payload = {"username": "x", "email": "x@e.invalid", "password": "short", "role": "proctor"}
    with _rows(monkeypatch, users=[admin]):
        response = lenient_client.post("/api/auth/register", json=payload, headers=_auth(admin))
    assert response.status_code == 422


def test_schema_default_role_is_the_least_privileged():
    """Pinned directly, because this default WAS the vulnerability.

    Asserted on the schema rather than through the API so it keeps being checked even if the
    endpoint's gating changes again.
    """
    from backend.schemas.user import UserCreate

    parsed = UserCreate(username="x", email="x@e.invalid", password="password123")
    assert parsed.role is UserRole.PROCTOR
    assert parsed.role is not UserRole.ADMIN


def test_model_column_default_role_is_the_least_privileged():
    """The same defect one layer down: an INSERT that omits ``role`` must not yield an admin."""
    assert User.__table__.c.role.default.arg == UserRole.PROCTOR.value


# ── 6. IDOR / ownership ───────────────────────────────────────────────────────


def test_device_token_cannot_start_a_session_for_another_device(client, monkeypatch):
    """Ownership, not merely a valid token.

    One compromised or copied workstation credential must not let its holder act as the rest of the
    lab. The token here is genuine; only the device it names in the body is somebody else's.
    """
    own = _make_device("LAB1-PC01")
    token = create_device_token(hardware_uuid="LAB1-PC01")
    with _rows(monkeypatch, devices=[own]):
        response = client.post(
            "/api/v1/sessions/start",
            json={"hardwareUuid": "LAB1-PC02", "deviceName": "LAB1-PC02"},
            headers={"X-Device-Token": token},
        )
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"].lower()


def test_device_token_cannot_file_events_against_another_device(client, monkeypatch):
    """Fabricating violations against a machine you are not is a false-accusation vector."""
    own = _make_device("LAB1-PC01")
    token = create_device_token(hardware_uuid="LAB1-PC01")
    with _rows(monkeypatch, devices=[own]):
        response = client.post(
            "/api/v1/events",
            json={
                "eventId": str(uuid.uuid4()),
                "deviceName": "LAB1-PC02",
                "eventType": "APPLICATION_OPENED",
                "processId": 1234,
                "processName": "chrome.exe",
                "timestampUtc": datetime.utcnow().isoformat(),
            },
            headers={"X-Device-Token": token},
        )
    assert response.status_code == 403


def test_device_token_cannot_verify_a_student_onto_another_devices_session(client, monkeypatch):
    """The IDOR that mattered most.

    ``sessionId`` is a caller-supplied reference to a row belonging to SOME device, and nothing
    required it to be this device's. Binding a roll number onto another candidate's live session
    attributes that candidate's subsequent violations to the wrong student - and the exam record is
    the artefact this whole system exists to produce.
    """
    own = _make_device("LAB1-PC01")
    someone_elses_session = _make_session_row(device_id=uuid.uuid4())
    token = create_device_token(hardware_uuid="LAB1-PC01")
    with _rows(monkeypatch, devices=[own], sessions=[someone_elses_session]):
        response = client.post(
            "/api/v1/sessions/verify-student",
            json={"sessionId": str(someone_elses_session.session_id), "rollNumber": "R1"},
            headers={"X-Device-Token": token},
        )
    assert response.status_code == 403
    assert "session" in response.json()["detail"].lower()


def test_device_may_act_on_its_own_session(lenient_client, monkeypatch):
    """The falsifier for the test above.

    Without this, the ownership check would satisfy its test just as well by refusing everything,
    and the agent would be unable to verify any candidate at all.
    """
    own = _make_device("LAB1-PC01")
    own_session = _make_session_row(device_id=own.device_id)
    token = create_device_token(hardware_uuid="LAB1-PC01")
    with _rows(monkeypatch, devices=[own], sessions=[own_session]):
        response = lenient_client.post(
            "/api/v1/sessions/verify-student",
            json={"sessionId": str(own_session.session_id), "rollNumber": "R1"},
            headers={"X-Device-Token": token},
        )
    assert response.status_code not in (401, 403), (
        "the ownership check refused a device acting on its own session"
    )


def test_ownership_refusal_is_403_not_404(client, monkeypatch):
    """404 would disclose whether the other device exists; 403 says only "not yours"."""
    own = _make_device("LAB1-PC01")
    token = create_device_token(hardware_uuid="LAB1-PC01")
    with _rows(monkeypatch, devices=[own]):
        response = client.post(
            "/api/v1/sessions/start",
            json={"deviceName": "A-DEVICE-THAT-DOES-NOT-EXIST"},
            headers={"X-Device-Token": token},
        )
    assert response.status_code == 403


def test_token_for_a_removed_enrolment_is_refused(client, monkeypatch):
    """A token whose device row is gone is a credential that identifies nobody.

    401 rather than 404, so the endpoint is not an oracle for which enrolments exist.
    """
    token = create_device_token(hardware_uuid="LAB1-PC01")
    with _rows(monkeypatch, devices=[]):
        response = client.post(
            "/api/v1/sessions/start",
            json={"hardwareUuid": "LAB1-PC01"},
            headers={"X-Device-Token": token},
        )
    assert response.status_code == 401


# ── 7. Dashboard WebSocket authentication and authorization ───────────────────


def test_dashboard_websocket_sends_nothing_before_authentication(client, monkeypatch):
    """The socket must send NOTHING before the client authenticates.

    The old handler pushed INITIAL_STATE - the full online-device inventory - as its first frame, to
    anyone who could reach the port. This asserts the ORDERING, not merely an eventual close: the
    first frame the client ever sees after a failed AUTHENTICATE must be the refusal.
    """
    with _rows(monkeypatch, users=[]):
        with client.websocket_connect("/api/v1/ws/dashboard") as ws:
            ws.send_json({"action": "AUTHENTICATE", "token": ""})
            first = ws.receive_json()
    assert first["type"] == "ERROR"
    assert first["error_code"] == "AUTH_FAILED"


def test_dashboard_websocket_refuses_a_first_frame_that_is_not_authenticate(client, monkeypatch):
    """Subscribing before authenticating must not work."""
    with _rows(monkeypatch, users=[]):
        with client.websocket_connect("/api/v1/ws/dashboard") as ws:
            ws.send_json({"action": "SUBSCRIBE_EXAM", "exam_id": str(uuid.uuid4())})
            first = ws.receive_json()
    assert first["type"] == "ERROR"
    assert first["error_code"] == "AUTH_REQUIRED"


def test_dashboard_websocket_admits_an_administrator(client, monkeypatch):
    admin = _make_user(UserRole.ADMIN.value, username="admin-user")
    with _rows(monkeypatch, users=[admin]):
        with client.websocket_connect("/api/v1/ws/dashboard") as ws:
            ws.send_json({"action": "AUTHENTICATE", "token": _token_for(admin)})
            first = ws.receive_json()
            second = ws.receive_json()
    assert first["type"] == "AUTHENTICATED"
    assert first["payload"]["role"] == UserRole.ADMIN.value
    assert second["type"] == "INITIAL_STATE"


def test_dashboard_websocket_admits_a_proctor(client, monkeypatch):
    proctor = _make_user(UserRole.PROCTOR.value, username="proctor-user")
    with _rows(monkeypatch, users=[proctor]):
        with client.websocket_connect("/api/v1/ws/dashboard") as ws:
            ws.send_json({"action": "AUTHENTICATE", "token": _token_for(proctor)})
            first = ws.receive_json()
    assert first["type"] == "AUTHENTICATED"


def test_dashboard_websocket_accepts_a_bearer_header_from_a_non_browser_client(client, monkeypatch):
    admin = _make_user(UserRole.ADMIN.value)
    with _rows(monkeypatch, users=[admin]):
        with client.websocket_connect("/api/v1/ws/dashboard", headers=_auth(admin)) as ws:
            first = ws.receive_json()
    assert first["type"] == "AUTHENTICATED"


def test_dashboard_websocket_refuses_an_unauthorized_role(client, monkeypatch):
    """Authenticated but not entitled: FORBIDDEN, distinct from the AUTH_FAILED case.

    The distinction is safe here and nowhere else: a caller who authenticated successfully already
    knows their token is good, so being told the role is insufficient reveals nothing new.
    """
    outsider = _make_user("student", username="student-user")
    with _rows(monkeypatch, users=[outsider]):
        with client.websocket_connect("/api/v1/ws/dashboard") as ws:
            ws.send_json({"action": "AUTHENTICATE", "token": _token_for(outsider)})
            first = ws.receive_json()
    assert first["type"] == "ERROR"
    assert first["error_code"] == "FORBIDDEN"


def test_dashboard_websocket_refuses_an_expired_token(client, monkeypatch):
    admin = _make_user(UserRole.ADMIN.value)
    expired = create_access_token(
        data={"sub": str(admin.user_id), "username": admin.username, "role": admin.role},
        expires_delta=timedelta(minutes=-1),
    )
    with _rows(monkeypatch, users=[admin]):
        with client.websocket_connect("/api/v1/ws/dashboard") as ws:
            ws.send_json({"action": "AUTHENTICATE", "token": expired})
            first = ws.receive_json()
    assert first["error_code"] == "AUTH_FAILED"


def test_dashboard_websocket_refuses_a_device_token(client, monkeypatch):
    """A device token is not an operator credential, on the socket either."""
    device_token = create_device_token(hardware_uuid="LAB1-PC01")
    with _rows(monkeypatch, users=[]):
        with client.websocket_connect("/api/v1/ws/dashboard") as ws:
            ws.send_json({"action": "AUTHENTICATE", "token": device_token})
            first = ws.receive_json()
    assert first["error_code"] == "AUTH_FAILED"


def test_dashboard_websocket_does_not_register_a_refused_connection(client, monkeypatch):
    """A refused socket must never enter the broadcast set.

    Otherwise the ordering guarantee is worthless: the connection would be closed to the client
    while still being written to, and dashboard data would reach a socket that never authenticated.
    """
    from backend.websocket.manager import realtime_manager

    before = realtime_manager.get_dashboard_count()
    with _rows(monkeypatch, users=[]):
        with client.websocket_connect("/api/v1/ws/dashboard") as ws:
            ws.send_json({"action": "AUTHENTICATE", "token": "invalid"})
            ws.receive_json()
            assert realtime_manager.get_dashboard_count() == before


def test_dashboard_websocket_does_register_an_accepted_connection(client, monkeypatch):
    """The falsifier for the test above: registration must still happen once authorized."""
    from backend.websocket.manager import realtime_manager

    before = realtime_manager.get_dashboard_count()
    admin = _make_user(UserRole.ADMIN.value)
    with _rows(monkeypatch, users=[admin]):
        with client.websocket_connect("/api/v1/ws/dashboard") as ws:
            ws.send_json({"action": "AUTHENTICATE", "token": _token_for(admin)})
            ws.receive_json()
            ws.receive_json()
            assert realtime_manager.get_dashboard_count() == before + 1


# ── 8. Enrolment gate ─────────────────────────────────────────────────────────


def test_registration_without_an_enrollment_key_is_refused(client):
    response = client.post("/api/v1/devices/register", json={"deviceName": "LAB1-PC99"})
    assert response.status_code == 401


def test_registration_with_a_wrong_enrollment_key_is_refused(client):
    response = client.post(
        "/api/v1/devices/register",
        json={"deviceName": "LAB1-PC99", "enrollmentKey": "definitely-not-the-key"},
    )
    assert response.status_code == 401


def test_registration_is_refused_outright_when_no_key_is_configured(client, monkeypatch):
    """Fail closed, not open.

    The old guard was ``if settings.ENROLLMENT_BOOTSTRAP_KEY:`` around the comparison, so clearing
    the variable did not disable enrolment - it disabled the CHECK. An empty environment variable is
    the most likely way for that setting to go missing, and enrolment is how a machine obtains the
    device token every other agent endpoint requires.
    """
    monkeypatch.setattr(settings, "ENROLLMENT_BOOTSTRAP_KEY", "")
    response = client.post(
        "/api/v1/devices/register",
        json={"deviceName": "LAB1-PC99", "enrollmentKey": "anything-at-all"},
    )
    assert response.status_code == 503


def test_enrollment_refusal_gives_no_oracle(client):
    """One answer for "absent" and "wrong": no signal about how close a guess was."""
    absent = client.post("/api/v1/devices/register", json={"deviceName": "x"})
    wrong = client.post("/api/v1/devices/register",
                        json={"deviceName": "x", "enrollmentKey": "definitely-not-it"})
    assert absent.status_code == wrong.status_code
    assert absent.json()["detail"] == wrong.json()["detail"]


# ── 9. Credential leakage through responses and logs ──────────────────────────


def _configured_secret_material() -> list[str]:
    """The secret VALUES currently configured, used ONLY as needles to search output for.

    They are never printed, never included in an assertion message and never written anywhere.
    Every assertion below has the form "this string does not appear in the output", so a failure
    reports which endpoint leaked and never what.
    """
    values = [
        settings.SECRET_KEY,
        settings.DEVICE_TOKEN_SECRET,
        settings.ENROLLMENT_BOOTSTRAP_KEY,
        settings.DATABASE_URL,
    ]
    return [v for v in values if v and len(v) >= 8]


def test_failed_authentication_response_contains_no_secret_material(client):
    responses = {
        "anonymous REST": client.get("/api/alerts"),
        "malformed operator token": client.get("/api/alerts",
                                               headers={"Authorization": "Bearer garbage"}),
        "anonymous agent REST": client.post("/api/v1/events", json={}),
        "malformed device token": client.post("/api/v1/events", json={},
                                              headers={"X-Device-Token": "garbage"}),
        "wrong enrolment key": client.post("/api/v1/devices/register",
                                           json={"deviceName": "x", "enrollmentKey": "no"}),
    }
    for label, response in responses.items():
        body = response.text
        for needle in _configured_secret_material():
            assert needle not in body, f"{label} response leaked configured secret material"


def test_failed_authentication_logs_contain_no_secret_material(client, caplog):
    """Server-side logs must not carry the credential either.

    A rejection is exactly the moment a developer is tempted to log "the token was X", and these
    logs are read by whoever operates the exam.
    """
    with caplog.at_level(logging.DEBUG):
        client.get("/api/alerts", headers={"Authorization": "Bearer garbage"})
        client.post("/api/v1/events", json={}, headers={"X-Device-Token": "garbage"})
        client.post("/api/v1/devices/register",
                    json={"deviceName": "x", "enrollmentKey": "a-rejected-key-value"})

    logged = "\n".join(record.getMessage() for record in caplog.records)
    for needle in _configured_secret_material():
        assert needle not in logged, "a log record leaked configured secret material"
    # The REJECTED credential must not be echoed either: an attacker's guess in the log is one more
    # copy of a near-miss, and a legitimate operator's mistyped key is still a real key.
    assert "a-rejected-key-value" not in logged
    assert "Bearer garbage" not in logged


def test_role_refusal_log_names_the_user_not_the_token(client, monkeypatch, caplog):
    """The 403 path logs an identity, which is wanted; it must not log the credential."""
    proctor = _make_user(UserRole.PROCTOR.value, username="proctor-under-test")
    token = _token_for(proctor)
    with caplog.at_level(logging.DEBUG):
        with _rows(monkeypatch, users=[proctor]):
            client.get("/api/audit-logs", headers={"Authorization": f"Bearer {token}"})
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "proctor-under-test" in logged
    assert token not in logged


def test_device_token_refusal_is_uniform_across_failure_modes(client, monkeypatch):
    """Malformed, unparseable and expired must be indistinguishable to the caller.

    Distinguishing them tells an attacker which half of a forgery attempt worked - whether the
    payload parsed, and therefore whether only the signature is left to solve. The device row is
    stubbed so every refusal here comes from the token check rather than from the lookup.
    """
    expired = create_device_token(hardware_uuid="LAB1-PC01", ttl_seconds=-60)
    with _rows(monkeypatch, devices=[_make_device("LAB1-PC01")]):
        details = {
            client.post("/api/v1/sessions/start", json={"hardwareUuid": "LAB1-PC01"},
                        headers={"X-Device-Token": t}).json()["detail"]
            for t in ["garbage", "a.b", expired]
        }
    assert details == {"Invalid or expired device token"}
