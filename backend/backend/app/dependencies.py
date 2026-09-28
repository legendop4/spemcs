"""Shared FastAPI authentication and authorization dependencies.

WHY THIS MODULE EXISTS
----------------------
Route modules previously reached into ``backend.services.auth_service`` and spelled their own
``require_role([...])`` lists inline, which is how the two mistakes this module prevents happened:

1. ``routes/deployment.py`` depended on ``get_current_user``, which returns ``None`` when no
   credentials are supplied, and then never looked at the result. The endpoint read as
   authenticated - it had a ``current_user`` parameter and a docstring saying "Requires admin
   privileges" - while accepting anonymous requests. A dependency whose contract is "may return
   None" must never be the only gate on a route, so it is deliberately NOT re-exported here.

2. Role lists written by hand drift. ``["admin", "proctor"]`` and ``["proctor", "admin"]`` and
   ``["Admin"]`` all appeared in the codebase, and a typo in one of them fails open in the sense
   that matters: it never raises, it just admits or refuses the wrong people.

So this module exports exactly three user-facing gates - :data:`require_admin`,
:data:`require_staff`, :data:`require_authenticated` - two machine gates, :func:`require_device` for
an enrolled endpoint and :func:`require_enrollment_key` for one that has not enrolled yet. Routes
import from here and nowhere else.

DISTINCT TRUST DOMAINS
----------------------
Operator identity (a human with a password, carrying a JWT signed by ``SECRET_KEY``) and device
identity (an enrolled endpoint carrying an HMAC token keyed by ``DEVICE_TOKEN_SECRET``) are
separate credential types with separate secrets, and neither is accepted where the other is
required. A device token must not open a management endpoint, and an operator JWT must not be
usable to submit violation events attributed to a workstation.
"""

from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.app.config import settings
from backend.models.user import User, UserRole
from backend.services.auth_service import require_auth, require_role, verify_device_token

logger = logging.getLogger(__name__)

# ── Operator (human) gates ────────────────────────────────────────────────────
# Spelled once, from the UserRole enum rather than string literals, so that adding a role to the
# model cannot silently leave these lists behind.

#: Any authenticated operator. 401 when unauthenticated.
require_authenticated = require_auth

#: Read access to examination data: administrators and proctors. 401/403.
require_staff = require_role([UserRole.ADMIN.value, UserRole.PROCTOR.value])

#: State-changing and privileged operations: administrators only. 401/403.
require_admin = require_role([UserRole.ADMIN.value])


# ── Device (machine) gate ─────────────────────────────────────────────────────

_device_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class DeviceIdentity:
    """The verified subject of a device enrolment token.

    ``hardware_uuid`` is the authenticated claim: it came out of a payload whose HMAC was checked
    against ``DEVICE_TOKEN_SECRET``, not out of the request body. Routes must compare it against
    whatever device the request *claims* to act for; that comparison is the ownership check, and
    without it a valid token for workstation A can act as workstation B.
    """

    hardware_uuid: str
    token_id: Optional[str]
    roles: tuple[str, ...]


def require_device(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_device_bearer),
    x_device_token: Optional[str] = Header(default=None, alias="X-Device-Token"),
) -> DeviceIdentity:
    """Require a valid HMAC device enrolment token. Raises 401 otherwise.

    Accepts the token either as ``Authorization: Bearer <token>`` or as ``X-Device-Token``. Both
    are supported because the agent's HTTP adapters and its WebSocket client were built at
    different times; the header form is what the agent sends, and the bearer form keeps the
    endpoint usable from ordinary tooling.

    The 401 detail is deliberately uniform across "absent", "malformed", "bad signature" and
    "expired". Distinguishing them tells an attacker which half of a forgery attempt worked.
    """
    raw = x_device_token or (credentials.credentials if credentials else None)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_device_token(raw)
    if not payload:
        # verify_device_token already logged the specific reason server-side, without the token.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired device token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    hardware_uuid = payload.get("hardware_uuid")
    if not hardware_uuid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired device token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    roles = payload.get("roles") or []
    return DeviceIdentity(
        hardware_uuid=str(hardware_uuid),
        token_id=payload.get("token_id"),
        roles=tuple(str(r) for r in roles),
    )


def assert_device_owns(device: DeviceIdentity, claimed_hardware_uuid: Optional[str],
                       *, what: str) -> None:
    """Refuse a request whose device token does not match the device it claims to act for.

    This is the ownership half of device authentication and is separate from
    :func:`require_device` on purpose: authentication answers "is this a real endpoint", ownership
    answers "is this THAT endpoint". Collapsing them is how an authenticated-but-unauthorized
    request gets through. 403 rather than 404, because the caller proved an identity - it simply
    is not the identity that would permit this - and 404 would additionally leak whether the
    other device exists.
    """
    if not claimed_hardware_uuid:
        return
    if str(claimed_hardware_uuid) != device.hardware_uuid:
        logger.warning(
            "Device %s attempted to act on %s belonging to a different device",
            device.hardware_uuid, what,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Device token is not authorized for this {what}",
        )


# ── Enrolment (pre-device) gate ───────────────────────────────────────────────
# A FOURTH credential position, and the narrowest one. A workstation that has not enrolled yet holds
# neither an operator JWT nor a device token - a device token is what enrolment *issues* - so an
# endpoint it must reach before enrolling cannot be gated by either. What it does hold is the
# bootstrap enrolment key, and presenting that key is already exactly what entitles a machine to
# enrol (see routes/agent_api.py::register_device). So the key is the right authenticator here, and
# no new secret is introduced.
#
# The scope this licenses is deliberately tiny: it must never be accepted on a management route, and
# it must never substitute for require_device on a route that attributes anything to a specific
# workstation. The key identifies an *installation*, not a machine - every workstation in the
# deployment holds the same one - so it can authorise "tell me which labs exist to enrol into" and
# nothing that depends on knowing *which* endpoint is asking.


def require_enrollment_key(
    x_enrollment_key: Optional[str] = Header(default=None, alias="X-Enrollment-Key"),
) -> None:
    """Require the bootstrap enrolment key. Raises 503 when unconfigured, 401 when wrong.

    The unset case is 503 and refuses the request, matching ``register_device``: the earlier form of
    that check wrapped the comparison in ``if settings.ENROLLMENT_BOOTSTRAP_KEY:``, so clearing the
    variable disabled the CHECK rather than the feature. An empty environment variable is the most
    likely way for this setting to go missing, so unset must mean closed, not open.

    Compared with :func:`hmac.compare_digest` rather than ``==``: the key is a fixed secret that a
    caller may probe repeatedly, which is the exact shape a timing side channel needs.
    """
    expected = (settings.ENROLLMENT_BOOTSTRAP_KEY or "").strip()
    if not expected:
        logger.error("Enrolment request refused: ENROLLMENT_BOOTSTRAP_KEY is not configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Device enrollment is not configured on this server",
        )

    if not x_enrollment_key or not hmac.compare_digest(
        x_enrollment_key.encode("utf-8"),
        expected.encode("utf-8"),
    ):
        logger.warning("Enrolment request rejected: missing or invalid bootstrap enrollment key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing enrollment bootstrap key",
        )


__all__ = [
    "DeviceIdentity",
    "User",
    "assert_device_owns",
    "require_admin",
    "require_authenticated",
    "require_device",
    "require_enrollment_key",
    "require_staff",
]
