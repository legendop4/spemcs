"""Policy and VendorProfile management endpoints."""

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.schemas.policy import (
    DevicePolicyStateRead,
    NetworkPolicyRead,
    PolicyCompileRequest,
    SigningKeyRead,
    SigningKeyRevokeRequest,
    SigningKeyRotateRequest,
    SigningKeyringRead,
    VendorProfileCreate,
    VendorProfileRead,
    VendorProfileUpdate,
)
from backend.services import device_policy_state_service as dps
from backend.services import policy_service
from backend.services.auth_service import require_role
from backend.services.policy_compiler import PolicyCompilationError
from backend.services.signing_key_manager import (
    SigningKeyManager,
    SigningKeyStateError,
    SigningKeyUnavailableError,
    get_signing_key_manager,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/policies", tags=["policies"])


def signing_keys() -> SigningKeyManager:
    """FastAPI dependency yielding the process-wide signing key manager.

    A dependency rather than a module-level singleton so the key is created on first use
    instead of at import. The previous code generated a fresh RSA keypair while this module was
    being imported, which meant every process start - including a test run, an autoreload, and
    each additional uvicorn worker - silently replaced the key that had already signed and
    distributed policies. See services/signing_key_manager.py.
    """
    return get_signing_key_manager()


def _unavailable(err: SigningKeyUnavailableError) -> HTTPException:
    """Maps a missing/unusable signing key to 503.

    503 rather than 500: the request was valid and retrying after the deployment is fixed will
    work. The message is the manager's own remediation text, which names paths and settings but
    never key material.
    """
    logger.error("Policy signing key unavailable: %s", err)
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(err))


def _record_distribution_state(
    db: Session,
    *,
    exam_id: UUID,
    hardware_uuid: str,
    policy_id: UUID,
    status_value: str,
    last_error: Optional[str] = None,
) -> None:
    """Record the outcome of a distribution attempt, without letting the bookkeeping break it.

    A failure to write the state row is logged and swallowed, and that is safe in the only
    direction that matters: the activation precondition treats "no state row" as "not armed", so
    a lost write refuses an exam rather than starting one that is not locked down. Re-raising
    would instead turn a *successful* policy hand-off into a 500 and tell the operator the
    opposite of what happened.
    """
    try:
        dps.record_state_for_hardware_uuid(
            db,
            exam_id=exam_id,
            hardware_uuid=hardware_uuid,
            policy_id=policy_id,
            status=status_value,
            last_error=last_error,
        )
    except Exception:  # pragma: no cover - defensive; exercised only by a database fault
        db.rollback()
        logger.exception(
            "Failed to record %s enforcement state for device %s on exam %s",
            status_value, hardware_uuid, exam_id,
        )


# ==============================================================================
# Signing Key Lifecycle Endpoints
# ==============================================================================
# AUTHORIZATION NOTE
# The two GET endpoints publish PUBLIC key material and are reachable without a user session,
# because the consumer is the endpoint agent service - a machine account with no operator
# credentials, which must be able to populate its trust store before any exam starts. Nothing
# secret is exposed: SigningKeyRead has no field capable of holding a private key.
#
# What these endpoints do NOT provide is proof of origin. An agent that fetches its trust
# anchors over plaintext HTTP will trust whatever a network attacker returns, so the transport
# must be HTTPS with a verified hostname; the agent's ManagementConnectivityVerifier enforces
# StrictHttps for any https:// backend URL. Rotation and revocation change server state and are
# therefore admin-only.


@router.get("/signing-key/public", response_model=SigningKeyRead)
def get_signing_public_key(keys: SigningKeyManager = Depends(signing_keys)):
    """Export the ACTIVE signing public key for an agent's trusted key store.

    Kept for agents that only need the current key. Prefer /signing-key/keyring, which also
    carries retired keys (needed to verify policies issued before a rotation) and revocations.
    """
    try:
        return SigningKeyRead(**keys.active_descriptor().to_public_dict())
    except SigningKeyUnavailableError as err:
        raise _unavailable(err)


@router.get("/signing-key/keyring", response_model=SigningKeyringRead)
def get_signing_keyring(keys: SigningKeyManager = Depends(signing_keys)):
    """Export every signing key this server has issued, with its lifecycle state."""
    try:
        keyring = keys.keyring()
        return SigningKeyringRead(
            active_key_id=keys.active_key_id(),
            keys=[SigningKeyRead(**d.to_public_dict()) for d in keyring],
            revoked_key_ids=[d.key_id for d in keyring if d.is_revoked],
            ephemeral=keys.is_ephemeral,
        )
    except SigningKeyUnavailableError as err:
        raise _unavailable(err)


@router.post("/signing-key/rotate", response_model=SigningKeyringRead)
def rotate_signing_key(
    payload: Optional[SigningKeyRotateRequest] = None,
    keys: SigningKeyManager = Depends(signing_keys),
    _user=Depends(require_role(["admin"])),
):
    """Generate a new active signing key and retire the current one.

    Retirement is not revocation: the outgoing key stays published so policies it already
    signed keep verifying. Newly compiled policies use the new key, and agents pick it up on
    their next keyring fetch.
    """
    try:
        rotated = keys.rotate(reason=(payload.reason if payload else None))
        keyring = keys.keyring()
        logger.info("Signing key rotated to '%s' by an administrator.", rotated.key_id)
        return SigningKeyringRead(
            active_key_id=rotated.key_id,
            keys=[SigningKeyRead(**d.to_public_dict()) for d in keyring],
            revoked_key_ids=[d.key_id for d in keyring if d.is_revoked],
            ephemeral=keys.is_ephemeral,
        )
    except SigningKeyUnavailableError as err:
        raise _unavailable(err)
    except SigningKeyStateError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err))


@router.post("/signing-key/{key_id}/revoke", response_model=SigningKeyringRead)
def revoke_signing_key(
    key_id: str,
    payload: SigningKeyRevokeRequest,
    keys: SigningKeyManager = Depends(signing_keys),
    _user=Depends(require_role(["admin"])),
):
    """Mark a signing key untrusted so agents reject everything it signed.

    Use this for suspected key compromise, not for routine replacement - revocation
    invalidates policies that are already deployed, so any exam still relying on a policy
    signed by this key must have that policy recompiled.
    """
    try:
        revoked = keys.revoke(key_id, payload.reason)
        keyring = keys.keyring()
        logger.warning(
            "Signing key '%s' revoked by an administrator. Reason: %s", revoked.key_id, payload.reason
        )
        return SigningKeyringRead(
            active_key_id=keys.active_key_id(),
            keys=[SigningKeyRead(**d.to_public_dict()) for d in keyring],
            revoked_key_ids=[d.key_id for d in keyring if d.is_revoked],
            ephemeral=keys.is_ephemeral,
        )
    except SigningKeyStateError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except SigningKeyUnavailableError as err:
        raise _unavailable(err)


# ==============================================================================
# VendorProfile Endpoints
# ==============================================================================
@router.get("/vendors", response_model=List[VendorProfileRead])
def list_vendor_profiles(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """List all vendor profiles."""
    return policy_service.list_vendor_profiles(db, skip=skip, limit=limit)


@router.post("/vendors", response_model=VendorProfileRead, status_code=status.HTTP_201_CREATED)
def create_vendor_profile(
    payload: VendorProfileCreate,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    """Create a new vendor profile."""
    existing = policy_service.get_vendor_profile_by_name(db, payload.vendor_name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Vendor profile '{payload.vendor_name}' already exists",
        )
    return policy_service.create_vendor_profile(db, payload)


@router.get("/vendors/{vendor_id}", response_model=VendorProfileRead)
def get_vendor_profile(
    vendor_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Get a vendor profile by ID."""
    profile = policy_service.get_vendor_profile(db, vendor_id)
    if not profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor profile not found")
    return profile


@router.put("/vendors/{vendor_id}", response_model=VendorProfileRead)
def update_vendor_profile(
    vendor_id: UUID,
    payload: VendorProfileUpdate,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    """Update a vendor profile."""
    updated = policy_service.update_vendor_profile(db, vendor_id, payload)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor profile not found")
    return updated


@router.delete("/vendors/{vendor_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vendor_profile(
    vendor_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    """Delete a vendor profile."""
    success = policy_service.delete_vendor_profile(db, vendor_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor profile not found")
    return None


# ==============================================================================
# Policy Compilation Endpoints
# ==============================================================================
@router.post("/compile/{exam_id}", response_model=NetworkPolicyRead, status_code=status.HTTP_201_CREATED)
def compile_exam_policy(
    exam_id: UUID,
    payload: Optional[PolicyCompileRequest] = None,
    db: Session = Depends(get_db),
    keys: SigningKeyManager = Depends(signing_keys),
    _user=Depends(require_role(["admin"])),
):
    """Compiles, signs, and persists a NetworkPolicy for an exam."""
    from datetime import datetime, timedelta, timezone

    if payload is None:
        payload = PolicyCompileRequest()

    now = datetime.now(timezone.utc)
    mgmt = payload.management_server or {
        "ip_addresses": ["127.0.0.1"],
        "port": 8002,
        "use_tls": False,
    }
    nb = payload.not_before or now
    exp = payload.expires_at or (now + timedelta(hours=8))

    # Resolved before any database work: if the signing key is unusable, compiling and
    # persisting a policy row we cannot sign would leave an unusable policy behind for a later
    # distribution attempt to trip over.
    try:
        signer = keys.active_signer()
    except SigningKeyUnavailableError as err:
        raise _unavailable(err)

    try:
        policy = policy_service.compile_and_persist_exam_policy(
            db=db,
            exam_id=exam_id,
            version=payload.version or 1,
            management_server=mgmt,
            not_before=nb,
            expires_at=exp,
            signer=signer,
            vendor_profile_id=payload.vendor_profile_id,
            resolved_destinations=payload.resolved_destinations,
        )
        return policy
    except PolicyCompilationError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except Exception as err:
        logger.exception(f"Failed to compile policy for exam {exam_id}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))


@router.get("/exam/{exam_id}", response_model=NetworkPolicyRead)
def get_latest_exam_policy(
    exam_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Get the latest compiled NetworkPolicy for an exam."""
    policy = policy_service.get_latest_exam_policy(db, exam_id)
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No policy compiled for this exam")
    return policy


@router.post("/distribute/{exam_id}/{device_hardware_uuid}")
async def distribute_policy_to_device(
    exam_id: UUID,
    device_hardware_uuid: str,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Distribute the latest signed policy for an exam to a specific connected endpoint."""
    policy = policy_service.get_latest_exam_policy(db, exam_id)
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No policy found for this exam")

    from backend.services.canonical_json import canonicalize
    from backend.websocket.manager import realtime_manager

    # Reconstruct the exact canonical dictionary signed by the server. key_id,
    # schema_version and approved_browser all come from the persisted row - never from a
    # constant - so the bytes are identical to what was signed.
    try:
        payload_dict = policy_service.rebuild_signed_payload(policy)
    except PolicyCompilationError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err))
    raw_policy_json = canonicalize(payload_dict)

    sent = await realtime_manager.send_signed_policy_to_device(
        hardware_uuid=device_hardware_uuid,
        raw_policy_json=raw_policy_json,
        signature_base64=policy.signature,
    )

    if not sent:
        # Recorded before raising, so the refusal is visible to the activation precondition and to
        # the dashboard rather than existing only in this 503 the operator may not be watching for.
        _record_distribution_state(
            db,
            exam_id=exam_id,
            hardware_uuid=device_hardware_uuid,
            policy_id=policy.policy_id,
            status_value=dps.STATUS_FAILED,
            last_error="Device is not connected to the agent WebSocket",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Device '{device_hardware_uuid}' is not connected to WebSocket",
        )

    # APPLYING, not APPLIED: the bytes left the server. Whether enforcement is live is a claim
    # only the endpoint can make, and it makes it over POLICY_VALIDATION_RESULT.
    _record_distribution_state(
        db,
        exam_id=exam_id,
        hardware_uuid=device_hardware_uuid,
        policy_id=policy.policy_id,
        status_value=dps.STATUS_APPLYING,
    )

    return {
        "status": "SENT",
        "exam_id": str(exam_id),
        "device_hardware_uuid": device_hardware_uuid,
        "policy_id": str(policy.policy_id),
        "version": policy.version,
    }


@router.post("/update/{exam_id}/{device_hardware_uuid}")
async def distribute_policy_update_to_device(
    exam_id: UUID,
    device_hardware_uuid: str,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    """Distribute a compiled policy update (as UPDATE_EXAM_POLICY) for an exam to a connected endpoint."""
    policy = policy_service.get_latest_exam_policy(db, exam_id)
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No policy found for this exam")

    from backend.services.canonical_json import canonicalize
    from backend.websocket.manager import realtime_manager

    try:
        payload_dict = policy_service.rebuild_signed_payload(policy)
    except PolicyCompilationError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err))
    raw_policy_json = canonicalize(payload_dict)

    sent = await realtime_manager.send_signed_policy_to_device(
        hardware_uuid=device_hardware_uuid,
        raw_policy_json=raw_policy_json,
        signature_base64=policy.signature,
        message_type="UPDATE_EXAM_POLICY",
    )

    if not sent:
        _record_distribution_state(
            db,
            exam_id=exam_id,
            hardware_uuid=device_hardware_uuid,
            policy_id=policy.policy_id,
            status_value=dps.STATUS_FAILED,
            last_error="Device is not connected to the agent WebSocket",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Device '{device_hardware_uuid}' is not connected to WebSocket",
        )

    # A dynamic update supersedes whatever the device is currently enforcing, so its state goes
    # back to APPLYING until the endpoint reports the swap succeeded. Leaving an earlier APPLIED
    # in place would claim the device is enforcing a policy version it has not installed.
    _record_distribution_state(
        db,
        exam_id=exam_id,
        hardware_uuid=device_hardware_uuid,
        policy_id=policy.policy_id,
        status_value=dps.STATUS_APPLYING,
    )

    return {
        "status": "SENT",
        "message_type": "UPDATE_EXAM_POLICY",
        "exam_id": str(exam_id),
        "device_hardware_uuid": device_hardware_uuid,
        "policy_id": str(policy.policy_id),
        "version": policy.version,
    }


# ==============================================================================
# Per-device enforcement state
# ==============================================================================
# These are the read side of `device_policy_states`. Until P1-R nothing wrote that table and
# nothing read it, so the only per-device enforcement signal a proctor had was a toast in the
# browser tab that happened to issue the distribution - lost on refresh, invisible to anyone else,
# and gone entirely if the exam was activated from a different machine.


def _serialize_state(state, device) -> DevicePolicyStateRead:
    return DevicePolicyStateRead(
        id=state.id,
        exam_id=state.exam_id,
        device_id=state.device_id,
        policy_id=state.policy_id,
        status=state.status,
        armed=dps.is_armed(state.status),
        rules_installed=state.rules_installed or 0,
        last_error=state.last_error,
        applied_at=state.applied_at,
        updated_at=state.updated_at,
        device_name=device.device_name if device else None,
        hardware_uuid=device.hardware_uuid if device else None,
    )


@router.get("/exam/{exam_id}/device-states", response_model=List[DevicePolicyStateRead])
def list_exam_device_policy_states(
    exam_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Per-device network enforcement state for an exam, most recently updated first."""
    from backend.models.device import Device

    states = dps.get_states_for_exam(db, exam_id)
    device_ids = [s.device_id for s in states]
    devices = (
        db.query(Device).filter(Device.device_id.in_(device_ids)).all() if device_ids else []
    )
    device_map = {d.device_id: d for d in devices}
    return [_serialize_state(s, device_map.get(s.device_id)) for s in states]


@router.get("/exam/{exam_id}/device-states/{device_id}", response_model=DevicePolicyStateRead)
def get_exam_device_policy_state(
    exam_id: UUID,
    device_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Network enforcement state for one workstation in one exam."""
    from backend.models.device import Device

    state = dps.get_state(db, exam_id, device_id)
    if state is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No enforcement state recorded for this device on this exam",
        )
    device = db.query(Device).filter(Device.device_id == device_id).first()
    return _serialize_state(state, device)
