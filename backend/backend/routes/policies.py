"""Policy and VendorProfile management endpoints."""

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.schemas.policy import (
    NetworkPolicyRead,
    PolicyCompileRequest,
    VendorProfileCreate,
    VendorProfileRead,
    VendorProfileUpdate,
)
from backend.services import policy_service
from backend.services.auth_service import require_role
from backend.services.policy_compiler import PolicyCompilationError
from backend.services.policy_signer import (
    PolicySigner,
    generate_development_keypair,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/policies", tags=["policies"])

# Singleton development signer for dev/test compilation
_dev_priv, _ = generate_development_keypair()
_dev_signer = PolicySigner(private_key=_dev_priv, key_id="dev-key-1")


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
    payload: PolicyCompileRequest,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    """Compiles, signs, and persists a NetworkPolicy for an exam."""
    try:
        policy = policy_service.compile_and_persist_exam_policy(
            db=db,
            exam_id=exam_id,
            version=payload.version,
            management_server=payload.management_server,
            not_before=payload.not_before,
            expires_at=payload.expires_at,
            signer=_dev_signer,
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
    from backend.services.policy_signer import create_canonical_payload
    from backend.websocket.manager import realtime_manager

    # Reconstruct the exact canonical dictionary signed by server
    payload_dict = create_canonical_payload(
        exam_id=policy.exam_id,
        policy_id=policy.policy_id,
        version=policy.version,
        vendor_profile_id=policy.vendor_profile_id,
        allowed_destinations=policy.allowed_destinations,
        management_server=policy.management_server,
        not_before=policy.not_before,
        expires_at=policy.expires_at,
        key_id="dev-key-1",
    )
    raw_policy_json = canonicalize(payload_dict)

    sent = await realtime_manager.send_signed_policy_to_device(
        hardware_uuid=device_hardware_uuid,
        raw_policy_json=raw_policy_json,
        signature_base64=policy.signature,
    )

    if not sent:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Device '{device_hardware_uuid}' is not connected to WebSocket",
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
    from backend.services.policy_signer import create_canonical_payload
    from backend.websocket.manager import realtime_manager

    payload_dict = create_canonical_payload(
        exam_id=policy.exam_id,
        policy_id=policy.policy_id,
        version=policy.version,
        vendor_profile_id=policy.vendor_profile_id,
        allowed_destinations=policy.allowed_destinations,
        management_server=policy.management_server,
        not_before=policy.not_before,
        expires_at=policy.expires_at,
        key_id="dev-key-1",
    )
    raw_policy_json = canonicalize(payload_dict)

    sent = await realtime_manager.send_signed_policy_to_device(
        hardware_uuid=device_hardware_uuid,
        raw_policy_json=raw_policy_json,
        signature_base64=policy.signature,
        message_type="UPDATE_EXAM_POLICY",
    )

    if not sent:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Device '{device_hardware_uuid}' is not connected to WebSocket",
        )

    return {
        "status": "SENT",
        "message_type": "UPDATE_EXAM_POLICY",
        "exam_id": str(exam_id),
        "device_hardware_uuid": device_hardware_uuid,
        "policy_id": str(policy.policy_id),
        "version": policy.version,
    }
