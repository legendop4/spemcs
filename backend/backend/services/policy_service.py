"""SPEMCS Policy Service.

Exposes:
- VendorProfile CRUD operations
- Policy compilation engine
- Cryptographic signing & verification layer
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.models.exam import Exam
from backend.models.policy import NetworkPolicy, VendorProfile
from backend.schemas.policy import VendorProfileCreate, VendorProfileUpdate

from .canonical_json import canonicalize, canonicalize_to_bytes
from .policy_compiler import (
    InvalidDomainError,
    InvalidNetworkAddressError,
    InvalidPortError,
    InvalidValidityWindowError,
    MissingConfigurationError,
    PolicyCompilationError,
    compile_exam_policy,
    normalize_domain_list,
    normalize_ip_network_list,
    normalize_ports,
    validate_and_normalize_domain,
    validate_and_normalize_ip_network,
    validate_management_server,
    validate_port,
    validate_validity_window,
)
from .policy_signer import (
    CURRENT_SCHEMA_VERSION,
    PSS_SALT_LENGTH_BYTES,
    RSA_KEY_SIZE_BITS,
    ExpiredPolicyError,
    InvalidSignatureError,
    InvalidValidityWindowError as SignerValidityWindowError,
    KeyMismatchError,
    MalformedPayloadError,
    NotYetValidPolicyError,
    PolicySigner,
    PolicyVerificationError,
    PolicyVerifier,
    UnsupportedSchemaVersionError,
    create_canonical_payload,
    export_public_key_pem,
    generate_development_keypair,
    load_public_key_pem,
)

# ==============================================================================
# VendorProfile CRUD Operations
# ==============================================================================
def create_vendor_profile(db: Session, data: VendorProfileCreate) -> VendorProfile:
    """Creates a new VendorProfile in the database."""
    profile = VendorProfile(
        vendor_name=data.vendor_name,
        description=data.description,
        required_domains=data.required_domains,
        approved_ip_ranges=data.approved_ip_ranges,
        required_tcp_ports=data.required_tcp_ports,
        required_udp_ports=data.required_udp_ports,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


def get_vendor_profile(db: Session, vendor_id: UUID) -> Optional[VendorProfile]:
    """Retrieves a VendorProfile by its UUID."""
    return db.query(VendorProfile).filter(VendorProfile.vendor_id == vendor_id).first()


def get_vendor_profile_by_name(db: Session, vendor_name: str) -> Optional[VendorProfile]:
    """Retrieves a VendorProfile by its unique name."""
    return db.query(VendorProfile).filter(VendorProfile.vendor_name == vendor_name).first()


def list_vendor_profiles(db: Session, skip: int = 0, limit: int = 100) -> List[VendorProfile]:
    """Lists VendorProfiles with pagination."""
    return db.query(VendorProfile).order_by(VendorProfile.created_at.desc()).offset(skip).limit(limit).all()


def update_vendor_profile(db: Session, vendor_id: UUID, data: VendorProfileUpdate) -> Optional[VendorProfile]:
    """Updates an existing VendorProfile."""
    profile = get_vendor_profile(db, vendor_id)
    if not profile:
        return None

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(profile, field, value)

    db.commit()
    db.refresh(profile)
    return profile


def delete_vendor_profile(db: Session, vendor_id: UUID) -> bool:
    """Deletes a VendorProfile if it exists."""
    profile = get_vendor_profile(db, vendor_id)
    if not profile:
        return False
    db.delete(profile)
    db.commit()
    return True


# ==============================================================================
# Policy Compilation & Signing Service
# ==============================================================================
def compile_and_persist_exam_policy(
    db: Session,
    exam_id: UUID,
    version: int,
    management_server: Dict[str, Any],
    not_before: datetime,
    expires_at: datetime,
    signer: PolicySigner,
    vendor_profile_id: Optional[UUID] = None,
    resolved_destinations: Optional[List[Dict[str, Any]]] = None,
) -> NetworkPolicy:
    """Compiles, signs, and persists a NetworkPolicy for an examination."""
    # 1. Fetch Exam
    exam = db.query(Exam).filter(Exam.exam_id == exam_id).first()
    if not exam:
        raise PolicyCompilationError(f"Exam {exam_id} not found")

    # 2. Resolve VendorProfile
    vp = None
    target_vp_id = vendor_profile_id or exam.vendor_profile_id
    if target_vp_id:
        vp = get_vendor_profile(db, target_vp_id)
        if not vp:
            raise PolicyCompilationError(f"VendorProfile {target_vp_id} not found")

    # 3. Generate new policy UUID
    policy_id = uuid.uuid4()

    # 4. Compile Deterministic Policy Payload
    compiled_payload = compile_exam_policy(
        exam_id=exam_id,
        version=version,
        vendor_profile=vp,
        management_server=management_server,
        not_before=not_before,
        expires_at=expires_at,
        policy_id=policy_id,
        resolved_destinations=resolved_destinations,
        key_id=signer.key_id,
    )

    # 5. Sign Canonical Payload using M2 Signer
    signature_b64 = signer.sign_payload(compiled_payload)

    # 6. Persist to NetworkPolicy table
    net_policy = NetworkPolicy(
        policy_id=policy_id,
        exam_id=exam_id,
        version=version,
        vendor_profile_id=vp.vendor_id if vp else None,
        allowed_destinations=compiled_payload["allowed_destinations"],
        management_server=compiled_payload["management_server"],
        not_before=datetime.fromisoformat(compiled_payload["not_before"].replace("Z", "+00:00")),
        expires_at=datetime.fromisoformat(compiled_payload["expires_at"].replace("Z", "+00:00")),
        signature=signature_b64,
    )
    db.add(net_policy)
    db.commit()
    db.refresh(net_policy)

    return net_policy


def get_latest_exam_policy(db: Session, exam_id: UUID) -> Optional[NetworkPolicy]:
    """Retrieves the highest-version NetworkPolicy for an exam."""
    return (
        db.query(NetworkPolicy)
        .filter(NetworkPolicy.exam_id == exam_id)
        .order_by(NetworkPolicy.version.desc())
        .first()
    )


__all__ = [
    # Canonicalization
    "canonicalize",
    "canonicalize_to_bytes",
    # Compiler
    "compile_exam_policy",
    "validate_and_normalize_domain",
    "normalize_domain_list",
    "validate_and_normalize_ip_network",
    "normalize_ip_network_list",
    "validate_port",
    "normalize_ports",
    "validate_management_server",
    "validate_validity_window",
    # Compiler Exceptions
    "PolicyCompilationError",
    "InvalidDomainError",
    "InvalidNetworkAddressError",
    "InvalidPortError",
    "InvalidValidityWindowError",
    "MissingConfigurationError",
    # Crypto
    "PolicySigner",
    "PolicyVerifier",
    "PolicyVerificationError",
    "MalformedPayloadError",
    "UnsupportedSchemaVersionError",
    "ExpiredPolicyError",
    "NotYetValidPolicyError",
    "InvalidSignatureError",
    "KeyMismatchError",
    "create_canonical_payload",
    "generate_development_keypair",
    "export_public_key_pem",
    "load_public_key_pem",
    "CURRENT_SCHEMA_VERSION",
    "PSS_SALT_LENGTH_BYTES",
    "RSA_KEY_SIZE_BITS",
    # Service CRUD & Compilation
    "create_vendor_profile",
    "get_vendor_profile",
    "get_vendor_profile_by_name",
    "list_vendor_profiles",
    "update_vendor_profile",
    "delete_vendor_profile",
    "compile_and_persist_exam_policy",
    "get_latest_exam_policy",
]
