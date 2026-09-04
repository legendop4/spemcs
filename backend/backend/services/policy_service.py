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
from .destination_resolver import TrustedDestinationResolver, build_destination_resolver
from .policy_compiler import (
    InvalidApprovedBrowserError,
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
    validate_and_normalize_approved_browser,
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
    SUPPORTED_APPROVED_BROWSERS,
    ExpiredPolicyError,
    InvalidSignatureError,
    InvalidValidityWindowError as SignerValidityWindowError,
    KeyMismatchError,
    MalformedPayloadError,
    NotYetValidPolicyError,
    PolicySigner,
    PolicyVerificationError,
    PolicyVerifier,
    UnsupportedApprovedBrowserError,
    UnsupportedSchemaVersionError,
    create_canonical_payload,
    export_public_key_pem,
    generate_development_keypair,
    load_public_key_pem,
    normalize_approved_browser,
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
    approved_browser: Optional[str] = None,
    destination_resolver: Optional[TrustedDestinationResolver] = None,
) -> NetworkPolicy:
    """Compiles, signs, and persists a NetworkPolicy for an examination.

    `approved_browser` defaults to the exam's own configured browser. It is accepted as an
    override only so callers that already validated a value can pass it through; it is
    re-validated by the compiler either way. It is never silently defaulted to a constant -
    an exam with no approved browser is a configuration error, not a policy to be signed.

    `resolved_destinations` is a misnomer inherited from the original API and now means
    "additional destinations to resolve": entries carry a name, domains and ports, and this
    function resolves the domains itself. Addresses supplied by the caller are rejected outright.
    Requirement 3: the addresses in a signed policy become firewall allow rules verbatim, so they
    may only come from server-side vendor profile data or from this server's own trusted DNS
    resolution.

    `destination_resolver` is injectable so tests can supply a static resolver; in production it
    is built from settings.
    """
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

    # 2b. Resolve the signed browser identity from the exam record.
    # Requirement 4/5: the endpoint scopes vendor allow rules to this browser's executable,
    # so it must come from trusted server-side state and travel inside the signed bytes.
    effective_browser = validate_and_normalize_approved_browser(
        approved_browser if approved_browser is not None else exam.approved_browser
    )

    # 3. Generate new policy UUID
    policy_id = uuid.uuid4()

    # 4. Resolve the trusted allowlist, then compile.
    # Resolution is separated from compilation because it performs DNS I/O: the compiler stays
    # pure and deterministic, and every address it signs has already been obtained from a trusted
    # source and checked against the address-safety policy (which the compiler then re-checks).
    resolver = destination_resolver or build_destination_resolver()
    allowed_destinations = resolver.build_allowlist(
        vendor_profile=vp,
        requested_destinations=resolved_destinations,
    )

    # 5. Compile Deterministic Policy Payload
    compiled_payload = compile_exam_policy(
        exam_id=exam_id,
        version=version,
        vendor_profile=vp,
        management_server=management_server,
        not_before=not_before,
        expires_at=expires_at,
        approved_browser=effective_browser,
        policy_id=policy_id,
        allowed_destinations=allowed_destinations,
        key_id=signer.key_id,
        schema_version=CURRENT_SCHEMA_VERSION,
    )

    # 6. Sign Canonical Payload using M2 Signer
    signature_b64 = signer.sign_payload(compiled_payload)

    # 7. Persist to NetworkPolicy table.
    # Every signed field is persisted so /distribute can rebuild byte-identical canonical
    # bytes later; nothing about the signed envelope is reconstructed from a constant.
    net_policy = NetworkPolicy(
        policy_id=policy_id,
        exam_id=exam_id,
        version=version,
        vendor_profile_id=vp.vendor_id if vp else None,
        approved_browser=compiled_payload["approved_browser"],
        allowed_destinations=compiled_payload["allowed_destinations"],
        management_server=compiled_payload["management_server"],
        not_before=datetime.fromisoformat(compiled_payload["not_before"].replace("Z", "+00:00")),
        expires_at=datetime.fromisoformat(compiled_payload["expires_at"].replace("Z", "+00:00")),
        key_id=compiled_payload["key_id"],
        schema_version=compiled_payload["schema_version"],
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


def rebuild_signed_payload(policy: NetworkPolicy) -> Dict[str, Any]:
    """Rebuilds the exact canonical dictionary that was signed for a persisted policy.

    Single source of truth for policy distribution. Every field is read back from the
    persisted row - in particular `key_id`, `schema_version`, and `approved_browser` - so
    the canonicalized bytes are byte-identical to what was signed and the stored signature
    still verifies. Hardcoding any of these at distribution time would silently break
    verification the moment a key is rotated or the schema is bumped.

    Raises:
        PolicyCompilationError: if the row predates the signed-browser/key columns and
            therefore cannot be faithfully reconstructed. Distributing a guessed payload
            would ship an unverifiable policy, so this fails loudly instead.
    """
    if not policy.key_id:
        raise PolicyCompilationError(
            f"Policy {policy.policy_id} has no persisted key_id; its signature cannot be "
            "faithfully reproduced. Recompile the policy for this exam."
        )
    if not policy.approved_browser:
        raise PolicyCompilationError(
            f"Policy {policy.policy_id} has no persisted approved_browser; its signature "
            "cannot be faithfully reproduced. Recompile the policy for this exam."
        )

    return create_canonical_payload(
        exam_id=policy.exam_id,
        policy_id=policy.policy_id,
        version=policy.version,
        vendor_profile_id=policy.vendor_profile_id,
        allowed_destinations=policy.allowed_destinations,
        management_server=policy.management_server,
        not_before=policy.not_before,
        expires_at=policy.expires_at,
        approved_browser=policy.approved_browser,
        key_id=policy.key_id,
        schema_version=policy.schema_version or CURRENT_SCHEMA_VERSION,
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
    "validate_and_normalize_approved_browser",
    # Compiler Exceptions
    "PolicyCompilationError",
    "InvalidDomainError",
    "InvalidNetworkAddressError",
    "InvalidPortError",
    "InvalidValidityWindowError",
    "MissingConfigurationError",
    "InvalidApprovedBrowserError",
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
    "UnsupportedApprovedBrowserError",
    "create_canonical_payload",
    "generate_development_keypair",
    "export_public_key_pem",
    "load_public_key_pem",
    "normalize_approved_browser",
    "CURRENT_SCHEMA_VERSION",
    "SUPPORTED_APPROVED_BROWSERS",
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
    "rebuild_signed_payload",
]
