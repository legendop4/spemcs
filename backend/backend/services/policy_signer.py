"""SPEMCS Policy Integrity & RSA-PSS Cryptographic Layer.

Provides:
- Explicit RSA-2048 / RSA-PSS / SHA-256 / MGF1-SHA-256 / SaltLength=32 signing
- RFC 8785 JSON Canonicalization Scheme integration
- Complete error hierarchy distinguishing cryptographic vs temporal vs structural failures
- Future .NET 8 interoperable verification semantics
"""

import base64
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .canonical_json import canonicalize_to_bytes

# ==============================================================================
# Cryptographic Constants & Interoperability Parameters
# ==============================================================================
RSA_KEY_SIZE_BITS = 2048
RSA_PUBLIC_EXPONENT = 65537
PSS_SALT_LENGTH_BYTES = 32  # Explicit 32 bytes matches SHA-256 digest length (RFC 8017 / .NET 8)
CURRENT_SCHEMA_VERSION = "1.0"
MANDATORY_PAYLOAD_FIELDS = {
    "schema_version",
    "key_id",
    "exam_id",
    "policy_id",
    "version",
    "vendor_profile_id",
    "allowed_destinations",
    "management_server",
    "not_before",
    "expires_at",
}


# ==============================================================================
# Verification Exception Hierarchy
# ==============================================================================
class PolicyVerificationError(Exception):
    """Base exception for all policy integrity and verification failures."""
    pass


class MalformedPayloadError(PolicyVerificationError):
    """Payload is structurally invalid, missing mandatory fields, or contains invalid types."""
    pass


class UnsupportedSchemaVersionError(PolicyVerificationError):
    """Payload schema_version is not supported by this verifier."""
    pass


class InvalidValidityWindowError(PolicyVerificationError):
    """Timestamp window is logically invalid (e.g. expires_at <= not_before)."""
    pass


class NotYetValidPolicyError(PolicyVerificationError):
    """Current time is earlier than the policy not_before activation timestamp."""
    pass


class ExpiredPolicyError(PolicyVerificationError):
    """Current time is at or later than the policy expires_at dead-man timestamp."""
    pass


class InvalidSignatureError(PolicyVerificationError):
    """Cryptographic signature verification failed (corrupted or forged)."""
    pass


class KeyMismatchError(PolicyVerificationError):
    """Required public key for key_id is not available or unknown."""
    pass


# ==============================================================================
# Helper Functions
# ==============================================================================
def parse_iso_utc(ts_str: str) -> datetime:
    """Parses strict ISO-8601 UTC timestamp (e.g. 2026-09-03T10:00:00Z)."""
    if not isinstance(ts_str, str):
        raise MalformedPayloadError(f"Timestamp must be string, got {type(ts_str).__name__}")
    
    # Normalize Z to +00:00 for Python datetime.fromisoformat
    normalized = ts_str.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            # Assume UTC if naive
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception as exc:
        raise MalformedPayloadError(f"Invalid ISO-8601 timestamp '{ts_str}': {exc}")


def generate_development_keypair(key_size: int = RSA_KEY_SIZE_BITS) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates an in-memory RSA keypair for development/testing.
    
    Private key must remain in memory or local test scope and never be committed.
    """
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def export_public_key_pem(public_key: rsa.RSAPublicKey) -> str:
    """Exports public key in standard SubjectPublicKeyInfo (SPKI) PEM format."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("ascii")


def load_public_key_pem(pem_str: str) -> rsa.RSAPublicKey:
    """Loads public key from SubjectPublicKeyInfo PEM string."""
    return serialization.load_pem_public_key(pem_str.encode("ascii"))


def create_canonical_payload(
    exam_id: str | uuid.UUID,
    policy_id: str | uuid.UUID,
    version: int,
    vendor_profile_id: Optional[str | uuid.UUID],
    allowed_destinations: List[Dict[str, Any]],
    management_server: Dict[str, Any],
    not_before: datetime | str,
    expires_at: datetime | str,
    key_id: str = "dev-key-1",
    schema_version: str = CURRENT_SCHEMA_VERSION,
) -> Dict[str, Any]:
    """Constructs the canonical signed envelope dictionary.
    
    Ensures all IDs are string representations and timestamps are strict ISO-8601 UTC.
    The 'signature' field is explicitly EXCLUDED from this payload.
    """
    def _format_utc(dt: datetime | str) -> str:
        if isinstance(dt, str):
            return dt
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    nb_str = _format_utc(not_before)
    exp_str = _format_utc(expires_at)

    payload = {
        "schema_version": str(schema_version),
        "key_id": str(key_id),
        "exam_id": str(exam_id),
        "policy_id": str(policy_id),
        "version": int(version),
        "vendor_profile_id": str(vendor_profile_id) if vendor_profile_id else None,
        "allowed_destinations": allowed_destinations,
        "management_server": management_server,
        "not_before": nb_str,
        "expires_at": exp_str,
    }
    return payload


# ==============================================================================
# Policy Signer (Server-Side)
# ==============================================================================
class PolicySigner:
    """Signs NetworkPolicy payloads using RSA-PSS SHA-256 with explicit parameters."""

    def __init__(self, private_key: rsa.RSAPrivateKey, key_id: str = "dev-key-1"):
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("private_key must be an instance of RSAPrivateKey")
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self.key_id = key_id

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self._public_key

    def get_public_key_pem(self) -> str:
        return export_public_key_pem(self._public_key)

    def sign_payload(self, payload: Dict[str, Any]) -> str:
        """Signs a policy payload using RFC 8785 canonical bytes and RSA-PSS.
        
        Returns:
            Standard Base64-encoded signature string.
        """
        # Validate that the signature field is NOT inside the signed payload
        if "signature" in payload:
            raise MalformedPayloadError("The 'signature' field MUST NOT be included inside the signed payload dictionary")

        # Verify mandatory fields exist
        missing = MANDATORY_PAYLOAD_FIELDS - set(payload.keys())
        if missing:
            raise MalformedPayloadError(f"Missing mandatory payload fields: {sorted(list(missing))}")

        # Canonicalize to UTF-8 bytes via RFC 8785 JCS
        canonical_bytes = canonicalize_to_bytes(payload)

        # Sign with RSA-PSS SHA-256 with explicit salt length 32
        sig_bytes = self._private_key.sign(
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=PSS_SALT_LENGTH_BYTES,
            ),
            hashes.SHA256(),
        )

        return base64.b64encode(sig_bytes).decode("ascii")


# ==============================================================================
# Policy Verifier (Endpoint / Server Verification)
# ==============================================================================
class PolicyVerifier:
    """Verifies NetworkPolicy payloads using RSA-PSS SHA-256 with explicit parameters.
    
    Compatible with future C# .NET 8 RSASignaturePadding.Pss verifier.
    """

    def __init__(self, trusted_keys: Optional[Dict[str, rsa.RSAPublicKey]] = None):
        """Initializes verifier with a dictionary of key_id -> RSAPublicKey."""
        self._trusted_keys: Dict[str, rsa.RSAPublicKey] = dict(trusted_keys) if trusted_keys else {}

    def add_trusted_key(self, key_id: str, public_key: rsa.RSAPublicKey) -> None:
        self._trusted_keys[key_id] = public_key

    def verify_signature_bytes(
        self,
        canonical_bytes: bytes,
        signature_b64: str,
        public_key: rsa.RSAPublicKey,
    ) -> None:
        """Verifies raw canonical bytes against a Base64 signature and public key."""
        try:
            sig_bytes = base64.b64decode(signature_b64, validate=True)
        except Exception as exc:
            raise InvalidSignatureError(f"Signature is not valid Base64: {exc}")

        try:
            public_key.verify(
                sig_bytes,
                canonical_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=PSS_SALT_LENGTH_BYTES,
                ),
                hashes.SHA256(),
            )
        except InvalidSignature:
            raise InvalidSignatureError("RSA-PSS signature verification failed: signature mismatch or altered data")
        except Exception as exc:
            raise InvalidSignatureError(f"RSA-PSS verification error: {exc}")

    def verify_policy(
        self,
        payload: Dict[str, Any],
        signature_b64: str,
        current_time: Optional[datetime] = None,
        public_key: Optional[rsa.RSAPublicKey] = None,
    ) -> Dict[str, Any]:
        """Performs comprehensive policy validation:
        1. Checks mandatory fields
        2. Validates schema_version
        3. Validates timestamp validity window (not_before < expires_at)
        4. Validates current temporal validity (if current_time provided)
        5. Verifies cryptographic RSA-PSS signature
        
        Returns:
            The verified payload dict if completely valid.
        Raises:
            MalformedPayloadError
            UnsupportedSchemaVersionError
            InvalidValidityWindowError
            NotYetValidPolicyError
            ExpiredPolicyError
            InvalidSignatureError
            KeyMismatchError
        """
        # 1. Structural check
        if not isinstance(payload, dict):
            raise MalformedPayloadError(f"Payload must be dictionary, got {type(payload).__name__}")
        
        # Ensure 'signature' was not included inside payload
        clean_payload = {k: v for k, v in payload.items() if k != "signature"}

        missing = MANDATORY_PAYLOAD_FIELDS - set(clean_payload.keys())
        if missing:
            raise MalformedPayloadError(f"Missing mandatory payload fields: {sorted(list(missing))}")

        # 2. Schema version
        if clean_payload["schema_version"] != CURRENT_SCHEMA_VERSION:
            raise UnsupportedSchemaVersionError(
                f"Unsupported schema_version '{clean_payload['schema_version']}'. Expected '{CURRENT_SCHEMA_VERSION}'."
            )

        # 3. Numeric version
        if not isinstance(clean_payload["version"], int) or clean_payload["version"] < 1:
            raise MalformedPayloadError("Policy version must be a positive integer >= 1")

        # 4. Validity Window
        nb = parse_iso_utc(clean_payload["not_before"])
        exp = parse_iso_utc(clean_payload["expires_at"])
        if exp <= nb:
            raise InvalidValidityWindowError(
                f"Invalid validity window: expires_at ({clean_payload['expires_at']}) must be strictly after not_before ({clean_payload['not_before']})"
            )

        # 5. Temporal Validity check (against current_time)
        if current_time is not None:
            now_utc = current_time.astimezone(timezone.utc) if current_time.tzinfo else current_time.replace(tzinfo=timezone.utc)
            if now_utc < nb:
                raise NotYetValidPolicyError(f"Policy is not yet valid. Current time: {now_utc.isoformat()}, not_before: {nb.isoformat()}")
            if now_utc >= exp:
                raise ExpiredPolicyError(f"Policy has expired. Current time: {now_utc.isoformat()}, expires_at: {exp.isoformat()}")

        # 6. Key Resolution
        key_id = clean_payload["key_id"]
        target_key = public_key
        if target_key is None:
            target_key = self._trusted_keys.get(key_id)
            if target_key is None:
                raise KeyMismatchError(f"No trusted public key registered for key_id '{key_id}'")

        # 7. Cryptographic Verification over RFC 8785 Canonical Bytes
        canonical_bytes = canonicalize_to_bytes(clean_payload)
        self.verify_signature_bytes(canonical_bytes, signature_b64, target_key)

        return clean_payload
