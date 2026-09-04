"""SPEMCS Milestone 2 Cryptographic Integrity & RSA-PSS Test Suite.

Exhaustively covers all 19 required M2 test specifications:
1. Sign valid policy
2. Verify valid signature
3. Same payload verifies repeatedly
4. Alter allowed destination -> verification fails (InvalidSignatureError)
5. Alter exam_id -> verification fails (InvalidSignatureError)
6. Alter policy_id -> verification fails (InvalidSignatureError)
7. Alter version -> verification fails (InvalidSignatureError)
8. Alter expires_at -> verification fails (InvalidSignatureError)
9. Alter management server -> verification fails (InvalidSignatureError)
10. Corrupt signature -> verification fails (InvalidSignatureError)
11. Wrong public key -> verification fails (InvalidSignatureError)
12. Expired policy rejected (ExpiredPolicyError)
13. Not-yet-valid policy rejected (NotYetValidPolicyError)
14. Invalid expires_at <= not_before rejected (InvalidValidityWindowError)
15. Signature field itself is excluded from signed payload
16. Canonicalization produces identical bytes regardless of key insertion order
17. Unicode/string canonicalization behaves deterministically (RFC 8785)
18. Numeric canonicalization follows RFC 8785 / ECMAScript rules
19. Unsupported schema version is rejected (UnsupportedSchemaVersionError)
+ Interoperability fixture generation & verification for future .NET 8 verifier
"""

import copy
import json
import uuid
from datetime import datetime, timedelta, timezone
import pytest

from backend.services.canonical_json import (
    canonicalize,
    canonicalize_to_bytes,
)
from backend.services.policy_signer import (
    PolicySigner,
    PolicyVerifier,
    PolicyVerificationError,
    MalformedPayloadError,
    UnsupportedSchemaVersionError,
    InvalidValidityWindowError,
    NotYetValidPolicyError,
    ExpiredPolicyError,
    InvalidSignatureError,
    KeyMismatchError,
    create_canonical_payload,
    generate_development_keypair,
    export_public_key_pem,
    load_public_key_pem,
    CURRENT_SCHEMA_VERSION,
    PSS_SALT_LENGTH_BYTES,
    RSA_KEY_SIZE_BITS,
)


@pytest.fixture(scope="module")
def dev_keys():
    """Generates an ephemeral RSA-2048 keypair for the test session."""
    priv, pub = generate_development_keypair(key_size=2048)
    return priv, pub


@pytest.fixture
def signer(dev_keys):
    priv, _ = dev_keys
    return PolicySigner(private_key=priv, key_id="dev-key-1")


@pytest.fixture
def verifier(dev_keys):
    _, pub = dev_keys
    v = PolicyVerifier()
    v.add_trusted_key("dev-key-1", pub)
    return v


@pytest.fixture
def valid_payload():
    """Constructs a standard valid payload dictionary."""
    now = datetime.now(timezone.utc)
    return create_canonical_payload(
        exam_id=uuid.uuid4(),
        policy_id=uuid.uuid4(),
        version=1,
        vendor_profile_id=uuid.uuid4(),
        allowed_destinations=[
            {
                "name": "Moodle Campus LMS",
                "ip_ranges": ["192.168.10.50/32", "192.168.10.51/32"],
                "tcp_ports": [80, 443],
                "udp_ports": [],
            }
        ],
        management_server={"ip_addresses": ["192.168.11.200"], "port": 8000},
        not_before=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=3),
        approved_browser="chrome",
        key_id="dev-key-1",
        schema_version=CURRENT_SCHEMA_VERSION,
    )


# ------------------------------------------------------------------------------
# Tests 1 - 3: Baseline Signing & Repeated Verification
# ------------------------------------------------------------------------------
def test_1_sign_valid_policy(signer, valid_payload):
    """Test 1: Successfully signs a valid policy payload and returns Base64 string."""
    sig = signer.sign_payload(valid_payload)
    assert isinstance(sig, str)
    assert len(sig) > 100  # RSA-2048 base64 signature is ~344 characters


def test_2_verify_valid_signature(signer, verifier, valid_payload):
    """Test 2: Verifies a valid signature against the payload."""
    sig = signer.sign_payload(valid_payload)
    now = datetime.now(timezone.utc)
    result = verifier.verify_policy(valid_payload, sig, current_time=now)
    assert result["exam_id"] == valid_payload["exam_id"]
    assert result["version"] == valid_payload["version"]


def test_3_same_payload_verifies_repeatedly(signer, verifier, valid_payload):
    """Test 3: The same payload and signature verify consistently across multiple calls."""
    sig = signer.sign_payload(valid_payload)
    now = datetime.now(timezone.utc)
    for _ in range(5):
        result = verifier.verify_policy(valid_payload, sig, current_time=now)
        assert result["policy_id"] == valid_payload["policy_id"]


# ------------------------------------------------------------------------------
# Tests 4 - 9: Tamper Detection (Altered Payload Fields)
# ------------------------------------------------------------------------------
def test_4_alter_allowed_destinations_fails(signer, verifier, valid_payload):
    """Test 4: Modifying allowed destinations causes signature verification to fail."""
    sig = signer.sign_payload(valid_payload)
    tampered = copy.deepcopy(valid_payload)
    tampered["allowed_destinations"][0]["ip_ranges"] = ["8.8.8.8/32"]

    with pytest.raises(InvalidSignatureError):
        verifier.verify_policy(tampered, sig)


def test_5_alter_exam_id_fails(signer, verifier, valid_payload):
    """Test 5: Modifying exam_id causes signature verification to fail (prevents exam substitution)."""
    sig = signer.sign_payload(valid_payload)
    tampered = copy.deepcopy(valid_payload)
    tampered["exam_id"] = str(uuid.uuid4())

    with pytest.raises(InvalidSignatureError):
        verifier.verify_policy(tampered, sig)


def test_6_alter_policy_id_fails(signer, verifier, valid_payload):
    """Test 6: Modifying policy_id causes signature verification to fail."""
    sig = signer.sign_payload(valid_payload)
    tampered = copy.deepcopy(valid_payload)
    tampered["policy_id"] = str(uuid.uuid4())

    with pytest.raises(InvalidSignatureError):
        verifier.verify_policy(tampered, sig)


def test_7_alter_version_fails(signer, verifier, valid_payload):
    """Test 7: Modifying version causes signature verification to fail (prevents rollback)."""
    sig = signer.sign_payload(valid_payload)
    tampered = copy.deepcopy(valid_payload)
    tampered["version"] = 2

    with pytest.raises(InvalidSignatureError):
        verifier.verify_policy(tampered, sig)


def test_8_alter_expires_at_fails(signer, verifier, valid_payload):
    """Test 8: Modifying expires_at causes signature verification to fail."""
    sig = signer.sign_payload(valid_payload)
    tampered = copy.deepcopy(valid_payload)
    tampered["expires_at"] = "2099-01-01T00:00:00Z"

    with pytest.raises(InvalidSignatureError):
        verifier.verify_policy(tampered, sig)


def test_9_alter_management_server_fails(signer, verifier, valid_payload):
    """Test 9: Modifying management server IP causes signature verification to fail."""
    sig = signer.sign_payload(valid_payload)
    tampered = copy.deepcopy(valid_payload)
    tampered["management_server"]["ip_addresses"] = ["10.99.99.99"]

    with pytest.raises(InvalidSignatureError):
        verifier.verify_policy(tampered, sig)


# ------------------------------------------------------------------------------
# Tests 10 - 11: Corrupted Signature & Key Mismatch
# ------------------------------------------------------------------------------
def test_10_corrupt_signature_fails(signer, verifier, valid_payload):
    """Test 10: Corrupting signature characters causes verification to fail."""
    sig = signer.sign_payload(valid_payload)
    corrupted_char = "B" if sig[0] == "A" else "A"
    corrupted_sig = corrupted_char + sig[1:]
    with pytest.raises(InvalidSignatureError):
        verifier.verify_policy(valid_payload, corrupted_sig)


def test_11_wrong_public_key_fails(signer, valid_payload):
    """Test 11: Attempting verification with an unrelated public key fails."""
    sig = signer.sign_payload(valid_payload)
    _, unrelated_pub = generate_development_keypair(key_size=2048)

    unrelated_verifier = PolicyVerifier({"dev-key-1": unrelated_pub})
    with pytest.raises(InvalidSignatureError):
        unrelated_verifier.verify_policy(valid_payload, sig)


# ------------------------------------------------------------------------------
# Tests 12 - 14: Temporal Validity Window Checks
# ------------------------------------------------------------------------------
def test_12_expired_policy_rejected(signer, verifier):
    """Test 12: An expired policy is rejected with ExpiredPolicyError."""
    past = datetime.now(timezone.utc) - timedelta(hours=5)
    payload = create_canonical_payload(
        exam_id=uuid.uuid4(),
        policy_id=uuid.uuid4(),
        version=1,
        vendor_profile_id=None,
        allowed_destinations=[],
        management_server={"ip_addresses": ["127.0.0.1"], "port": 8000},
        not_before=past - timedelta(hours=2),
        expires_at=past - timedelta(hours=1),
        approved_browser="chrome",
    )
    sig = signer.sign_payload(payload)

    now = datetime.now(timezone.utc)
    with pytest.raises(ExpiredPolicyError):
        verifier.verify_policy(payload, sig, current_time=now)


def test_13_not_yet_valid_policy_rejected(signer, verifier):
    """Test 13: A future policy is rejected with NotYetValidPolicyError."""
    future = datetime.now(timezone.utc) + timedelta(hours=2)
    payload = create_canonical_payload(
        exam_id=uuid.uuid4(),
        policy_id=uuid.uuid4(),
        version=1,
        vendor_profile_id=None,
        allowed_destinations=[],
        management_server={"ip_addresses": ["127.0.0.1"], "port": 8000},
        not_before=future,
        expires_at=future + timedelta(hours=2),
        approved_browser="chrome",
    )
    sig = signer.sign_payload(payload)

    now = datetime.now(timezone.utc)
    with pytest.raises(NotYetValidPolicyError):
        verifier.verify_policy(payload, sig, current_time=now)


def test_14_invalid_validity_window_rejected(signer, verifier):
    """Test 14: expires_at <= not_before is rejected with InvalidValidityWindowError."""
    now = datetime.now(timezone.utc)
    payload = create_canonical_payload(
        exam_id=uuid.uuid4(),
        policy_id=uuid.uuid4(),
        version=1,
        vendor_profile_id=None,
        allowed_destinations=[],
        management_server={"ip_addresses": ["127.0.0.1"], "port": 8000},
        not_before=now + timedelta(hours=1),
        expires_at=now,  # expires before it begins!
        approved_browser="chrome",
    )
    sig = signer.sign_payload(payload)

    with pytest.raises(InvalidValidityWindowError):
        verifier.verify_policy(payload, sig)


# ------------------------------------------------------------------------------
# Test 15: Signature Field Excluded
# ------------------------------------------------------------------------------
def test_15_signature_field_excluded_from_signed_payload(signer, valid_payload):
    """Test 15: Signer refuses to sign if 'signature' key is passed inside the payload."""
    payload_with_sig = copy.deepcopy(valid_payload)
    payload_with_sig["signature"] = "CANNOT_SIGN_OWN_SIGNATURE"

    with pytest.raises(MalformedPayloadError, match="The 'signature' field MUST NOT be included"):
        signer.sign_payload(payload_with_sig)


# ------------------------------------------------------------------------------
# Tests 16 - 18: RFC 8785 JCS Canonicalization Details
# ------------------------------------------------------------------------------
def test_16_canonicalization_key_ordering_invariance():
    """Test 16: Dictionaries with different key insertion orders produce identical canonical bytes."""
    obj1 = {"b": 2, "a": 1, "nested": {"z": 26, "y": 25}}
    obj2 = {"nested": {"y": 25, "z": 26}, "a": 1, "b": 2}

    bytes1 = canonicalize_to_bytes(obj1)
    bytes2 = canonicalize_to_bytes(obj2)

    assert bytes1 == bytes2
    assert bytes1 == b'{"a":1,"b":2,"nested":{"y":25,"z":26}}'


def test_17_unicode_and_string_escaping_determinism():
    """Test 17: Unicode characters are output unescaped in UTF-8; control chars properly escaped."""
    obj = {
        "unicode": "Campus \u00e9tudiant \u4e2d\u6587 \U0001f393",
        "escapes": "line1\nline2\ttab\"quote\\backslash",
        "solidus": "https://exam.univ.edu/api/v1",  # / MUST NOT be escaped per RFC 8785
    }
    canon = canonicalize(obj)

    # Unicode characters must remain literal UTF-8, not \\uXXXX
    assert "Campus \u00e9tudiant \u4e2d\u6587 \U0001f393" in canon
    assert "\\n" in canon
    assert "\\t" in canon
    assert '\\"' in canon
    assert "\\\\" in canon
    # Slash MUST NOT be escaped
    assert "https://exam.univ.edu/api/v1" in canon
    assert "\\/" not in canon


def test_18_numeric_canonicalization_rules():
    """Test 18: Numeric formatting follows RFC 8785: -0.0 -> 0, integers without decimal."""
    obj = {
        "int": 42,
        "negative_zero": -0.0,
        "large_int": 9007199254740991,
        "float": 1.5,
    }
    canon = canonicalize(obj)
    assert '"negative_zero":0' in canon
    assert '"int":42' in canon
    assert '"float":1.5' in canon


# ------------------------------------------------------------------------------
# Test 19: Unsupported Schema Version Rejected
# ------------------------------------------------------------------------------
def test_19_unsupported_schema_version_rejected(signer, verifier, valid_payload):
    """Test 19: Schema versions other than '1.0' are rejected with UnsupportedSchemaVersionError."""
    tampered = copy.deepcopy(valid_payload)
    tampered["schema_version"] = "2.0"
    sig = signer.sign_payload(tampered)

    with pytest.raises(UnsupportedSchemaVersionError, match="Unsupported schema_version '2.0'"):
        verifier.verify_policy(tampered, sig)


# ------------------------------------------------------------------------------
# Test 20: Future .NET 8 Interoperability Fixture
# ------------------------------------------------------------------------------
def test_20_interoperability_fixture(signer, verifier, valid_payload):
    """Generates and validates an explicit cross-platform fixture for .NET 8 verifier."""
    sig = signer.sign_payload(valid_payload)
    canonical_str = canonicalize(valid_payload)
    pub_pem = signer.get_public_key_pem()

    fixture = {
        "algorithm": "RSA-PSS",
        "key_size_bits": RSA_KEY_SIZE_BITS,
        "hash_algorithm": "SHA-256",
        "mgf": "MGF1-SHA-256",
        "pss_salt_length": PSS_SALT_LENGTH_BYTES,
        "encoding": "Standard-Base64",
        "public_key_spki_pem": pub_pem,
        "canonical_payload_json": canonical_str,
        "signature_base64": sig,
        "expected_result": "VALID",
    }

    # Verify that the fixture's public key loads from PEM and verifies the signature
    imported_pub = load_public_key_pem(fixture["public_key_spki_pem"])
    verifier_imported = PolicyVerifier({"dev-key-1": imported_pub})
    parsed_payload = json.loads(fixture["canonical_payload_json"])

    verified = verifier_imported.verify_policy(parsed_payload, fixture["signature_base64"])
    assert verified["exam_id"] == valid_payload["exam_id"]
