"""Regression tests for the signed approved-browser identity (Requirements 4 & 5).

Background
----------
The endpoint scopes every vendor/exam firewall allow rule to the approved examination
browser's executable (ApplicationName on the Windows firewall rule). If the browser
identity were not part of the signed policy, an attacker who could influence local agent
input could re-point the allowlist at an arbitrary program (curl.exe, python.exe) while
the RSA-PSS signature still verified. These tests pin the invariants that prevent that:

  1. `approved_browser` is a MANDATORY field of the signed payload.
  2. It is validated against a closed set, never silently defaulted.
  3. Tampering with it after signing is a signature failure.
  4. A legacy schema-1.0 payload (no browser field) cannot be signed or verified.
  5. The exam write-path schemas refuse a browser the endpoint could never enforce, so an
     unactivatable exam is a 422 at creation rather than a failure on exam day.

This module deliberately imports ONLY pure modules (no fastapi / no DB), so it runs in
any environment that has `cryptography` and `pydantic` available.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from backend.services.canonical_json import canonicalize_to_bytes
from backend.services.policy_compiler import (
    SUPPORTED_APPROVED_BROWSERS as COMPILER_BROWSERS,
    InvalidApprovedBrowserError,
    compile_exam_policy,
    validate_and_normalize_approved_browser,
)
from backend.services.policy_signer import (
    CURRENT_SCHEMA_VERSION,
    MANDATORY_PAYLOAD_FIELDS,
    SUPPORTED_APPROVED_BROWSERS as SIGNER_BROWSERS,
    InvalidSignatureError,
    MalformedPayloadError,
    PolicySigner,
    PolicyVerifier,
    UnsupportedApprovedBrowserError,
    create_canonical_payload,
    generate_development_keypair,
    normalize_approved_browser,
)

VENDOR_PROFILE = {
    "vendor_name": "Moodle",
    "required_domains": ["moodle.univ.edu"],
    "approved_ip_ranges": ["10.20.0.0/24"],
    "required_tcp_ports": [443],
    "required_udp_ports": [],
}
MGMT = {"ip_addresses": ["127.0.0.1"], "port": 8002}


@pytest.fixture(scope="module")
def keypair():
    return generate_development_keypair(key_size=2048)


@pytest.fixture
def signer(keypair):
    priv, _ = keypair
    return PolicySigner(private_key=priv, key_id="test-key-1")


@pytest.fixture
def verifier(keypair):
    _, pub = keypair
    return PolicyVerifier({"test-key-1": pub})


def _compile(browser="chrome", **overrides):
    now = overrides.pop("now", datetime.now(timezone.utc))
    kwargs = dict(
        exam_id=uuid.uuid4(),
        version=1,
        vendor_profile=VENDOR_PROFILE,
        management_server=MGMT,
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=2),
        approved_browser=browser,
        key_id="test-key-1",
    )
    kwargs.update(overrides)
    return compile_exam_policy(**kwargs)


# ------------------------------------------------------------------------------
# 1. Schema shape
# ------------------------------------------------------------------------------
def test_approved_browser_is_a_mandatory_signed_field():
    assert "approved_browser" in MANDATORY_PAYLOAD_FIELDS


def test_compiler_emits_exactly_the_mandatory_field_set():
    """The compiler output and the signer's mandatory set must not drift apart.

    A missing field would fail at signing time; an EXTRA field would be rejected by the
    agent's strict top-level whitelist. Both are release-blocking, so pin equality.
    """
    payload = _compile()
    assert set(payload.keys()) == set(MANDATORY_PAYLOAD_FIELDS)


def test_schema_version_was_bumped_for_the_new_mandatory_field():
    """Adding a mandatory field is breaking; the version bump makes skew fail loudly.

    Old agent (accepts only 1.0) + new backend -> UnsupportedSchema.
    New agent (accepts only 1.1) + old backend -> UnsupportedSchema.
    Neither direction can silently produce an unscoped firewall allow rule.
    """
    assert CURRENT_SCHEMA_VERSION == "1.1"
    assert _compile()["schema_version"] == "1.1"


def test_compiler_and_signer_agree_on_the_supported_browser_set():
    """The two modules duplicate the set to stay import-cycle free; pin them together."""
    assert COMPILER_BROWSERS == SIGNER_BROWSERS == frozenset({"chrome", "edge"})


def test_firefox_is_not_signable_even_though_the_db_enum_still_has_it():
    """Firefox must not be compilable into a signed policy.

    models.exam.ApprovedBrowser still carries FIREFOX so historical exam rows keep loading,
    but the endpoint classifier hard-denies firefox.exe (KnownUnapprovedBrowserExes) and has
    no Firefox approval branch. Signing a Firefox policy would firewall-allow a browser the
    monitor simultaneously reports as a violation. Failing to compile is the correct,
    loud outcome.
    """
    assert "firefox" not in SIGNER_BROWSERS
    assert "firefox" not in COMPILER_BROWSERS
    with pytest.raises(InvalidApprovedBrowserError):
        _compile(browser="firefox")
    with pytest.raises(UnsupportedApprovedBrowserError):
        normalize_approved_browser("firefox")


# ------------------------------------------------------------------------------
# 2. Validation: rejected, never defaulted
# ------------------------------------------------------------------------------
@pytest.mark.parametrize("browser", ["chrome", "CHROME", "  Chrome  ", "Edge", "EDGE"])
def test_supported_browsers_normalize_to_lowercase(browser):
    assert validate_and_normalize_approved_browser(browser) == browser.strip().lower()
    assert normalize_approved_browser(browser) == browser.strip().lower()


@pytest.mark.parametrize(
    "browser",
    [
        "safari",          # real browser, but the agent cannot identify it
        "firefox",         # in the DB enum, but the classifier hard-denies firefox.exe
        "chrome.exe",      # an executable name is not a family identifier
        "curl",            # the exact substitution this field exists to prevent
        "",
        "   ",
        None,
        5,
        ["chrome"],
        "chrome; edge",
    ],
)
def test_unsupported_browser_is_rejected_not_defaulted(browser):
    """An unrecognised browser must be a hard compile error.

    Defaulting to "chrome" would scope the allow rules to a browser the candidate is not
    using, and the operator would see an unexplained network outage rather than a
    configuration error.
    """
    with pytest.raises(InvalidApprovedBrowserError):
        _compile(browser=browser)


def test_compile_requires_approved_browser_argument():
    """The parameter has no default, so omitting it is a TypeError - not a silent policy."""
    now = datetime.now(timezone.utc)
    with pytest.raises(TypeError):
        compile_exam_policy(
            exam_id=uuid.uuid4(),
            version=1,
            vendor_profile=None,
            management_server=MGMT,
            not_before=now,
            expires_at=now + timedelta(hours=1),
        )


def test_create_canonical_payload_requires_approved_browser():
    now = datetime.now(timezone.utc)
    with pytest.raises(TypeError):
        create_canonical_payload(
            exam_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            version=1,
            vendor_profile_id=None,
            allowed_destinations=[],
            management_server=MGMT,
            not_before=now,
            expires_at=now + timedelta(hours=1),
        )


# ------------------------------------------------------------------------------
# 3. Cryptographic binding
# ------------------------------------------------------------------------------
def test_browser_identity_survives_sign_and_verify(signer, verifier):
    now = datetime.now(timezone.utc)
    payload = _compile(browser="Edge", now=now)
    sig = signer.sign_payload(payload)
    verified = verifier.verify_policy(payload, sig, current_time=now)
    assert verified["approved_browser"] == "edge"


def test_swapping_the_browser_after_signing_fails_verification(signer, verifier):
    """The core requirement-4/5 attack: re-scope the allowlist onto another program."""
    now = datetime.now(timezone.utc)
    payload = _compile(browser="chrome", now=now)
    sig = signer.sign_payload(payload)

    tampered = dict(payload)
    tampered["approved_browser"] = "edge"
    with pytest.raises(InvalidSignatureError):
        verifier.verify_policy(tampered, sig, current_time=now)


def test_verifier_rejects_out_of_set_browser_before_crypto(signer, verifier):
    """A payload naming an unresolvable browser is refused even though it is well-formed."""
    now = datetime.now(timezone.utc)
    payload = _compile(now=now)
    sig = signer.sign_payload(payload)

    tampered = dict(payload)
    tampered["approved_browser"] = "curl"
    with pytest.raises(UnsupportedApprovedBrowserError):
        verifier.verify_policy(tampered, sig, current_time=now)


def test_legacy_schema_1_0_payload_cannot_be_signed(signer):
    """A payload with no browser field is refused at signing, not signed-and-shipped."""
    payload = _compile()
    legacy = {k: v for k, v in payload.items() if k != "approved_browser"}
    with pytest.raises(MalformedPayloadError, match="approved_browser"):
        signer.sign_payload(legacy)


def test_legacy_schema_1_0_payload_cannot_be_verified(signer, verifier):
    now = datetime.now(timezone.utc)
    payload = _compile(now=now)
    sig = signer.sign_payload(payload)

    legacy = {k: v for k, v in payload.items() if k != "approved_browser"}
    with pytest.raises(MalformedPayloadError, match="approved_browser"):
        verifier.verify_policy(legacy, sig, current_time=now)


# ------------------------------------------------------------------------------
# 4. Determinism is preserved
# ------------------------------------------------------------------------------
def test_canonical_bytes_remain_deterministic_with_the_new_field():
    now = datetime.now(timezone.utc)
    fixed = dict(
        exam_id="11111111-1111-1111-1111-111111111111",
        policy_id="22222222-2222-2222-2222-222222222222",
        version=1,
        not_before=now,
        expires_at=now + timedelta(hours=1),
        key_id="test-key-1",
    )
    a = compile_exam_policy(
        vendor_profile=VENDOR_PROFILE,
        management_server={"port": 8002, "ip_addresses": ["127.0.0.1"]},
        approved_browser="Edge",
        **fixed,
    )
    b = compile_exam_policy(
        vendor_profile=VENDOR_PROFILE,
        management_server={"ip_addresses": ["127.0.0.1"], "port": 8002},
        approved_browser="   edge   ",
        **fixed,
    )
    assert canonicalize_to_bytes(a) == canonicalize_to_bytes(b)


# ------------------------------------------------------------------------------
# 5. The API write path refuses browsers that could never be enforced
# ------------------------------------------------------------------------------
# Without this, an admin can create an exam with approved_browser="firefox", see it saved
# successfully, and only discover on exam day that activation fails closed. The failure
# belongs at creation time, while the form is still on screen.
#
# ExamRead is deliberately NOT validated: models.exam.ApprovedBrowser still carries FIREFOX
# so historical rows keep loading, and validating on read would turn old data into a 500 on
# the exam list.
@pytest.mark.parametrize("browser", ["firefox", "safari", "curl", "chrome.exe", "", "   "])
def test_exam_create_schema_rejects_unenforceable_browser(browser):
    from pydantic import ValidationError

    from backend.schemas.exam import ExamCreate

    with pytest.raises(ValidationError):
        ExamCreate(exam_name="Midterm", approved_browser=browser)


@pytest.mark.parametrize("browser", ["firefox", "safari", "curl", "chrome.exe"])
def test_exam_update_schema_rejects_unenforceable_browser(browser):
    from pydantic import ValidationError

    from backend.schemas.exam import ExamUpdate

    with pytest.raises(ValidationError):
        ExamUpdate(approved_browser=browser)


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [("chrome", "chrome"), ("CHROME", "chrome"), ("  Edge  ", "edge"), ("EDGE", "edge")],
)
def test_exam_schemas_normalize_supported_browsers(supplied, expected):
    """Normalizing here means the persisted row already matches the signed wire value."""
    from backend.schemas.exam import ExamCreate, ExamUpdate

    assert ExamCreate(exam_name="Midterm", approved_browser=supplied).approved_browser == expected
    assert ExamUpdate(approved_browser=supplied).approved_browser == expected


def test_exam_create_defaults_to_chrome_and_update_allows_omission():
    """The default must remain valid, and a partial update must not require the field."""
    from backend.schemas.exam import ExamCreate, ExamUpdate

    assert ExamCreate(exam_name="Midterm").approved_browser == "chrome"
    assert ExamUpdate(exam_name="Renamed").approved_browser is None


def test_exam_schema_browser_set_matches_the_signable_set():
    """One source of truth: the API must accept exactly what the signer can sign."""
    from backend.schemas.exam import SUPPORTED_APPROVED_BROWSERS as SCHEMA_BROWSERS

    assert SCHEMA_BROWSERS is SIGNER_BROWSERS


def test_exam_read_still_accepts_historical_firefox_rows():
    """Reads must keep working for exams created before the set was narrowed."""
    from backend.schemas.exam import ExamRead

    row = ExamRead(exam_id=uuid.uuid4(), exam_name="Legacy", approved_browser="firefox")
    assert row.approved_browser == "firefox"
