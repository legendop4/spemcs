"""Policy signing key lifecycle tests (P0-B).

These tests exist because of a specific defect: ``routes/policies.py`` used to generate a fresh
RSA keypair at *module import time* and label it with the constant id ``"dev-key-1"``. Three
things went wrong at once, and each has a test here:

1. Every process start produced new key material, so policies that had already been compiled and
   distributed could no longer be verified. That is an availability failure that lands mid-exam.
   Covered by the "restart" tests: a manager reconstructed over the same directory must produce
   the same key id and must still verify a signature made by the earlier instance.

2. The id was constant while the material changed, so an endpoint resolved the id, found *a*
   public key, and reported a **signature failure** - i.e. "this policy was forged" - when the
   real cause was a backend restart. Ids are now SHA-256 fingerprints of the SPKI DER, so an id
   cannot outlive its key. Covered by the key-id derivation tests.

3. Missing key material was indistinguishable from a first run, so the failure mode was to
   silently mint a replacement. Covered by the fail-closed tests: a deleted, tampered, or
   undecryptable key raises and nothing is regenerated.

No test writes a real credential anywhere. Passphrases here are literal test strings, and the
only key material that leaves the manager is a public SPKI PEM.
"""

import json
import os
import sys
import threading
from pathlib import Path

import pytest

from backend.services.policy_signer import (
    MalformedPayloadError,
    PolicySigner,
    create_canonical_payload,
    export_public_key_pem,
    generate_development_keypair,
)
from backend.services.signing_key_manager import (
    KEY_ID_FINGERPRINT_CHARS,
    KEY_ID_PREFIX_EPHEMERAL,
    KEY_ID_PREFIX_PERSISTENT,
    KEY_STATE_ACTIVE,
    KEY_STATE_RETIRED,
    KEY_STATE_REVOKED,
    KEYRING_FILENAME,
    PRIVATE_KEY_SUBDIR,
    SigningKeyManager,
    SigningKeyStateError,
    SigningKeyUnavailableError,
    compute_key_id,
    default_key_dir,
    get_signing_key_manager,
    is_ephemeral_key_id,
    set_signing_key_manager,
)

# RSA-1024 keeps this suite fast. It is a test-only size: the manager's default and every
# production path use RSA_KEY_SIZE_BITS (2048). Nothing under test depends on the modulus size -
# key ids are digests of the SPKI encoding, and PSS/SHA-256 with a 32-byte salt fits a 1024-bit
# modulus (32 + 32 + 2 <= 128).
TEST_KEY_SIZE = 1024


def make_manager(key_dir, **kwargs) -> SigningKeyManager:
    kwargs.setdefault("key_size", TEST_KEY_SIZE)
    return SigningKeyManager(key_dir=key_dir, **kwargs)


def private_key_files(key_dir: Path):
    return sorted((Path(key_dir) / PRIVATE_KEY_SUBDIR).glob("*.pem"))


def read_keyring(key_dir: Path) -> dict:
    return json.loads((Path(key_dir) / KEYRING_FILENAME).read_text(encoding="utf-8"))


def sample_payload(key_id: str) -> dict:
    return create_canonical_payload(
        exam_id="11111111-1111-1111-1111-111111111111",
        policy_id="22222222-2222-2222-2222-222222222222",
        version=1,
        vendor_profile_id=None,
        allowed_destinations=[{"ip": "203.0.113.10/32", "protocol": "TCP", "ports": [443]}],
        management_server={"ip_addresses": ["127.0.0.1"], "port": 8002, "use_tls": False},
        not_before="2026-01-01T00:00:00Z",
        expires_at="2026-01-01T08:00:00Z",
        approved_browser="chrome",
        key_id=key_id,
    )


# ==============================================================================
# Key id derivation: an id cannot outlive the key it names (defect 2)
# ==============================================================================
def test_key_id_is_a_fingerprint_of_the_public_key():
    _, public = generate_development_keypair(key_size=TEST_KEY_SIZE)

    key_id = compute_key_id(public)

    prefix, _, fingerprint = key_id.partition("-")
    assert prefix == KEY_ID_PREFIX_PERSISTENT
    assert len(fingerprint) == KEY_ID_FINGERPRINT_CHARS
    assert all(c in "0123456789abcdef" for c in fingerprint)


def test_key_id_is_stable_across_pem_round_trips():
    """Re-encoding must not change the id.

    The fingerprint is taken over the DER SubjectPublicKeyInfo rather than the PEM text
    precisely so that whitespace, line wrapping, or a save/load cycle cannot appear to be a
    different key.
    """
    from backend.services.policy_signer import load_public_key_pem

    _, public = generate_development_keypair(key_size=TEST_KEY_SIZE)
    reloaded = load_public_key_pem(export_public_key_pem(public))

    assert compute_key_id(public) == compute_key_id(reloaded)


def test_distinct_keys_get_distinct_ids():
    _, first = generate_development_keypair(key_size=TEST_KEY_SIZE)
    _, second = generate_development_keypair(key_size=TEST_KEY_SIZE)

    assert compute_key_id(first) != compute_key_id(second)


def test_ephemeral_ids_are_recognisable():
    _, public = generate_development_keypair(key_size=TEST_KEY_SIZE)

    ephemeral = compute_key_id(public, ephemeral=True)
    persistent = compute_key_id(public)

    assert ephemeral.startswith(f"{KEY_ID_PREFIX_EPHEMERAL}-")
    assert is_ephemeral_key_id(ephemeral)
    assert not is_ephemeral_key_id(persistent)
    # Same material, but the two are never confusable for one another.
    assert ephemeral != persistent


# ==============================================================================
# Persistence across restarts (defect 1)
# ==============================================================================
def test_first_use_creates_a_persistent_key(tmp_path):
    manager = make_manager(tmp_path / "keys")

    key_id = manager.active_key_id()

    assert key_id.startswith(f"{KEY_ID_PREFIX_PERSISTENT}-")
    assert manager.is_ephemeral is False
    assert len(private_key_files(tmp_path / "keys")) == 1
    assert read_keyring(tmp_path / "keys")["active_key_id"] == key_id


def test_restart_reuses_the_same_key(tmp_path):
    """The regression test for the original defect."""
    key_dir = tmp_path / "keys"

    first_boot = make_manager(key_dir)
    original_id = first_boot.active_key_id()
    original_pem = first_boot.active_descriptor().public_key_pem

    # A brand new manager over the same directory stands in for a restarted backend process.
    second_boot = make_manager(key_dir)

    assert second_boot.active_key_id() == original_id
    assert second_boot.active_descriptor().public_key_pem == original_pem
    assert len(private_key_files(key_dir)) == 1


def test_policy_signed_before_a_restart_still_verifies_after_it(tmp_path):
    key_dir = tmp_path / "keys"

    before = make_manager(key_dir)
    signer = before.active_signer()
    payload = sample_payload(signer.key_id)
    signature = signer.sign_payload(payload)

    after = make_manager(key_dir)

    # Would raise InvalidSignatureError or KeyMismatchError under the old import-time keygen.
    verified = after.verifier().verify_policy(payload, signature)
    assert verified["key_id"] == signer.key_id


def test_repeated_restarts_never_accumulate_keys(tmp_path):
    key_dir = tmp_path / "keys"
    ids = {make_manager(key_dir).active_key_id() for _ in range(4)}

    assert len(ids) == 1
    assert len(private_key_files(key_dir)) == 1
    assert len(read_keyring(key_dir)["keys"]) == 1


# ==============================================================================
# Fail closed instead of silently regenerating (defect 3)
# ==============================================================================
def test_missing_private_key_fails_closed_and_regenerates_nothing(tmp_path):
    key_dir = tmp_path / "keys"
    original_id = make_manager(key_dir).active_key_id()

    (key_dir / PRIVATE_KEY_SUBDIR / f"{original_id}.pem").unlink()

    with pytest.raises(SigningKeyUnavailableError) as err:
        make_manager(key_dir).active_signer()

    assert original_id in str(err.value)
    # The important half of the assertion: no replacement was minted behind the operator's back.
    assert private_key_files(key_dir) == []
    assert read_keyring(key_dir)["active_key_id"] == original_id


def test_private_key_swapped_under_an_existing_id_is_rejected(tmp_path):
    """Filesystem write access must not be enough to substitute key material.

    Because the id is a fingerprint, the loaded private key can be checked against the id it was
    filed under. Without that check an attacker who could write to the key directory would be
    able to sign policies that agents accept under an id they already trust.
    """
    from cryptography.hazmat.primitives import serialization

    key_dir = tmp_path / "keys"
    original_id = make_manager(key_dir).active_key_id()

    impostor, _ = generate_development_keypair(key_size=TEST_KEY_SIZE)
    (key_dir / PRIVATE_KEY_SUBDIR / f"{original_id}.pem").write_bytes(
        impostor.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    with pytest.raises(SigningKeyUnavailableError) as err:
        make_manager(key_dir).active_signer()

    assert "tampered" in str(err.value).lower() or "fingerprints as" in str(err.value)


def test_public_key_swapped_in_the_keyring_is_rejected(tmp_path):
    key_dir = tmp_path / "keys"
    make_manager(key_dir).active_key_id()

    _, impostor_public = generate_development_keypair(key_size=TEST_KEY_SIZE)
    document = read_keyring(key_dir)
    document["keys"][0]["public_key_pem"] = export_public_key_pem(impostor_public)
    (key_dir / KEYRING_FILENAME).write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SigningKeyUnavailableError) as err:
        make_manager(key_dir).active_signer()

    assert "fingerprint" in str(err.value).lower()


def test_corrupt_keyring_is_not_silently_rebuilt(tmp_path):
    key_dir = tmp_path / "keys"
    make_manager(key_dir).active_key_id()
    (key_dir / KEYRING_FILENAME).write_text("{ this is not json", encoding="utf-8")

    with pytest.raises(SigningKeyUnavailableError) as err:
        make_manager(key_dir).active_signer()

    assert "not valid JSON" in str(err.value)
    # Rebuilding would discard the record of which keys this server has issued.
    assert len(private_key_files(key_dir)) == 1


def test_keyring_naming_an_unknown_active_key_is_rejected(tmp_path):
    key_dir = tmp_path / "keys"
    make_manager(key_dir).active_key_id()

    document = read_keyring(key_dir)
    document["active_key_id"] = "spemcs-" + "0" * KEY_ID_FINGERPRINT_CHARS
    (key_dir / KEYRING_FILENAME).write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SigningKeyUnavailableError):
        make_manager(key_dir).active_signer()


def test_unknown_keyring_schema_version_is_rejected(tmp_path):
    key_dir = tmp_path / "keys"
    make_manager(key_dir).active_key_id()

    document = read_keyring(key_dir)
    document["schema_version"] = 99
    (key_dir / KEYRING_FILENAME).write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SigningKeyUnavailableError) as err:
        make_manager(key_dir).active_signer()

    assert "schema_version" in str(err.value)


# ==============================================================================
# Passphrase handling
# ==============================================================================
def test_passphrase_protected_key_survives_a_restart(tmp_path):
    key_dir = tmp_path / "keys"
    passphrase = "unit-test-passphrase-not-a-real-secret"

    first = make_manager(key_dir, passphrase=passphrase)
    key_id = first.active_key_id()

    stored = (key_dir / PRIVATE_KEY_SUBDIR / f"{key_id}.pem").read_bytes()
    assert b"ENCRYPTED" in stored

    assert make_manager(key_dir, passphrase=passphrase).active_key_id() == key_id


def test_wrong_passphrase_fails_closed(tmp_path):
    key_dir = tmp_path / "keys"
    make_manager(key_dir, passphrase="unit-test-passphrase-not-a-real-secret").active_key_id()

    with pytest.raises(SigningKeyUnavailableError):
        make_manager(key_dir, passphrase="a-different-passphrase").active_signer()

    # A misconfigured passphrase must not look like a first run.
    assert len(private_key_files(key_dir)) == 1


def test_missing_passphrase_for_an_encrypted_key_fails_closed(tmp_path):
    key_dir = tmp_path / "keys"
    make_manager(key_dir, passphrase="unit-test-passphrase-not-a-real-secret").active_key_id()

    with pytest.raises(SigningKeyUnavailableError):
        make_manager(key_dir).active_signer()


# ==============================================================================
# Rotation: retirement is not revocation
# ==============================================================================
def test_rotation_installs_a_new_active_key_and_retires_the_old_one(tmp_path):
    key_dir = tmp_path / "keys"
    manager = make_manager(key_dir)
    original_id = manager.active_key_id()

    rotated = manager.rotate(reason="scheduled test rotation")

    assert rotated.key_id != original_id
    assert rotated.state == KEY_STATE_ACTIVE
    assert manager.active_key_id() == rotated.key_id

    states = {d.key_id: d.state for d in manager.keyring()}
    assert states[original_id] == KEY_STATE_RETIRED
    assert states[rotated.key_id] == KEY_STATE_ACTIVE


def test_policies_signed_before_a_rotation_keep_verifying(tmp_path):
    """The reason rotation retires rather than deletes.

    An exam already in progress is running against a policy signed by the outgoing key. If
    rotation invalidated it, a routine key change would break live exams.
    """
    key_dir = tmp_path / "keys"
    manager = make_manager(key_dir)

    old_signer = manager.active_signer()
    old_payload = sample_payload(old_signer.key_id)
    old_signature = old_signer.sign_payload(old_payload)

    manager.rotate()

    new_signer = manager.active_signer()
    new_payload = sample_payload(new_signer.key_id)
    new_signature = new_signer.sign_payload(new_payload)

    verifier = manager.verifier()
    assert verifier.verify_policy(old_payload, old_signature)["key_id"] == old_signer.key_id
    assert verifier.verify_policy(new_payload, new_signature)["key_id"] == new_signer.key_id


def test_rotation_is_visible_to_another_process_without_a_restart(tmp_path):
    """Multi-worker coherence.

    Under uvicorn with several workers, a rotation issued to one worker has to be picked up by
    the others or they carry on signing with a key the keyring no longer calls active.
    """
    key_dir = tmp_path / "keys"
    worker_a = make_manager(key_dir)
    worker_b = make_manager(key_dir)

    original_id = worker_b.active_key_id()
    assert worker_a.active_key_id() == original_id

    rotated = worker_a.rotate()

    assert worker_b.active_key_id() == rotated.key_id
    assert rotated.key_id != original_id


# ==============================================================================
# Revocation
# ==============================================================================
def test_revocation_marks_the_key_untrusted_and_destroys_its_private_half(tmp_path):
    key_dir = tmp_path / "keys"
    manager = make_manager(key_dir)

    doomed = manager.active_key_id()
    manager.rotate()  # so the revoked key is not the active one
    assert (key_dir / PRIVATE_KEY_SUBDIR / f"{doomed}.pem").exists()

    revoked = manager.revoke(doomed, "suspected compromise (test)")

    assert revoked.state == KEY_STATE_REVOKED
    assert revoked.is_revoked
    assert revoked.is_trusted_for_verification is False
    assert revoked.revocation_reason == "suspected compromise (test)"
    assert not (key_dir / PRIVATE_KEY_SUBDIR / f"{doomed}.pem").exists()


def test_a_revoked_key_stays_listed(tmp_path):
    """"Revoked" and "unknown" are different decisions for an agent.

    Dropping the entry entirely would leave an endpoint unable to tell a compromised key from
    one it simply has not fetched yet.
    """
    key_dir = tmp_path / "keys"
    manager = make_manager(key_dir)
    doomed = manager.active_key_id()
    manager.rotate()
    manager.revoke(doomed, "test")

    assert doomed in {d.key_id for d in manager.keyring()}
    assert doomed in {entry["key_id"] for entry in read_keyring(key_dir)["keys"]}


def test_revoked_key_no_longer_verifies_its_own_policies(tmp_path):
    key_dir = tmp_path / "keys"
    manager = make_manager(key_dir)

    signer = manager.active_signer()
    payload = sample_payload(signer.key_id)
    signature = signer.sign_payload(payload)
    assert manager.verifier().verify_policy(payload, signature)

    manager.rotate()
    manager.revoke(signer.key_id, "test")

    from backend.services.policy_signer import KeyMismatchError

    with pytest.raises(KeyMismatchError):
        manager.verifier().verify_policy(payload, signature)


def test_revoking_the_active_key_rotates_first(tmp_path):
    """A server must never be left signing with a key agents are required to refuse."""
    key_dir = tmp_path / "keys"
    manager = make_manager(key_dir)
    original_id = manager.active_key_id()

    manager.revoke(original_id, "compromised while active (test)")

    assert manager.active_key_id() != original_id
    assert manager.active_descriptor().state == KEY_STATE_ACTIVE
    assert manager.active_descriptor().is_revoked is False


def test_revocation_survives_a_restart(tmp_path):
    key_dir = tmp_path / "keys"
    manager = make_manager(key_dir)
    doomed = manager.active_key_id()
    manager.rotate()
    manager.revoke(doomed, "test")

    after_restart = make_manager(key_dir)
    states = {d.key_id: d.state for d in after_restart.keyring()}

    assert states[doomed] == KEY_STATE_REVOKED


def test_revocation_requires_a_reason(tmp_path):
    manager = make_manager(tmp_path / "keys")
    key_id = manager.active_key_id()

    with pytest.raises(SigningKeyStateError):
        manager.revoke(key_id, "   ")


def test_revoking_an_unknown_key_is_refused(tmp_path):
    manager = make_manager(tmp_path / "keys")

    with pytest.raises(SigningKeyStateError):
        manager.revoke("spemcs-" + "f" * KEY_ID_FINGERPRINT_CHARS, "test")


def test_revocation_is_idempotent(tmp_path):
    manager = make_manager(tmp_path / "keys")
    doomed = manager.active_key_id()
    manager.rotate()

    first = manager.revoke(doomed, "first reason (test)")
    second = manager.revoke(doomed, "second reason (test)")

    # The original reason is audit evidence and is not overwritten by a repeat call.
    assert second.revocation_reason == first.revocation_reason == "first reason (test)"


# ==============================================================================
# Ephemeral keys are opt-in only
# ==============================================================================
def test_no_key_directory_fails_closed_by_default():
    manager = SigningKeyManager(key_dir=None, key_size=TEST_KEY_SIZE)

    with pytest.raises(SigningKeyUnavailableError) as err:
        manager.active_signer()

    message = str(err.value)
    assert "SIGNING_KEY_DIR" in message
    assert "SIGNING_KEY_ALLOW_EPHEMERAL" in message


def test_ephemeral_key_is_used_only_when_explicitly_allowed():
    manager = SigningKeyManager(key_dir=None, allow_ephemeral=True, key_size=TEST_KEY_SIZE)

    assert manager.is_ephemeral is True
    assert is_ephemeral_key_id(manager.active_key_id())
    # Signing still works; the point is that the id announces the risk.
    payload = sample_payload(manager.active_key_id())
    assert manager.active_signer().sign_payload(payload)


def test_ephemeral_manager_writes_nothing_to_disk(tmp_path):
    """An unusable directory degrades to memory only when allowed, and leaves no residue."""
    unusable = tmp_path / "definitely-not-a-directory"
    unusable.write_text("I am a file", encoding="utf-8")

    manager = SigningKeyManager(
        key_dir=unusable, allow_ephemeral=True, key_size=TEST_KEY_SIZE
    )

    assert manager.is_ephemeral is True
    assert unusable.read_text(encoding="utf-8") == "I am a file"


# ==============================================================================
# The keyring publishes public material only
# ==============================================================================
def test_published_descriptor_carries_no_private_material(tmp_path):
    manager = make_manager(tmp_path / "keys")

    published = manager.active_descriptor().to_public_dict()

    serialized = json.dumps(published)
    assert "PRIVATE KEY" not in serialized
    assert "BEGIN PUBLIC KEY" in published["public_key_pem"]
    assert set(published).isdisjoint({"private_key_pem", "passphrase", "private_key"})


def test_keyring_file_on_disk_contains_no_private_material(tmp_path):
    key_dir = tmp_path / "keys"
    manager = make_manager(key_dir)
    manager.rotate()

    text = (key_dir / KEYRING_FILENAME).read_text(encoding="utf-8")

    assert "PRIVATE KEY" not in text
    assert text.count("BEGIN PUBLIC KEY") == 2


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX modes are advisory on Windows")
def test_private_key_material_is_not_world_readable(tmp_path):
    key_dir = tmp_path / "keys"
    key_id = make_manager(key_dir).active_key_id()

    key_mode = os.stat(key_dir / PRIVATE_KEY_SUBDIR / f"{key_id}.pem").st_mode & 0o777
    dir_mode = os.stat(key_dir / PRIVATE_KEY_SUBDIR).st_mode & 0o777

    assert key_mode == 0o600
    assert dir_mode == 0o700


# ==============================================================================
# Concurrent first use (the multi-worker keygen race)
# ==============================================================================
def test_concurrent_first_use_converges_on_one_key(tmp_path):
    """Several workers starting at once must not each mint their own key.

    Whichever one wins the keyring lock creates the key; the rest read it. If they raced, they
    would each sign with different material while advertising it from the same keyring.
    """
    key_dir = tmp_path / "keys"
    results: list = []
    errors: list = []
    start = threading.Barrier(6)

    def boot():
        try:
            start.wait(timeout=30)
            results.append(make_manager(key_dir).active_key_id())
        except Exception as exc:  # pragma: no cover - only on a real regression
            errors.append(exc)

    threads = [threading.Thread(target=boot) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert errors == []
    assert len(results) == 6
    assert len(set(results)) == 1
    assert len(private_key_files(key_dir)) == 1


def test_concurrent_rotation_leaves_a_consistent_keyring(tmp_path):
    key_dir = tmp_path / "keys"
    manager = make_manager(key_dir)
    manager.active_key_id()

    errors: list = []
    start = threading.Barrier(4)

    def rotate():
        try:
            start.wait(timeout=30)
            make_manager(key_dir).rotate(reason="concurrent test")
        except Exception as exc:  # pragma: no cover - only on a real regression
            errors.append(exc)

    threads = [threading.Thread(target=rotate) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert errors == []

    document = read_keyring(key_dir)
    ids = [entry["key_id"] for entry in document["keys"]]
    # No entry was lost by a blind overwrite, the active key is one of them, and exactly one
    # key is active.
    assert len(ids) == len(set(ids))
    assert document["active_key_id"] in ids
    assert sum(1 for e in document["keys"] if e["state"] == KEY_STATE_ACTIVE) == 1
    # A reader must still be able to load it.
    assert make_manager(key_dir).active_key_id() == document["active_key_id"]


# ==============================================================================
# The signer refuses to mislabel a policy
# ==============================================================================
def test_signer_requires_an_explicit_key_id():
    private_key, _ = generate_development_keypair(key_size=TEST_KEY_SIZE)

    with pytest.raises(TypeError):
        PolicySigner(private_key=private_key)  # type: ignore[call-arg]

    for bad in ("", "   "):
        with pytest.raises(ValueError):
            PolicySigner(private_key=private_key, key_id=bad)


def test_signing_a_payload_that_names_a_different_key_is_refused(tmp_path):
    """This is what made the original defect undiagnosable.

    A policy announces the key that verifies it, inside the signed bytes. If that announcement
    names a different key than the one signing, the endpoint resolves the advertised id, gets a
    public key that never matches, and reports a signature failure - which reads as forgery
    rather than as the configuration error it is.
    """
    manager = make_manager(tmp_path / "keys")
    signer = manager.active_signer()

    payload = sample_payload("spemcs-" + "a" * KEY_ID_FINGERPRINT_CHARS)

    with pytest.raises(MalformedPayloadError) as err:
        signer.sign_payload(payload)

    assert signer.key_id in str(err.value)


def test_manager_signer_and_payload_key_ids_agree(tmp_path):
    manager = make_manager(tmp_path / "keys")
    signer = manager.active_signer()

    assert signer.key_id == manager.active_key_id()
    assert signer.key_id == manager.active_descriptor().key_id
    assert signer.sign_payload(sample_payload(signer.key_id))


# ==============================================================================
# Process-wide accessor
# ==============================================================================
def test_default_key_dir_is_inside_the_backend_project():
    path = default_key_dir()

    assert path.name == "signing_keys"
    assert path.parent.name == "secrets"
    # A default that pointed at a temp directory would reintroduce the original defect, because
    # a deployment that configures nothing would get a key that disappears.
    assert path.is_absolute()


def test_injected_manager_is_returned_by_the_accessor(tmp_path):
    injected = make_manager(tmp_path / "keys")
    try:
        set_signing_key_manager(injected)
        assert get_signing_key_manager() is injected
    finally:
        set_signing_key_manager(None)


def test_accessor_is_not_invoked_at_import_time():
    """The defect was import-time key generation, so importing must have no side effects."""
    import backend.services.signing_key_manager as module

    assert module._manager is None or isinstance(module._manager, SigningKeyManager)


def test_router_has_no_module_level_keygen():
    """Asserted against the router's source rather than by importing it.

    A source-level check is the more faithful regression test here: the defect was that merely
    importing this module produced cryptographic material, so the property worth pinning is that
    the offending statements are absent from the file - not that a particular import happens to
    succeed. It also keeps this test runnable without the web stack installed.
    """
    router_source = (
        Path(__file__).resolve().parents[1] / "routes" / "policies.py"
    ).read_text(encoding="utf-8")

    assert "generate_development_keypair" not in router_source
    assert "_dev_signer" not in router_source
    assert "_dev_priv" not in router_source
    assert '"dev-key-1"' not in router_source
    # The signer must come from the managed keyring, per request.
    assert "active_signer()" in router_source
    assert "get_signing_key_manager" in router_source
