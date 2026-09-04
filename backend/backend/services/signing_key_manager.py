"""Persistent policy-signing key lifecycle.

WHY THIS MODULE EXISTS
======================
The signing key used to be created like this, at module import time, inside
``routes/policies.py``::

    _dev_priv, _ = generate_development_keypair()
    _dev_signer = PolicySigner(private_key=_dev_priv, key_id="dev-key-1")

Three separate failures came out of those two lines:

1. **A brand new RSA keypair on every process start.** Restarting the backend (a deploy, a
   crash, an autoreload, a second uvicorn worker) silently replaced the signing key. Every
   policy already compiled and distributed became unverifiable.
2. **A constant ``key_id`` over changing key material.** The endpoint agent resolves a policy's
   ``key_id`` against its trusted key store. Because every generation reused the string
   ``"dev-key-1"``, the agent could not tell the old key from the new one: it looked the id up,
   found a key, and failed the *signature* check instead of reporting a key mismatch. The
   diagnostic pointed at forgery when the real cause was a restart.
3. **Fail-open by accident.** A missing or unreadable key was indistinguishable from a first
   run, so the system's response to lost key material was to quietly mint replacement material.

Because SPEMCS fails closed on an unverifiable policy, defect 1 is an availability failure that
lands mid-exam: the candidate's endpoint refuses the policy, the lockdown never activates, and
the exam cannot start.

DESIGN
======
* **Load-or-create-once.** Key material lives on disk and is generated exactly once, under a
  cross-process lock, so concurrent workers converge on one key instead of racing.
* **``key_id`` is derived from the key material** - a SHA-256 fingerprint of the SPKI DER
  encoding (:func:`compute_key_id`). Two different keys therefore cannot share an id, and the
  same key always presents the same id. Defect 2 becomes structurally impossible rather than
  something a naming convention has to prevent.
* **Nothing is regenerated silently.** If a key is expected but unusable - file missing, wrong
  passphrase, corrupt PEM - the manager raises :class:`SigningKeyUnavailableError` and signing
  fails closed. Replacing key material is an explicit administrative act (:meth:`rotate`).
* **Rotation is additive.** The retired key keeps its entry, and its public half stays
  published, so policies signed before the rotation continue to verify. Only the *active* key
  changes.
* **Revocation is separate from retirement.** A retired key is still trusted for verification;
  a revoked key must be rejected outright. Agents mirror this distinction into their own trust
  store, and persist revocations locally so an offline endpoint still refuses a revoked key.

SECRET HANDLING
===============
This module writes private key material to disk. It never logs, returns, or serialises that
material: the only key bytes that leave here are SPKI public keys. Log lines carry the
``key_id`` and the file path, never the key or the passphrase. ``*.pem`` is covered by
``.gitignore``, and the key directory is additionally ignored by name.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .policy_signer import (
    RSA_KEY_SIZE_BITS,
    RSA_PUBLIC_EXPONENT,
    PolicySigner,
    PolicyVerifier,
    export_public_key_pem,
    load_public_key_pem,
)

logger = logging.getLogger(__name__)

# ==============================================================================
# Constants
# ==============================================================================

#: Number of hex characters of the SPKI SHA-256 digest kept in a key id. 32 hex chars is
#: 128 bits - far more than enough to make an accidental collision impossible, while leaving
#: the full id inside the 64-character ``network_policies.key_id`` column.
KEY_ID_FINGERPRINT_CHARS = 32

#: Prefix for a key whose private half is persisted and will survive a restart.
KEY_ID_PREFIX_PERSISTENT = "spemcs"

#: Prefix for an in-memory-only key. Deliberately visible in the id so that a policy row
#: signed by a throwaway key is self-identifying: if these appear in a real deployment's
#: database, the key directory was not writable and every one of those policies stopped
#: verifying at the next restart.
KEY_ID_PREFIX_EPHEMERAL = "ephemeral"

KEY_STATE_ACTIVE = "active"
KEY_STATE_RETIRED = "retired"
KEY_STATE_REVOKED = "revoked"

KEYRING_FILENAME = "keyring.json"
PRIVATE_KEY_SUBDIR = "private"
LOCK_FILENAME = ".keyring.lock"
KEYRING_SCHEMA_VERSION = 1

_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIR_MODE = 0o700
_KEYRING_FILE_MODE = 0o644

#: How long a lock file may sit untouched before it is treated as abandoned by a crashed
#: process. Generous compared with the work done under the lock (one RSA-2048 keygen plus two
#: small file writes) so a slow machine is never mistaken for a dead one.
_LOCK_STALE_SECONDS = 60.0

#: How long to wait for another process to finish its keyring mutation before failing closed.
_LOCK_TIMEOUT_SECONDS = 15.0


# ==============================================================================
# Errors
# ==============================================================================
class SigningKeyError(RuntimeError):
    """Base class for signing key lifecycle failures."""


class SigningKeyUnavailableError(SigningKeyError):
    """No usable signing key could be obtained, so nothing may be signed.

    Always a fail-closed outcome. Raised instead of generating replacement material, because
    silent regeneration is the defect this module exists to remove: it invalidates every
    previously issued policy while reporting success.
    """


class SigningKeyStateError(SigningKeyError):
    """A lifecycle request is not valid for the key's current state.

    Examples: revoking a key id the keyring has never seen, or revoking the only usable key
    without rotating first.
    """


# ==============================================================================
# Key identity
# ==============================================================================
def compute_key_id(public_key: rsa.RSAPublicKey, *, ephemeral: bool = False) -> str:
    """Derives a key id from the public key's SPKI DER encoding.

    The id is a pure function of the key material, which is the property that matters: an
    agent that has cached ``spemcs-<fingerprint>`` and is handed a *different* key can only
    ever see a different id, so it reports an honest key mismatch instead of a signature
    failure. Deriving rather than assigning also means the id needs no registry, is stable
    across processes and machines, and cannot be typo'd into a collision.

    The digest covers SPKI DER (not PEM) so that re-encoding, line wrapping, or trailing
    whitespace differences cannot change the id of an unchanged key.
    """
    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(spki_der).hexdigest()[:KEY_ID_FINGERPRINT_CHARS]
    prefix = KEY_ID_PREFIX_EPHEMERAL if ephemeral else KEY_ID_PREFIX_PERSISTENT
    return f"{prefix}-{fingerprint}"


def is_ephemeral_key_id(key_id: str) -> bool:
    """True when ``key_id`` names a key that was never persisted."""
    return isinstance(key_id, str) and key_id.startswith(f"{KEY_ID_PREFIX_EPHEMERAL}-")


# ==============================================================================
# Keyring entries
# ==============================================================================
@dataclass(frozen=True)
class SigningKeyDescriptor:
    """Everything publicly knowable about one signing key.

    Holds the public half only. There is deliberately no field capable of carrying private key
    material, so no serialisation of this type can leak a secret.
    """

    key_id: str
    public_key_pem: str
    state: str
    created_at: str
    retired_at: Optional[str] = None
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None

    @property
    def is_revoked(self) -> bool:
        return self.state == KEY_STATE_REVOKED

    @property
    def is_trusted_for_verification(self) -> bool:
        """Active and retired keys still verify; revoked keys never do.

        Retirement means "stop signing with this"; it does not invalidate the signatures the
        key already produced. Dropping retired keys from the published set would break every
        policy issued before the most recent rotation - which is exactly the outage this
        module was written to prevent, just triggered by rotation instead of restart.
        """
        return self.state in (KEY_STATE_ACTIVE, KEY_STATE_RETIRED)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "state": self.state,
            "created_at": self.created_at,
            "retired_at": self.retired_at,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
        }

    @staticmethod
    def from_dict(raw: Dict[str, Any]) -> "SigningKeyDescriptor":
        state = raw.get("state")
        if state not in (KEY_STATE_ACTIVE, KEY_STATE_RETIRED, KEY_STATE_REVOKED):
            raise SigningKeyUnavailableError(
                f"Keyring entry '{raw.get('key_id')}' has unrecognised state {state!r}."
            )
        key_id = raw.get("key_id")
        pem = raw.get("public_key_pem")
        if not isinstance(key_id, str) or not key_id:
            raise SigningKeyUnavailableError("Keyring entry is missing its key_id.")
        if not isinstance(pem, str) or "PUBLIC KEY" not in pem:
            raise SigningKeyUnavailableError(
                f"Keyring entry '{key_id}' is missing a SubjectPublicKeyInfo PEM."
            )
        return SigningKeyDescriptor(
            key_id=key_id,
            public_key_pem=pem,
            state=state,
            created_at=str(raw.get("created_at") or ""),
            retired_at=raw.get("retired_at"),
            revoked_at=raw.get("revoked_at"),
            revocation_reason=raw.get("revocation_reason"),
        )


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ==============================================================================
# Cross-process lock
# ==============================================================================
class _KeyringLock:
    """An ``O_EXCL`` lock file guarding every mutation of the key directory.

    Deliberately not ``fcntl``/``msvcrt`` based: the backend is developed on Windows and
    deployed on Linux, and an advisory lock that exists on only one of those would leave the
    keygen race open on the other. Creating a file exclusively is atomic on both.

    An abandoned lock (the holder was killed mid-write) is stolen once it is older than
    :data:`_LOCK_STALE_SECONDS`. Without that, one ``SIGKILL`` would wedge policy compilation
    permanently and the only recovery would be a manual file deletion nobody documents.
    """

    def __init__(self, path: Path, timeout: float = _LOCK_TIMEOUT_SECONDS):
        self._path = path
        self._timeout = timeout
        self._acquired = False

    def __enter__(self) -> "_KeyringLock":
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                fd = os.open(str(self._path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, _PRIVATE_FILE_MODE)
                try:
                    os.write(fd, f"{os.getpid()} {_utc_now_iso()}".encode("ascii"))
                finally:
                    os.close(fd)
                self._acquired = True
                return self
            except FileExistsError:
                if self._steal_if_stale():
                    continue
                if time.monotonic() >= deadline:
                    raise SigningKeyUnavailableError(
                        f"Timed out after {self._timeout:.0f}s waiting for the signing key lock at "
                        f"{self._path}. Another process may be holding it; remove the file only if "
                        "no backend process is running."
                    )
                time.sleep(0.05)
            except OSError as exc:
                raise SigningKeyUnavailableError(
                    f"Cannot create the signing key lock at {self._path}: {exc.strerror or exc}"
                ) from exc

    def _steal_if_stale(self) -> bool:
        try:
            age = time.time() - os.stat(str(self._path)).st_mtime
        except FileNotFoundError:
            return True  # released while we looked; retry immediately
        except OSError:
            return False
        if age < _LOCK_STALE_SECONDS:
            return False
        logger.warning(
            "Signing key lock %s is %.0fs old and is being treated as abandoned by a crashed process.",
            self._path, age,
        )
        try:
            os.unlink(str(self._path))
        except FileNotFoundError:
            pass
        except OSError:
            return False
        return True

    def __exit__(self, *exc_info: Any) -> None:
        if not self._acquired:
            return
        try:
            os.unlink(str(self._path))
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.warning("Could not release signing key lock %s: %s", self._path, exc)


def _atomic_write_bytes(path: Path, data: bytes, mode: int) -> None:
    """Writes ``data`` to ``path`` atomically, so a reader never sees a half-written file.

    A torn keyring or a truncated private key is unrecoverable in a way that a missing one is
    not: the manager would read plausible-but-wrong material and fail closed on every policy.
    The temp file is created in the destination directory so ``os.replace`` stays on one
    filesystem and therefore stays atomic.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=path.suffix)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp_name, mode)
        except OSError:
            # POSIX permissions are advisory on Windows; deployment relies on NTFS ACLs there.
            pass
        os.replace(tmp_name, str(path))
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# ==============================================================================
# The manager
# ==============================================================================
class SigningKeyManager:
    """Owns the policy signing key for the lifetime of the process.

    Thread-safe. Also tolerant of *other* processes mutating the same directory: the keyring
    file's identity (mtime, size, inode) is checked on access and re-read when it changes, so a
    rotation performed by one uvicorn worker is picked up by the rest without a restart.
    """

    def __init__(
        self,
        key_dir: Optional[Path | str],
        *,
        allow_ephemeral: bool = False,
        passphrase: Optional[str] = None,
        key_size: int = RSA_KEY_SIZE_BITS,
    ):
        self._key_dir = Path(key_dir).expanduser() if key_dir else None
        self._allow_ephemeral = bool(allow_ephemeral)
        self._passphrase = passphrase.encode("utf-8") if passphrase else None
        self._key_size = int(key_size)

        self._lock = threading.RLock()
        self._keys: Dict[str, SigningKeyDescriptor] = {}
        self._active_key_id: Optional[str] = None
        self._signer: Optional[PolicySigner] = None
        self._ephemeral = False
        self._keyring_stamp: Optional[tuple] = None

    # ------------------------------------------------------------------ paths
    @property
    def key_dir(self) -> Optional[Path]:
        return self._key_dir

    @property
    def is_ephemeral(self) -> bool:
        """True when the active key exists only in memory and dies with this process."""
        with self._lock:
            self._ensure_loaded()
            return self._ephemeral

    def _keyring_path(self) -> Path:
        assert self._key_dir is not None
        return self._key_dir / KEYRING_FILENAME

    def _private_key_path(self, key_id: str) -> Path:
        assert self._key_dir is not None
        return self._key_dir / PRIVATE_KEY_SUBDIR / f"{key_id}.pem"

    def _lock_path(self) -> Path:
        assert self._key_dir is not None
        return self._key_dir / LOCK_FILENAME

    # ----------------------------------------------------------- public reads
    def active_signer(self) -> PolicySigner:
        """The signer every policy compilation must use.

        Raises:
            SigningKeyUnavailableError: if no usable key exists. Callers must surface this as a
                configuration failure rather than falling back to anything: an unsigned or
                differently-signed policy is rejected by the endpoint anyway, and a policy
                signed by a key that will not exist after the next restart is worse than no
                policy at all.
        """
        with self._lock:
            self._ensure_loaded()
            assert self._signer is not None
            return self._signer

    def active_key_id(self) -> str:
        return self.active_signer().key_id

    def active_descriptor(self) -> SigningKeyDescriptor:
        with self._lock:
            self._ensure_loaded()
            assert self._active_key_id is not None
            return self._keys[self._active_key_id]

    def keyring(self) -> List[SigningKeyDescriptor]:
        """Every key this server has ever signed with, newest first.

        Includes retired and revoked keys on purpose. An agent needs the retired ones to verify
        policies issued before a rotation, and needs the revoked ones to know which key_ids to
        refuse - a key silently dropped from the list is indistinguishable from one the agent
        simply has not fetched yet, and "unknown" is not the same decision as "revoked".
        """
        with self._lock:
            self._ensure_loaded()
            return sorted(self._keys.values(), key=lambda d: (d.created_at, d.key_id), reverse=True)

    def verifier(self) -> PolicyVerifier:
        """A verifier seeded with every key that is still trusted for verification."""
        verifier = PolicyVerifier()
        for descriptor in self.keyring():
            if descriptor.is_trusted_for_verification:
                verifier.add_trusted_key(descriptor.key_id, load_public_key_pem(descriptor.public_key_pem))
        return verifier

    # ------------------------------------------------------------- public ops
    def rotate(self, reason: Optional[str] = None) -> SigningKeyDescriptor:
        """Generates a new active key and retires the current one.

        Retirement is not revocation: the outgoing key stays published and keeps verifying the
        policies it already signed. Only newly compiled policies use the new key.
        """
        with self._lock:
            self._ensure_loaded()
            if self._ephemeral:
                # Nothing durable to mutate, but rotation is still meaningful in-process and is
                # what the tests exercise. It is explicitly not persisted.
                previous = self._active_key_id
                descriptor, signer = self._generate_in_memory_key()
                if previous:
                    self._keys[previous] = replace(
                        self._keys[previous], state=KEY_STATE_RETIRED, retired_at=_utc_now_iso()
                    )
                self._keys[descriptor.key_id] = descriptor
                self._active_key_id = descriptor.key_id
                self._signer = signer
                logger.warning(
                    "Rotated the EPHEMERAL signing key to '%s'; this rotation is not persisted.",
                    descriptor.key_id,
                )
                return descriptor

            with _KeyringLock(self._lock_path()):
                # Re-read under the lock: another worker may have rotated while we waited, and
                # rotating again would retire a key that was never used to sign anything.
                self._read_keyring_locked(required=True)
                previous_id = self._active_key_id
                descriptor = self._create_persistent_key_locked()
                if previous_id and previous_id != descriptor.key_id:
                    self._keys[previous_id] = replace(
                        self._keys[previous_id], state=KEY_STATE_RETIRED, retired_at=_utc_now_iso()
                    )
                self._active_key_id = descriptor.key_id
                self._write_keyring_locked()
                self._signer = self._signer_for_locked(descriptor.key_id)

            logger.info(
                "Rotated policy signing key: active is now '%s' (previous '%s' retired). Reason: %s",
                descriptor.key_id, previous_id, reason or "not stated",
            )
            return self._keys[descriptor.key_id]

    def revoke(self, key_id: str, reason: str) -> SigningKeyDescriptor:
        """Marks ``key_id`` untrusted, so signatures it produced must be rejected.

        Revoking the active key rotates first, then revokes: leaving the server with a revoked
        active key would mean every subsequent policy is signed by a key agents are required to
        refuse, which fails closed in the least diagnosable way possible - the signature is
        valid, the key is known, and the policy is rejected anyway.
        """
        if not isinstance(key_id, str) or not key_id.strip():
            raise SigningKeyStateError("A key id is required to revoke a signing key.")
        if not isinstance(reason, str) or not reason.strip():
            raise SigningKeyStateError("A revocation reason is required; it is audit evidence.")

        key_id = key_id.strip()
        with self._lock:
            self._ensure_loaded()
            if key_id not in self._keys:
                raise SigningKeyStateError(
                    f"Signing key '{key_id}' is not in this server's keyring; refusing to record a "
                    "revocation for a key it never issued."
                )
            if self._keys[key_id].is_revoked:
                return self._keys[key_id]

            if key_id == self._active_key_id:
                logger.warning(
                    "Revoking the ACTIVE signing key '%s'; rotating to a fresh key first.", key_id
                )
                self.rotate(reason=f"Forced by revocation of {key_id}")

            now = _utc_now_iso()
            self._keys[key_id] = replace(
                self._keys[key_id],
                state=KEY_STATE_REVOKED,
                revoked_at=now,
                revocation_reason=reason.strip(),
            )

            if not self._ephemeral:
                with _KeyringLock(self._lock_path()):
                    # Merge into whatever is on disk now rather than overwriting it: another
                    # worker may have rotated in the meantime, and a blind write would resurrect
                    # a stale active_key_id.
                    revoked = self._keys[key_id]
                    self._read_keyring_locked(required=True)
                    self._keys[key_id] = revoked
                    self._write_keyring_locked()
                self._delete_private_key_material(key_id)

            logger.warning("Signing key '%s' revoked. Reason: %s", key_id, reason.strip())
            return self._keys[key_id]

    # ------------------------------------------------------------- load paths
    def _ensure_loaded(self) -> None:
        """Loads the key on first use and re-reads the keyring when it changes on disk."""
        if self._signer is None:
            self._load()
            return
        if self._ephemeral or self._key_dir is None:
            return
        if self._keyring_stamp != self._stat_keyring():
            logger.info("Signing keyring changed on disk; reloading.")
            self._load()

    def _stat_keyring(self) -> Optional[tuple]:
        try:
            st = os.stat(str(self._keyring_path()))
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def _load(self) -> None:
        if self._key_dir is None:
            self._load_ephemeral("no signing key directory is configured")
            return

        try:
            self._key_dir.mkdir(parents=True, exist_ok=True)
            private_dir = self._key_dir / PRIVATE_KEY_SUBDIR
            private_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(str(private_dir), _PRIVATE_DIR_MODE)
            except OSError:
                pass  # Windows: ACLs, not modes.
        except OSError as exc:
            self._load_ephemeral(
                f"signing key directory {self._key_dir} is not usable ({exc.strerror or exc})"
            )
            return

        with _KeyringLock(self._lock_path()):
            self._read_keyring_locked(required=False)
            if self._active_key_id is None:
                descriptor = self._create_persistent_key_locked()
                self._active_key_id = descriptor.key_id
                self._write_keyring_locked()
                logger.info(
                    "Created the persistent policy signing key '%s' in %s.",
                    descriptor.key_id, self._key_dir,
                )
            self._signer = self._signer_for_locked(self._active_key_id)
            self._ephemeral = False
            self._keyring_stamp = self._stat_keyring()

        logger.info(
            "Policy signing key '%s' loaded (%d key(s) in keyring, %d revoked).",
            self._active_key_id,
            len(self._keys),
            sum(1 for d in self._keys.values() if d.is_revoked),
        )

    def _load_ephemeral(self, why: str) -> None:
        """Last resort for environments with no writable storage.

        Only reachable when ``allow_ephemeral`` was explicitly enabled. Otherwise this is a hard
        failure: an ephemeral key means every policy compiled in this process becomes
        unverifiable the moment it exits, and finding that out at exam time is far worse than
        finding out at startup that the key directory is misconfigured.
        """
        if not self._allow_ephemeral:
            raise SigningKeyUnavailableError(
                f"No persistent policy signing key is available: {why}. Set SIGNING_KEY_DIR to a "
                "writable directory, or set SIGNING_KEY_ALLOW_EPHEMERAL=true for throwaway "
                "development environments only - policies signed by an ephemeral key stop "
                "verifying as soon as the process restarts."
            )
        descriptor, signer = self._generate_in_memory_key()
        self._keys = {descriptor.key_id: descriptor}
        self._active_key_id = descriptor.key_id
        self._signer = signer
        self._ephemeral = True
        self._keyring_stamp = None
        logger.error(
            "USING AN EPHEMERAL POLICY SIGNING KEY '%s' because %s. Every policy signed by this "
            "process will fail verification after a restart. Never use this configuration for a "
            "real examination.",
            descriptor.key_id, why,
        )

    def _generate_in_memory_key(self) -> tuple[SigningKeyDescriptor, PolicySigner]:
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT, key_size=self._key_size
        )
        public_key = private_key.public_key()
        key_id = compute_key_id(public_key, ephemeral=True)
        descriptor = SigningKeyDescriptor(
            key_id=key_id,
            public_key_pem=export_public_key_pem(public_key),
            state=KEY_STATE_ACTIVE,
            created_at=_utc_now_iso(),
        )
        return descriptor, PolicySigner(private_key=private_key, key_id=key_id)

    # --------------------------------------------------- locked disk helpers
    # Every method below assumes the keyring lock is held by the caller.

    def _read_keyring_locked(self, *, required: bool) -> None:
        path = self._keyring_path()
        try:
            raw_bytes = path.read_bytes()
        except FileNotFoundError:
            if required:
                raise SigningKeyUnavailableError(
                    f"The signing keyring {path} disappeared. Refusing to continue with an "
                    "unknown key set."
                )
            self._keys = {}
            self._active_key_id = None
            return
        except OSError as exc:
            raise SigningKeyUnavailableError(
                f"Cannot read the signing keyring {path}: {exc.strerror or exc}"
            ) from exc

        try:
            document = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SigningKeyUnavailableError(
                f"The signing keyring {path} is not valid JSON ({exc}). It is not regenerated "
                "automatically: doing so would discard the record of which keys this server has "
                "issued. Restore it from backup or move it aside deliberately."
            ) from exc

        if not isinstance(document, dict):
            raise SigningKeyUnavailableError(f"The signing keyring {path} is not a JSON object.")

        version = document.get("schema_version")
        if version != KEYRING_SCHEMA_VERSION:
            raise SigningKeyUnavailableError(
                f"The signing keyring {path} declares schema_version {version!r}, but this build "
                f"understands {KEYRING_SCHEMA_VERSION}. Refusing to guess at its meaning."
            )

        entries = document.get("keys")
        if not isinstance(entries, list):
            raise SigningKeyUnavailableError(f"The signing keyring {path} has no 'keys' array.")

        keys: Dict[str, SigningKeyDescriptor] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise SigningKeyUnavailableError(f"The signing keyring {path} has a malformed entry.")
            descriptor = SigningKeyDescriptor.from_dict(entry)
            # The id is a fingerprint of the key, so it is verifiable rather than merely
            # declared. Recomputing it here catches a hand-edited or swapped keyring: without
            # this check an attacker with write access to the file could publish their own
            # public key under a key_id agents already trust.
            expected = compute_key_id(
                load_public_key_pem(descriptor.public_key_pem),
                ephemeral=is_ephemeral_key_id(descriptor.key_id),
            )
            if expected != descriptor.key_id:
                raise SigningKeyUnavailableError(
                    f"Keyring entry '{descriptor.key_id}' does not match the fingerprint of its own "
                    f"public key (expected '{expected}'). The keyring has been altered."
                )
            keys[descriptor.key_id] = descriptor

        active = document.get("active_key_id")
        if active is not None and active not in keys:
            raise SigningKeyUnavailableError(
                f"The signing keyring {path} names active key '{active}', which is not in its own "
                "key list."
            )
        if active is not None and keys[active].is_revoked:
            raise SigningKeyUnavailableError(
                f"The signing keyring {path} names revoked key '{active}' as active. Rotate to a "
                "fresh key before signing anything else."
            )

        self._keys = keys
        self._active_key_id = active

    def _write_keyring_locked(self) -> None:
        document = {
            "schema_version": KEYRING_SCHEMA_VERSION,
            "active_key_id": self._active_key_id,
            "updated_at": _utc_now_iso(),
            # Public halves only; see SigningKeyDescriptor.
            "keys": [d.to_public_dict() for d in self._keys.values()],
        }
        payload = json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
        _atomic_write_bytes(self._keyring_path(), payload, _KEYRING_FILE_MODE)
        self._keyring_stamp = self._stat_keyring()

    def _create_persistent_key_locked(self) -> SigningKeyDescriptor:
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT, key_size=self._key_size
        )
        public_key = private_key.public_key()
        key_id = compute_key_id(public_key)

        encryption: serialization.KeySerializationEncryption
        if self._passphrase:
            encryption = serialization.BestAvailableEncryption(self._passphrase)
        else:
            encryption = serialization.NoEncryption()

        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        try:
            _atomic_write_bytes(self._private_key_path(key_id), pem_bytes, _PRIVATE_FILE_MODE)
        except OSError as exc:
            raise SigningKeyUnavailableError(
                f"Generated a signing key but could not persist it to "
                f"{self._private_key_path(key_id)}: {exc.strerror or exc}"
            ) from exc
        finally:
            # Do not keep the serialised private key in a local any longer than needed.
            del pem_bytes

        descriptor = SigningKeyDescriptor(
            key_id=key_id,
            public_key_pem=export_public_key_pem(public_key),
            state=KEY_STATE_ACTIVE,
            created_at=_utc_now_iso(),
        )
        self._keys[key_id] = descriptor
        return descriptor

    def _signer_for_locked(self, key_id: Optional[str]) -> PolicySigner:
        if key_id is None:
            raise SigningKeyUnavailableError("The signing keyring has no active key.")
        path = self._private_key_path(key_id)
        try:
            pem_bytes = path.read_bytes()
        except FileNotFoundError as exc:
            # Deliberately NOT self-healing. Auto-generating a replacement here is the original
            # defect wearing a different hat: it would look like recovery while silently
            # invalidating nothing (new id) or everything (reused id), and it would erase the
            # evidence that key material went missing - which is also what a theft looks like.
            raise SigningKeyUnavailableError(
                f"The private key for active signing key '{key_id}' is missing from {path}. It is "
                "not regenerated automatically. Restore it from backup, or rotate deliberately "
                "via POST /api/policies/signing-key/rotate (previously issued policies will need "
                "recompiling)."
            ) from exc
        except OSError as exc:
            raise SigningKeyUnavailableError(
                f"Cannot read the private key for '{key_id}' from {path}: {exc.strerror or exc}"
            ) from exc

        try:
            private_key = serialization.load_pem_private_key(pem_bytes, password=self._passphrase)
        except TypeError:
            # Mismatch between how the file was written and how it is being read: either it is
            # encrypted and no passphrase was supplied, or the reverse. Retry the other way so a
            # passphrase added or removed in configuration is a clear error, not a mystery.
            try:
                private_key = serialization.load_pem_private_key(
                    pem_bytes, password=None if self._passphrase else b""
                )
            except Exception as exc:
                raise SigningKeyUnavailableError(
                    f"The private key for '{key_id}' is encrypted differently than configured. "
                    "Check SIGNING_KEY_PASSPHRASE; the key is not regenerated automatically."
                ) from exc
            if self._passphrase:
                # The retry only succeeds in one direction: a passphrase is configured but this
                # key predates it and sits on disk unencrypted. Loading it is correct (the key is
                # still the right key), but the configured protection is not actually in force,
                # and only a rotation can put it there - re-encrypting in place would rewrite key
                # material outside an explicit administrative action.
                logger.warning(
                    "SIGNING_KEY_PASSPHRASE is configured but the stored private key for '%s' is "
                    "not encrypted. Rotate the signing key to apply passphrase protection.",
                    key_id,
                )
        except ValueError as exc:
            raise SigningKeyUnavailableError(
                f"The private key for '{key_id}' could not be decrypted or parsed. Check "
                "SIGNING_KEY_PASSPHRASE and the file's integrity; the key is not regenerated "
                "automatically."
            ) from exc
        finally:
            del pem_bytes

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise SigningKeyUnavailableError(
                f"The key file for '{key_id}' does not hold an RSA private key."
            )

        # The file must actually be the key the keyring claims. Without this, replacing the PEM
        # on disk would let an attacker sign policies that agents accept under a trusted key_id.
        actual_id = compute_key_id(private_key.public_key())
        if actual_id != key_id:
            raise SigningKeyUnavailableError(
                f"The private key stored as '{key_id}' fingerprints as '{actual_id}'. The key "
                "directory has been tampered with or restored inconsistently."
            )

        return PolicySigner(private_key=private_key, key_id=key_id)

    def _delete_private_key_material(self, key_id: str) -> None:
        """Removes the private half of a revoked key so it cannot be used again by mistake.

        The public half stays in the keyring: agents need to know the id is revoked, and an id
        that simply vanished would read as "not fetched yet" instead of "refuse this".
        """
        path = self._private_key_path(key_id)
        try:
            os.unlink(str(path))
            logger.info("Deleted private key material for revoked key '%s'.", key_id)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.error(
                "Could not delete private key material for revoked key '%s' at %s: %s. Remove it "
                "manually.", key_id, path, exc,
            )


# ==============================================================================
# Process-wide accessor
# ==============================================================================
_manager_guard = threading.Lock()
_manager: Optional[SigningKeyManager] = None


def default_key_dir() -> Path:
    """``<backend project root>/secrets/signing_keys``.

    Chosen so a developer who sets nothing still gets a *persistent* key rather than a fresh
    one per restart - the failure this module removes must not come back as the default. The
    directory is covered by ``.gitignore`` (both by name and by the global ``*.pem`` rule).
    """
    # .../backend/backend/services/signing_key_manager.py -> .../backend
    project_root = Path(__file__).resolve().parents[2]
    return project_root / "secrets" / "signing_keys"


def get_signing_key_manager() -> SigningKeyManager:
    """The process-wide :class:`SigningKeyManager`, built from settings on first use.

    Construction is lazy on purpose. Building it at import time is how the original defect got
    in: importing a router should not be the thing that creates cryptographic material, and it
    makes the behaviour impossible to configure from a test.
    """
    global _manager
    with _manager_guard:
        if _manager is None:
            from backend.app.config import settings

            configured = (settings.SIGNING_KEY_DIR or "").strip()
            _manager = SigningKeyManager(
                key_dir=Path(configured) if configured else default_key_dir(),
                allow_ephemeral=settings.SIGNING_KEY_ALLOW_EPHEMERAL,
                passphrase=(settings.SIGNING_KEY_PASSPHRASE or None),
            )
        return _manager


def set_signing_key_manager(manager: Optional[SigningKeyManager]) -> None:
    """Replaces the process-wide manager. For tests and for explicit wiring only."""
    global _manager
    with _manager_guard:
        _manager = manager


__all__ = [
    "KEY_ID_FINGERPRINT_CHARS",
    "KEY_ID_PREFIX_EPHEMERAL",
    "KEY_ID_PREFIX_PERSISTENT",
    "KEY_STATE_ACTIVE",
    "KEY_STATE_RETIRED",
    "KEY_STATE_REVOKED",
    "KEYRING_FILENAME",
    "KEYRING_SCHEMA_VERSION",
    "PRIVATE_KEY_SUBDIR",
    "SigningKeyDescriptor",
    "SigningKeyError",
    "SigningKeyManager",
    "SigningKeyStateError",
    "SigningKeyUnavailableError",
    "compute_key_id",
    "default_key_dir",
    "get_signing_key_manager",
    "is_ephemeral_key_id",
    "set_signing_key_manager",
]
