"""Centralized application configuration loaded from environment variables."""

import os
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings
from typing import List


def _find_dotenv() -> str | None:
    """Walk up from this file to find a .env in the repo root."""
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        candidate = os.path.join(current, ".env")
        if os.path.isfile(candidate):
            return candidate
        current = os.path.dirname(current)
    return None


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str

    # ── Deployment environment ───────────────────────────────────
    # Governs whether placeholder secrets are tolerated. It defaults to "production" on purpose:
    # the failure mode being closed off here is a real deployment that silently runs on the
    # committed development defaults below, and a default of "development" would leave exactly
    # that deployment unprotected while looking configured. A developer sees one clear startup
    # error naming the variable to set; a production operator who forgets cannot boot at all.
    SPEMCS_ENV: str = "production"

    # Auth
    # NOTE: the default is a PLACEHOLDER and is refused by validate_production_secrets() outside
    # development. It is kept (rather than made required) so that importing this module never
    # fails - tests, tooling and the parity harness all import settings - while startup still
    # refuses to serve traffic on it.
    SECRET_KEY: str = "dev-secret-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours
    ALGORITHM: str = "HS256"

    # CORS
    # Development browser requests are same-origin through Vite's /api proxy.
    # Deployments that bypass that proxy can supply an explicit JSON list here.
    CORS_ORIGINS: List[str] = []

    # WebSocket
    WS_HEARTBEAT_INTERVAL: int = 30  # seconds
    WS_HEARTBEAT_TIMEOUT: int = 10   # seconds

    # M8 Security
    DEVICE_TOKEN_SECRET: str = "dev-device-token-secret-change-in-production"
    ENROLLMENT_BOOTSTRAP_KEY: str = "spemcs-enrollment-bootstrap-key-default"

    # ── Policy signing key material ──────────────────────────────
    # Directory holding the RSA policy-signing keyring. The private key is generated ONCE and
    # reused, so restarting the backend does not invalidate policies that were already compiled
    # and distributed. Empty means the default under the backend project root
    # (see services.signing_key_manager.default_key_dir).
    SIGNING_KEY_DIR: str = Field(
        default="",
        validation_alias=AliasChoices("SIGNING_KEY_DIR", "SPEMCS_SIGNING_KEY_DIR"),
    )

    # Optional passphrase used to encrypt the stored private key (PKCS#8). Leave empty to store
    # it unencrypted and protect it with filesystem permissions instead. Changing this value
    # does NOT re-encrypt an existing key - rotate the key to apply it.
    SIGNING_KEY_PASSPHRASE: str = Field(
        default="",
        validation_alias=AliasChoices("SIGNING_KEY_PASSPHRASE", "SPEMCS_SIGNING_KEY_PASSPHRASE"),
    )

    # Allow falling back to an in-memory signing key when no writable key directory exists.
    # OFF by default and must stay off outside throwaway environments: an ephemeral key makes
    # every policy signed by the process unverifiable after it exits, which surfaces as an exam
    # that cannot start rather than as a configuration error.
    SIGNING_KEY_ALLOW_EPHEMERAL: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "SIGNING_KEY_ALLOW_EPHEMERAL", "SPEMCS_SIGNING_KEY_ALLOW_EPHEMERAL"
        ),
    )

    # ── Trusted destination resolution (requirement 3) ───────────
    # Comma-separated IP addresses of the DNS servers this backend trusts to resolve vendor and
    # exam destination domains into firewall allowlist addresses. They must be addresses, not
    # names: resolving the resolver would be circular. Empty means no domain resolution is
    # available, in which case a vendor profile that declares domains fails policy compilation
    # loudly rather than compiling an allowlist that silently omits them.
    #
    # These are the *backend's* resolvers for building policies. They are unrelated to what the
    # endpoint is allowed to query during an exam.
    TRUSTED_DNS_SERVERS: str = Field(
        default="",
        validation_alias=AliasChoices("TRUSTED_DNS_SERVERS", "SPEMCS_TRUSTED_DNS_SERVERS"),
    )

    # Fall back to the host's own resolver (getaddrinfo) when no trusted servers are configured.
    # OFF by default: answers would come from whatever nameserver the backend host happens to
    # have, which is not a basis for trusting an address enough to sign it into an allowlist.
    POLICY_DNS_ALLOW_SYSTEM_RESOLVER: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "POLICY_DNS_ALLOW_SYSTEM_RESOLVER", "SPEMCS_POLICY_DNS_ALLOW_SYSTEM_RESOLVER"
        ),
    )

    POLICY_DNS_TIMEOUT_SECONDS: float = 3.0
    POLICY_DNS_ATTEMPTS: int = 2

    # Caps on allowlist expansion. Every resolved address becomes a firewall rule that has to be
    # applied at activation and undone at rollback, so an unbounded DNS answer would become an
    # unbounded rule set. Exceeding a cap is a hard error, never a silent truncation.
    POLICY_MAX_ADDRESSES_PER_DOMAIN: int = 32
    POLICY_MAX_ADDRESSES_PER_POLICY: int = 256

    # Permit RFC 1918 / unique-local destinations. On by default because on-premises examination
    # servers are legitimate; a deployment whose destinations are all public can turn it off to
    # stop a private range reaching an allowlist. Loopback, link-local (including the cloud
    # metadata address), multicast and tunnel ranges are refused regardless of this setting.
    POLICY_ALLOW_PRIVATE_DESTINATIONS: bool = True

    model_config = {
        "env_file": _find_dotenv(),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

settings = Settings()


# ══════════════════════════════════════════════════════════════════════════════
# Fail-closed secret validation
# ══════════════════════════════════════════════════════════════════════════════
# Three shared secrets in this file ship with working development defaults, and every one of
# them is a full authentication bypass when a real deployment keeps it:
#
#   SECRET_KEY               - signs operator JWTs. Knowing it lets anyone mint an admin token.
#   DEVICE_TOKEN_SECRET      - HMAC key for device enrolment tokens. Knowing it lets anyone forge
#                              a device identity and speak on the agent WebSocket as any endpoint.
#   ENROLLMENT_BOOTSTRAP_KEY - gate on device registration. Knowing it lets anyone enrol.
#
# A default that works is a default nobody notices, so these are checked at startup rather than
# documented. The checks are a plain function, NOT a pydantic validator, because settings is
# imported by tests, by the policy-compiler parity harness and by tooling that has no business
# needing production credentials; making import fail would break all of them and would tempt
# somebody to weaken the check instead of configuring the secret.
#
# WHAT IS DELIBERATELY NOT DONE HERE: the values are never logged, echoed, included in the
# exception message, hashed into it, or length-reported. Every diagnostic names the ENVIRONMENT
# VARIABLE and the reason only. An error message is the one place a secret leak looks helpful.

#: Values that are known-public because they are committed to this repository. Membership is by
#: exact match: a deployment that appends to one of these is deliberately deriving from a public
#: string and should still be refused, but that requires entropy checks rather than a set, and
#: the minimum-length rule below covers the realistic cases.
PLACEHOLDER_SECRETS = frozenset({
    "dev-secret-change-in-production",
    "dev-device-token-secret-change-in-production",
    "spemcs-enrollment-bootstrap-key-default",
    "changeme",
    "change-me",
    "secret",
    "password",
})

#: Minimum characters for an HMAC/JWT shared secret. HS256 keys shorter than the 32-byte hash
#: output add no security beyond their own length, and the committed development SECRET_KEY is
#: 20 characters, so this rule catches it independently of the exact-match set above.
MIN_SECRET_LENGTH = 32

#: Secrets required to be strong. Name only - never paired with its value in any diagnostic.
_REQUIRED_STRONG_SECRETS = (
    "SECRET_KEY",
    "DEVICE_TOKEN_SECRET",
    "ENROLLMENT_BOOTSTRAP_KEY",
)

#: Attached to every "this secret is not good enough" diagnostic. An operator who is told the value
#: is unacceptable but not how to produce an acceptable one reaches for whatever is to hand, and
#: what is to hand is usually another short memorable string.
_GENERATE_HINT = 'Generate one: python -c "import secrets; print(secrets.token_urlsafe(48))"'


class InsecureConfigurationError(RuntimeError):
    """Raised when startup would otherwise serve traffic on placeholder or missing secrets."""


def is_production(cfg: "Settings | None" = None) -> bool:
    """True unless SPEMCS_ENV explicitly names a non-production environment."""
    env = ((cfg or settings).SPEMCS_ENV or "").strip().lower()
    return env not in {"development", "dev", "test", "testing", "local"}


def describe_secret_problems(cfg: "Settings | None" = None) -> list[str]:
    """Return one human-readable problem per insecure secret, or an empty list.

    Returns descriptions rather than raising so that a caller can log every problem at once
    instead of an operator fixing them one restart at a time. No returned string contains any
    part of a secret value.
    """
    cfg = cfg or settings
    problems: list[str] = []

    for name in _REQUIRED_STRONG_SECRETS:
        value = getattr(cfg, name, None)
        if value is None or not str(value).strip():
            problems.append(
                f"{name} is not set. Supply it through the environment. {_GENERATE_HINT}"
            )
            continue
        value = str(value)
        if value in PLACEHOLDER_SECRETS:
            problems.append(
                f"{name} is set to a placeholder value that is committed to this repository "
                f"and must be treated as public. {_GENERATE_HINT}"
            )
        elif len(value) < MIN_SECRET_LENGTH:
            problems.append(
                f"{name} is shorter than the {MIN_SECRET_LENGTH}-character minimum for an "
                f"HMAC/JWT shared secret. {_GENERATE_HINT}"
            )

    # An ephemeral policy-signing key makes every policy signed by this process unverifiable once
    # it exits, which surfaces to an invigilator as an exam that cannot start. That is a
    # configuration error, not a runtime condition, so it is refused here rather than discovered
    # at activation time. This does NOT change the signing-key lifecycle itself - it only refuses
    # the escape hatch that bypasses it.
    if cfg.SIGNING_KEY_ALLOW_EPHEMERAL:
        problems.append(
            "SIGNING_KEY_ALLOW_EPHEMERAL is enabled. An in-memory signing key cannot verify "
            "policies after a restart; configure SIGNING_KEY_DIR instead."
        )

    return problems


def validate_production_secrets(cfg: "Settings | None" = None) -> list[str]:
    """Refuse to start on insecure secrets when running as production.

    Returns the problem list (empty when the configuration is sound) so a development run can
    log warnings on the same data the production path refuses on. Raises
    :class:`InsecureConfigurationError` only when :func:`is_production` holds.
    """
    cfg = cfg or settings
    problems = describe_secret_problems(cfg)
    if problems and is_production(cfg):
        raise InsecureConfigurationError(
            "Refusing to start: insecure secret configuration.\n  - "
            + "\n  - ".join(problems)
            + "\n\nSet SPEMCS_ENV=development to run locally with development defaults."
        )
    return problems
