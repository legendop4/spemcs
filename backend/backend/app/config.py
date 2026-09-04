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

    # Auth
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
