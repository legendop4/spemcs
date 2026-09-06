"""Phase 19 fail-closed secret configuration coverage.

Nothing here reads, prints or asserts on a real configured secret. Every case builds its own
throwaway configuration object, so the tests are hermetic in the strongest sense: they never touch
``settings`` as loaded from the environment, never open the tracked ``.env.txt``, and cannot leak a
deployment value even if one is present on the machine running them.

The one exception is deliberate and safe: the tests that pin the module's *committed defaults*
reference those defaults by value, because a string checked into this repository is public by
definition and recognising it as public is the whole point of ``PLACEHOLDER_SECRETS``.
"""

from __future__ import annotations

import asyncio
import secrets
from types import SimpleNamespace

import pytest

from backend.app.config import (
    MIN_SECRET_LENGTH,
    PLACEHOLDER_SECRETS,
    InsecureConfigurationError,
    Settings,
    describe_secret_problems,
    is_production,
    validate_production_secrets,
)

#: Freshly generated per test run, so it is not a secret and cannot be reused as one.
STRONG = secrets.token_urlsafe(48)

REQUIRED = ("SECRET_KEY", "DEVICE_TOKEN_SECRET", "ENROLLMENT_BOOTSTRAP_KEY")


def _cfg(**overrides) -> SimpleNamespace:
    """A sound configuration, with the named fields replaced.

    A ``SimpleNamespace`` rather than a ``Settings``: the validation functions take any object with
    these attributes, and constructing a real ``Settings`` would load the environment file and pull
    the machine's actual credentials into the test process for no benefit. One test below does
    construct a real ``Settings`` to prove the production type flows through.
    """
    base = {
        "SPEMCS_ENV": "production",
        "SECRET_KEY": STRONG,
        "DEVICE_TOKEN_SECRET": STRONG,
        "ENROLLMENT_BOOTSTRAP_KEY": STRONG,
        "SIGNING_KEY_ALLOW_EPHEMERAL": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


# ── A sound configuration must start ──────────────────────────────────────────


def test_a_fully_configured_production_deployment_starts():
    """The falsifier for everything below.

    Without this, a validator that refused every configuration unconditionally would satisfy all
    the negative tests, and the backend would be unbootable.
    """
    assert describe_secret_problems(_cfg()) == []
    assert validate_production_secrets(_cfg()) == []


# ── Missing secrets ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", REQUIRED)
@pytest.mark.parametrize("empty", ["", "   ", None])
def test_missing_secret_is_refused_in_production(name, empty):
    with pytest.raises(InsecureConfigurationError):
        validate_production_secrets(_cfg(**{name: empty}))


@pytest.mark.parametrize("name", REQUIRED)
def test_missing_secret_names_the_variable_to_set(name):
    problems = describe_secret_problems(_cfg(**{name: ""}))
    assert len(problems) == 1
    assert name in problems[0]


def test_every_missing_secret_is_reported_at_once():
    """One restart per problem is how an operator ends up disabling the check.

    ``describe_secret_problems`` returns a list rather than raising on the first fault precisely so
    the startup log names all of them together.
    """
    problems = describe_secret_problems(
        _cfg(SECRET_KEY="", DEVICE_TOKEN_SECRET="", ENROLLMENT_BOOTSTRAP_KEY="")
    )
    assert len(problems) == 3


# ── Placeholder secrets ───────────────────────────────────────────────────────


@pytest.mark.parametrize("name", REQUIRED)
def test_each_committed_default_is_recognised_as_a_placeholder(name):
    """The defaults in config.py are checked into this repository, so they are public.

    This asserts the recognition rather than restating the strings: the code default is read out of
    the model and looked up in ``PLACEHOLDER_SECRETS``. Changing a default without adding it to that
    set - which is exactly how this protection silently lapses - fails here.
    """
    default = Settings.model_fields[name].default
    assert isinstance(default, str) and default
    assert default in PLACEHOLDER_SECRETS


@pytest.mark.parametrize("name", REQUIRED)
def test_placeholder_secret_is_refused_in_production(name):
    default = Settings.model_fields[name].default
    with pytest.raises(InsecureConfigurationError):
        validate_production_secrets(_cfg(**{name: default}))


@pytest.mark.parametrize("placeholder", sorted(PLACEHOLDER_SECRETS))
def test_no_known_public_string_can_serve_as_the_jwt_key(placeholder):
    problems = describe_secret_problems(_cfg(SECRET_KEY=placeholder))
    assert problems, f"a known-public value was accepted as SECRET_KEY"


@pytest.mark.parametrize("name", REQUIRED)
def test_a_short_secret_is_refused(name):
    """Length is checked independently of the placeholder set.

    Exact-match on a list of known strings only catches values somebody already thought of. A
    16-character secret nobody has seen before is still not an HS256 key.
    """
    short = secrets.token_urlsafe(8)[:MIN_SECRET_LENGTH - 1]
    problems = describe_secret_problems(_cfg(**{name: short}))
    assert len(problems) == 1
    assert name in problems[0]


def test_a_secret_of_exactly_the_minimum_length_is_accepted():
    """Pins the boundary, so the rule cannot drift into rejecting compliant configurations."""
    exact = "x" * MIN_SECRET_LENGTH
    assert describe_secret_problems(_cfg(SECRET_KEY=exact)) == []


# ── The ephemeral-signing-key escape hatch ────────────────────────────────────


def test_ephemeral_signing_key_is_refused_in_production():
    """An in-memory policy signing key is a configuration error, not a fallback.

    Every policy signed by the process becomes unverifiable once it exits, which reaches the
    invigilator as an exam that will not start rather than as a startup fault. Refusing it here
    does not alter the signing-key lifecycle itself - it closes the switch that bypasses it.
    """
    with pytest.raises(InsecureConfigurationError):
        validate_production_secrets(_cfg(SIGNING_KEY_ALLOW_EPHEMERAL=True))


def test_ephemeral_signing_key_default_is_off():
    assert Settings.model_fields["SIGNING_KEY_ALLOW_EPHEMERAL"].default is False


def test_ephemeral_signing_key_is_reported_even_when_secrets_are_sound():
    problems = describe_secret_problems(_cfg(SIGNING_KEY_ALLOW_EPHEMERAL=True))
    assert len(problems) == 1
    assert "SIGNING_KEY_ALLOW_EPHEMERAL" in problems[0]


# ── Environment classification ────────────────────────────────────────────────


def test_the_environment_default_is_production():
    """Fail closed on omission.

    A default of "development" would leave the one deployment this check exists for - a real one
    where nobody set the variable - completely unprotected while appearing configured. A developer
    who has not set it gets one clear error naming the variable; an operator who forgets cannot
    boot at all. That asymmetry is the design.
    """
    assert Settings.model_fields["SPEMCS_ENV"].default == "production"


@pytest.mark.parametrize("env", ["development", "dev", "test", "testing", "local",
                                "DEVELOPMENT", "  Dev  "])
def test_named_non_production_environments_downgrade_to_warnings(env):
    cfg = _cfg(SPEMCS_ENV=env, SECRET_KEY="")
    assert is_production(cfg) is False
    problems = validate_production_secrets(cfg)  # must not raise
    assert problems, "a development run must still report the problem it tolerates"


@pytest.mark.parametrize("env", ["production", "prod", "staging", "uat", "", "  ", "anything"])
def test_anything_else_is_treated_as_production(env):
    """Including the empty string and unrecognised names.

    "staging" holds real candidate data and is reachable from the same network as production; an
    allow-list of non-production names is the only safe shape for this check.
    """
    assert is_production(_cfg(SPEMCS_ENV=env)) is True


# ── No diagnostic may carry a secret ──────────────────────────────────────────


@pytest.mark.parametrize("name", REQUIRED)
def test_a_problem_description_never_contains_the_offending_value(name):
    """An error message is the one place a leaked secret looks like helpful diagnostics.

    Checked against a value distinctive enough that a substring match is meaningful, and against
    its halves so that a truncated or "redacted to the first few characters" report is caught too.
    """
    marker = "Zq7-marker-value-that-should-never-be-echoed-anywhere-9xR"
    problems = describe_secret_problems(_cfg(**{name: marker[:MIN_SECRET_LENGTH - 1]}))
    joined = " ".join(problems)
    assert marker[:MIN_SECRET_LENGTH - 1] not in joined
    assert marker[:12] not in joined
    assert marker[-12:] not in joined


@pytest.mark.parametrize("name", REQUIRED)
def test_a_problem_description_does_not_report_the_secret_length(name):
    """Length is a real leak for a short secret: it bounds a brute-force search.

    Proven by giving two different-length bad values and requiring identical text - a message that
    interpolated either length could not satisfy both.
    """
    a = describe_secret_problems(_cfg(**{name: "a" * 5}))
    b = describe_secret_problems(_cfg(**{name: "b" * 25}))
    assert a == b


def test_the_startup_exception_message_contains_no_secret_value():
    marker = "Kj4-another-marker-value-not-to-be-echoed"
    with pytest.raises(InsecureConfigurationError) as caught:
        validate_production_secrets(_cfg(SECRET_KEY=marker[:20]))
    message = str(caught.value)
    assert marker[:20] not in message
    assert marker[:10] not in message
    # It must still be actionable: name the variable and how to generate a replacement.
    assert "SECRET_KEY" in message
    assert "secrets.token_urlsafe" in message


# ── Wiring: the real Settings type, and the real startup path ─────────────────


def test_the_real_settings_type_flows_through_the_validator():
    """The tests above use a namespace; this one proves the production object behaves the same.

    Every field is passed explicitly, so no value is read from the environment or from a tracked
    .env file. The database URL carries no credentials and is never connected to.
    """
    cfg = Settings(
        DATABASE_URL="postgresql://localhost/spemcs_unused_by_this_test",
        SPEMCS_ENV="production",
        SECRET_KEY=STRONG,
        DEVICE_TOKEN_SECRET=STRONG,
        ENROLLMENT_BOOTSTRAP_KEY=STRONG,
        SIGNING_KEY_ALLOW_EPHEMERAL=False,
    )
    assert describe_secret_problems(cfg) == []

    weak = Settings(
        DATABASE_URL="postgresql://localhost/spemcs_unused_by_this_test",
        SPEMCS_ENV="production",
        SECRET_KEY=Settings.model_fields["SECRET_KEY"].default,
        DEVICE_TOKEN_SECRET=STRONG,
        ENROLLMENT_BOOTSTRAP_KEY=STRONG,
        SIGNING_KEY_ALLOW_EPHEMERAL=False,
    )
    with pytest.raises(InsecureConfigurationError):
        validate_production_secrets(weak)


def test_the_database_url_has_no_default():
    """No silent fallback to some other database.

    A default here would let a misconfigured deployment come up against the wrong instance - or a
    local one - and report itself healthy.
    """
    assert Settings.model_fields["DATABASE_URL"].is_required()


def test_startup_refuses_before_touching_the_database(monkeypatch):
    """Ordering, not just presence, of the check.

    Secret validation is the first statement in the lifespan. Asserting that matters because the
    alternative - validating after ``engine.connect()`` and ``create_all`` - means a deployment on a
    placeholder JWT key has already opened its database and can be serving requests by the time it
    objects. This test would fail differently (a database error, or a hang) if the order regressed;
    as written it never opens a connection.
    """
    from backend.app import config as config_module
    from backend.app.main import app, lifespan

    monkeypatch.setattr(config_module.settings, "SPEMCS_ENV", "production")
    monkeypatch.setattr(
        config_module.settings, "SECRET_KEY", Settings.model_fields["SECRET_KEY"].default
    )

    async def _enter() -> None:
        async with lifespan(app):
            pass

    with pytest.raises(InsecureConfigurationError):
        asyncio.run(_enter())
