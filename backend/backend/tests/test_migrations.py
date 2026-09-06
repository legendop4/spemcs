"""Tests for the Alembic migration path.

Four questions, and each is asked in a way that can fail:

1. Does ``upgrade head`` on an empty database produce exactly ``Base.metadata``? This is what makes
   ``conftest.py``'s cheaper ``create_all`` legitimate everywhere else - if these two ever diverge,
   ~780 tests would be running against a schema no deployment will ever have.
2. Does ``downgrade base`` undo it?
3. Does migration ``0002`` actually add the three signed-envelope columns to a database that
   already has ``network_policies`` **rows**? A backfill that only works on an empty table is not a
   backfill, and the deployed table has 24 rows.
4. Do the ``env.py`` autogenerate filters keep a drifted database's extra tables and columns out of
   the diff? This is the data-loss guard, and it is the reason a comparison test exists at all: an
   unfiltered autogenerate against the deployed database emits ``drop_table`` for three tables and
   ``drop_column`` for nine columns of a table holding thousands of rows.

Everything runs against a temporary SQLite file, so no server and no credential is involved.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory

# Registers the JSONB->JSON rendering that lets the PostgreSQL models build on SQLite.
from backend.app.sqlite_compat import install_sqlite_compat

install_sqlite_compat()

import backend.models  # noqa: F401  - registers every model on Base.metadata
from backend.models.base import Base

# backend/tests/test_migrations.py -> backend/
_BACKEND_DIR = Path(__file__).resolve().parents[2]
_ALEMBIC_INI = _BACKEND_DIR / "alembic.ini"


def _config(url: str) -> Config:
    cfg = Config(str(_ALEMBIC_INI))
    # Relative paths in alembic.ini resolve against cwd; the suite may run from anywhere.
    cfg.set_main_option("script_location", str(_BACKEND_DIR / "backend" / "migrations"))
    # -x url=... is how env.py takes an override instead of settings.DATABASE_URL, so no test
    # ever touches the deployed database or reads a credential.
    cfg.cmd_opts = type("Opts", (), {"x": [f"url={url}"]})()
    return cfg


@pytest.fixture
def sqlite_url(tmp_path) -> str:
    return "sqlite:///" + (tmp_path / "migrations.db").as_posix()


def _schema_diff(url: str):
    """Differences alembic sees between the database at `url` and Base.metadata."""
    engine = sa.create_engine(url)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={
                    # compare_type is off: SQLite collapses several distinct PostgreSQL types
                    # (String(20) and String(64) are both TEXT), so a type comparison here would
                    # report differences that exist only in the test dialect. Presence and
                    # nullability of every table and column - which is what the migrations are
                    # responsible for - is compared exactly.
                    "compare_type": False,
                },
            )
            return compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()


def test_upgrade_head_produces_exactly_the_model_schema(sqlite_url):
    """The migration path and the models must agree, with no leftover diff in either direction."""
    command.upgrade(_config(sqlite_url), "head")

    diffs = _schema_diff(sqlite_url)

    assert diffs == [], f"Migrations and models disagree: {diffs}"


def test_the_schema_comparison_can_actually_fail(sqlite_url):
    """Falsifier for the test above.

    An empty diff is only meaningful if a non-empty one is reachable. Without this, a comparison
    that silently stopped inspecting anything would make the previous test pass forever.
    """
    command.upgrade(_config(sqlite_url), "head")

    engine = sa.create_engine(sqlite_url)
    with engine.begin() as connection:
        connection.execute(sa.text("ALTER TABLE devices DROP COLUMN pc_number"))
    engine.dispose()

    diffs = _schema_diff(sqlite_url)

    assert any(
        d[0] == "add_column" and d[2] == "devices" and d[3].name == "pc_number"
        for d in diffs
        if isinstance(d, tuple)
    ), f"Expected the removed column to be detected, got: {diffs}"


def test_downgrade_base_removes_every_table(sqlite_url):
    """A revision that cannot be reverted is a one-way door; both of these can be."""
    cfg = _config(sqlite_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")

    engine = sa.create_engine(sqlite_url)
    try:
        remaining = set(sa.inspect(engine).get_table_names())
    finally:
        engine.dispose()

    # alembic_version is alembic's own bookkeeping and is expected to survive.
    assert remaining == {"alembic_version"}


def test_0002_adds_the_signed_columns_to_a_table_that_already_has_rows(sqlite_url):
    """The deployed `network_policies` table has rows; the backfill has to cope with them.

    An `ADD COLUMN ... NOT NULL` with no default fails outright on a non-empty table, so this is
    the case that matters and the one an empty-database test would miss entirely.
    """
    cfg = _config(sqlite_url)
    command.upgrade(cfg, "0001")

    engine = sa.create_engine(sqlite_url)
    with engine.begin() as connection:
        # A policy row of the shape that existed before the signed-envelope columns were added.
        connection.execute(
            sa.text(
                "INSERT INTO exams (exam_id, exam_name, approved_browser, status, "
                "network_enforcement, created_at) VALUES "
                "('e1', 'Legacy Exam', 'chrome', 'pending', 0, '2026-01-01 00:00:00')"
            )
        )
        connection.execute(
            sa.text(
                "INSERT INTO network_policies (policy_id, exam_id, version, "
                "allowed_destinations, management_server, not_before, expires_at, created_at) "
                "VALUES ('p1', 'e1', 1, '[]', '{}', '2026-01-01 00:00:00', "
                "'2026-01-01 08:00:00', '2026-01-01 00:00:00')"
            )
        )
    engine.dispose()

    command.upgrade(cfg, "0002")

    engine = sa.create_engine(sqlite_url)
    try:
        with engine.connect() as connection:
            row = connection.execute(
                sa.text(
                    "SELECT approved_browser, key_id, schema_version FROM network_policies "
                    "WHERE policy_id = 'p1'"
                )
            ).one()
        columns = {c["name"]: c for c in sa.inspect(engine).get_columns("network_policies")}
    finally:
        engine.dispose()

    # The tombstone, not a plausible-looking value. See the 0002 docstring: any real-looking value
    # would produce canonical bytes that differ from the bytes actually signed, and the endpoint
    # would reject the policy with an opaque signature failure instead of the server refusing it
    # with "recompile the policy for this exam".
    assert tuple(row) == ("", "", "")

    for name in ("approved_browser", "key_id", "schema_version"):
        assert columns[name]["nullable"] is False, f"{name} must end up NOT NULL"


def test_0002_leaves_no_server_default_behind(sqlite_url):
    """A `server_default` used only to satisfy the backfill would be schema the model never
    declares, and would silently make future INSERTs that omit the column succeed."""
    command.upgrade(_config(sqlite_url), "head")

    engine = sa.create_engine(sqlite_url)
    try:
        columns = {c["name"]: c for c in sa.inspect(engine).get_columns("network_policies")}
    finally:
        engine.dispose()

    for name in ("approved_browser", "key_id", "schema_version"):
        assert columns[name]["default"] is None, f"{name} kept a server default"


# ---------------------------------------------------------------------------
# The autogenerate drop-guards
# ---------------------------------------------------------------------------
# These reproduce the exact drift found on the deployed database in September 2026: three tables
# present there and absent from the models, and nine columns present on `events` and absent from
# the model. Without env.py's include_name filter, autogenerate proposes dropping all of it.

_UNDECLARED_EVENT_COLUMNS = (
    "browser",
    "dns_confidence",
    "dns_resolved_ip",
    "domain",
    "profile",
    "search_engine",
    "search_query",
    "title",
    "url",
)


def _autogenerate_diffs_with_env_filters(url: str):
    """Diff the database at `url` against the models using env.py's own include_name filter.

    The filter comes from ``migrations/filters.py`` rather than from ``env.py`` because importing
    ``env.py`` outside an alembic run raises (it reads ``alembic.context.config`` at module level).
    That is exactly why the filter was moved: the guard is now the same object alembic configures,
    and it is reachable from a test.
    """
    from backend.migrations.filters import make_include_name

    engine = sa.create_engine(url)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={"compare_type": False, "include_name": make_include_name(Base.metadata)},
            )
            return compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()


@pytest.fixture
def drifted_database(sqlite_url) -> str:
    """A migrated database carrying the same undeclared tables and columns as the deployed one."""
    command.upgrade(_config(sqlite_url), "head")

    engine = sa.create_engine(sqlite_url)
    with engine.begin() as connection:
        for table in ("buildings", "settings", "spemcs_users"):
            connection.execute(sa.text(f"CREATE TABLE {table} (id TEXT PRIMARY KEY)"))
        for column in _UNDECLARED_EVENT_COLUMNS:
            connection.execute(sa.text(f"ALTER TABLE events ADD COLUMN {column} VARCHAR"))
    engine.dispose()
    return sqlite_url


def test_autogenerate_does_not_propose_dropping_undeclared_tables(drifted_database):
    diffs = _autogenerate_diffs_with_env_filters(drifted_database)

    dropped = {d[1].name for d in diffs if isinstance(d, tuple) and d[0] == "remove_table"}

    assert dropped == set(), f"autogenerate wants to drop tables it does not own: {dropped}"


def test_autogenerate_does_not_propose_dropping_undeclared_columns(drifted_database):
    diffs = _autogenerate_diffs_with_env_filters(drifted_database)

    dropped = {
        (d[2], d[3].name) for d in diffs if isinstance(d, tuple) and d[0] == "remove_column"
    }

    assert dropped == set(), f"autogenerate wants to drop columns it does not own: {dropped}"


def test_without_the_filters_those_drops_are_exactly_what_autogenerate_proposes(drifted_database):
    """Falsifier for the two tests above.

    They assert that a set is empty, which is what a test asserts when it has stopped working. This
    one runs the same comparison with the filters removed and requires the drops to appear, so
    "empty" is a statement about the guard rather than about the comparison.
    """
    engine = sa.create_engine(drifted_database)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection, opts={"compare_type": False})
            diffs = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()

    dropped_tables = {d[1].name for d in diffs if isinstance(d, tuple) and d[0] == "remove_table"}
    dropped_columns = {
        d[3].name for d in diffs if isinstance(d, tuple) and d[0] == "remove_column"
    }

    assert dropped_tables == {"buildings", "settings", "spemcs_users"}
    assert dropped_columns == set(_UNDECLARED_EVENT_COLUMNS)


def test_revision_history_is_linear_and_head_is_reachable():
    """Two heads means `upgrade head` is ambiguous and one branch silently never runs."""
    script = ScriptDirectory.from_config(_config("sqlite://"))

    heads = script.get_heads()

    assert len(heads) == 1, f"Expected a single head, found: {heads}"
    assert [r.revision for r in script.walk_revisions()] == ["0002", "0001"]


def test_alembic_ini_carries_no_database_url():
    """alembic.ini is tracked; a URL in it would be a committed credential."""
    text = _ALEMBIC_INI.read_text(encoding="utf-8")

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not stripped.startswith("sqlalchemy.url"), (
            "alembic.ini must not set sqlalchemy.url; env.py reads it from settings so the "
            "credential stays in the untracked .env"
        )
