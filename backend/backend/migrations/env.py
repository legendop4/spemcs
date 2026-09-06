"""Alembic environment for SPEMCS.

Two things in here are load-bearing and should not be simplified away.

**The URL is read from settings, never from alembic.ini.** ``DATABASE_URL`` carries live
credentials and ``alembic.ini`` is tracked, so putting the URL there would commit a secret.
``_database_url()`` prefers an explicit ``-x url=...`` (used by the migration tests, which point at
a throwaway SQLite file) and otherwise falls back to ``settings.DATABASE_URL``.

**Autogenerate is filtered so it can never propose dropping something it does not know about.**
This is not tidiness; it is a data-loss guard, and the live database is the reason it exists. The
filter itself lives in ``migrations/filters.py`` rather than here, because this module cannot be
imported outside an alembic run context and so nothing in it can be tested;
``tests/test_migrations.py`` exercises the same function alembic uses. See that module's docstring
for the drift it protects.
"""

from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# `prepend_sys_path = .` in alembic.ini covers the documented invocation (from `backend/`). This
# also covers being imported by the test suite through alembic's own API, where cwd may differ.
_BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

# Registers a SQLite rendering for JSONB. Inert on PostgreSQL (the shim is dialect-scoped), and
# required for the migration tests, which run the full upgrade path against a temporary SQLite file
# so that "the migrations and the models agree" is checkable without a database server.
from backend.app.sqlite_compat import install_sqlite_compat  # noqa: E402

install_sqlite_compat()

# Importing the package - not the individual modules - is what guarantees every model class is
# registered on Base.metadata before autogenerate compares against it. A model that is not
# imported looks, to autogenerate, exactly like a table that should be dropped.
import backend.models  # noqa: F401,E402
from backend.migrations.filters import make_include_name  # noqa: E402
from backend.models.base import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata
include_name = make_include_name(target_metadata)


def _database_url() -> str:
    """The URL to migrate, without ever reading a credential out of a tracked file."""
    override = context.get_x_argument(as_dictionary=True).get("url")
    if override:
        return override
    from backend.app.config import settings

    return settings.DATABASE_URL


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (`alembic upgrade head --sql`)."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        include_name=include_name,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect and run migrations against the configured database."""
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        is_sqlite = connection.dialect.name == "sqlite"
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            include_name=include_name,
            # SQLite cannot ALTER a column in place. Batch mode makes `alter_column` work there by
            # rewriting the table, which is what lets the migration tests exercise the real
            # upgrade path off PostgreSQL.
            render_as_batch=is_sqlite,
        )

        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
