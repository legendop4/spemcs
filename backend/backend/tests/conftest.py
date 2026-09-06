"""Hermetic database for the backend test suite.

Before this file existed, every test that touched the database talked to the **deployed remote
PostgreSQL instance**, because the test modules import ``SessionLocal`` from
``backend.app.database`` and that object is bound to ``settings.DATABASE_URL``. Three consequences,
all of which this conftest removes:

* the suite took ~316 seconds, nearly all of it network round-trips;
* ten tests failed for a reason that had nothing to do with the code under test - the deployed
  ``network_policies`` table was missing three columns the model declares (now migration ``0002``);
* one run failed on a transient DNS lookup for the database host, so a green suite was not
  repeatable and a red one was not necessarily a defect.

**How the redirect works.** ``SessionLocal`` is a ``sessionmaker`` *instance*, and
``sessionmaker.configure(bind=...)`` mutates it in place. That matters: the test modules did
``from backend.app.database import SessionLocal`` at import time, and so did
``websocket/dashboard_ws._authenticate`` (inside the function body, where a ``get_db`` override
cannot reach it). Rebinding the object reaches all of them, whereas replacing the name with
``monkeypatch.setattr`` would only reach references resolved after the patch.

**Why ``create_all`` and not ``alembic upgrade head``.** The schema here is built from
``Base.metadata`` directly. Running the migrations instead would be a stronger statement, but it
would also mean a single broken migration fails all ~800 tests instead of one. The guarantee is
kept, just localised: ``test_migrations.py`` runs the real upgrade path and asserts the resulting
schema is identical to ``Base.metadata``, so "the suite's schema is the migrations' schema" is
proven in one place and cheap everywhere else.

**Escape hatch.** Set ``SPEMCS_TEST_DATABASE_URL`` to run the suite against a real PostgreSQL
instance instead - needed for anything that depends on JSONB operators, which the SQLite shim does
not provide. Unset, the suite is hermetic and needs no server.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

# Must precede any create_all: registers a SQLite rendering for JSONB, without which
# `vendor_profiles.required_domains` raises CompileError. Dialect-scoped, so it cannot affect
# PostgreSQL.
from backend.app.sqlite_compat import install_sqlite_compat

install_sqlite_compat()

import backend.models  # noqa: F401  - registers every model on Base.metadata
from backend.models.base import Base


def _sqlite_url(tmp_dir: str) -> str:
    """A file-backed SQLite URL.

    A file rather than ``:memory:`` because ``TestClient`` runs the application in a separate
    thread with its own connections; each connection to ``:memory:`` gets its own empty database,
    so the schema created here would be invisible to the app under test.
    """
    return "sqlite:///" + (Path(tmp_dir) / "spemcs_test.db").as_posix()


@event.listens_for(Engine, "connect")
def _enforce_sqlite_foreign_keys(dbapi_connection, connection_record):
    """SQLite ignores foreign keys unless asked not to.

    Without this, a test asserting that a bad ``exam_id`` is rejected would pass on PostgreSQL and
    silently succeed-with-no-error on SQLite - the test would still be green while checking
    nothing. Guarded on the driver so it does not fire for psycopg connections.
    """
    if type(dbapi_connection).__module__.startswith("sqlite3"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


@pytest.fixture(scope="session", autouse=True)
def hermetic_database():
    """Point the application's session factory at a throwaway database for the whole session."""
    from backend.app import database as db_module

    override_url = os.environ.get("SPEMCS_TEST_DATABASE_URL")
    tmp_dir = None

    if override_url:
        url = override_url
        connect_args = {}
    else:
        tmp_dir = tempfile.TemporaryDirectory(prefix="spemcs-tests-")
        url = _sqlite_url(tmp_dir.name)
        # The app is exercised through TestClient, which serves requests on a worker thread.
        connect_args = {"check_same_thread": False}

    test_engine = create_engine(url, connect_args=connect_args, future=True)
    Base.metadata.create_all(bind=test_engine)

    original_engine = db_module.engine
    original_bind = db_module.SessionLocal.kw.get("bind")

    db_module.engine = test_engine
    db_module.SessionLocal.configure(bind=test_engine)

    try:
        yield test_engine
    finally:
        db_module.SessionLocal.configure(bind=original_bind)
        db_module.engine = original_engine
        test_engine.dispose()
        if tmp_dir is not None:
            tmp_dir.cleanup()
