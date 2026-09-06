"""Startup schema check.

Until this module existed, the application built its own schema on every boot:
``Base.metadata.create_all(bind=engine)`` followed by two hand-written
``ALTER TABLE exams ADD COLUMN IF NOT EXISTS`` statements wrapped in a ``try`` that logged failures
as "non-fatal". That is why the deployed database drifted. ``create_all`` **creates tables and
never alters them**, so the three columns added to ``network_policies`` for browser scoping and key
rotation were never applied to the existing table; every policy compilation against the deployed
database failed with ``UndefinedColumn`` and ten backend tests failed with it. The ad-hoc ALTERs
were the workaround for exactly this problem, applied to a different table, one column at a time,
by hand - and they only ever covered the two columns somebody remembered.

Schema is now owned by Alembic (``backend/migrations``). This module does not create or modify
anything; it reports.

**It warns rather than refusing to boot, deliberately.** A refusal here would take a running
deployment offline the moment it is upgraded, before anybody has had the chance to stamp the
existing database - and the schema check is not a security control, unlike
``validate_production_secrets``, which does refuse. What a drifted schema causes is a loud,
specific failure at the point of use (policy compilation raises, and P1-S's activation
precondition refuses to arm an exam), not a silent compromise. So the trade is: this logs an ERROR
naming the exact commands, and the exam-time path fails closed on its own.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

# backend/app/schema_check.py -> backend/
_BACKEND_DIR = Path(__file__).resolve().parents[2]
_ALEMBIC_INI = _BACKEND_DIR / "alembic.ini"
_MIGRATIONS_DIR = _BACKEND_DIR / "backend" / "migrations"

_STAMP_HINT = (
    "The database predates Alembic. Bring it under version control without recreating it:\n"
    "    cd backend\n"
    "    python -m alembic stamp 0001     # this database already has the 0001 schema\n"
    "    python -m alembic upgrade head   # apply everything since"
)
_UPGRADE_HINT = (
    "Apply the outstanding migrations:\n"
    "    cd backend\n"
    "    python -m alembic upgrade head"
)


def expected_head() -> Optional[str]:
    """The revision the code expects, or None if the migration directory cannot be read."""
    try:
        config = Config(str(_ALEMBIC_INI))
        config.set_main_option("script_location", str(_MIGRATIONS_DIR))
        heads = ScriptDirectory.from_config(config).get_heads()
    except Exception:
        logger.exception("Could not read the Alembic migration directory")
        return None

    if len(heads) != 1:
        # Multiple heads means `upgrade head` is ambiguous and one branch would silently be
        # skipped. tests/test_migrations.py fails on this too; reporting it here covers the case
        # where a bad merge reaches a deployment.
        logger.error("Alembic has %d heads (%s); the migration history has branched.",
                     len(heads), ", ".join(heads))
        return None
    return heads[0]


def current_revision(engine: Engine) -> Optional[str]:
    """The revision the database claims to be at, or None if it has never been stamped."""
    if not inspect(engine).has_table("alembic_version"):
        return None
    with engine.connect() as connection:
        row = connection.execute(text("SELECT version_num FROM alembic_version")).fetchone()
    return row[0] if row else None


def verify_schema_revision(engine: Engine) -> bool:
    """Log whether the database schema matches the migrations. Returns True when it does.

    Never modifies the database - see the module docstring for why this reports instead of
    repairing, and why it does not abort startup.
    """
    head = expected_head()
    if head is None:
        return False

    try:
        current = current_revision(engine)
    except Exception:
        logger.exception("Could not read the database's Alembic revision")
        return False

    if current == head:
        logger.info("Database schema is at Alembic revision %s (current).", head)
        return True

    if current is None:
        logger.error(
            "Database schema is NOT under Alembic control (no alembic_version table); the code "
            "expects revision %s. Policy compilation and exam activation will fail against a "
            "schema that is missing columns the models declare.\n%s",
            head, _STAMP_HINT,
        )
    else:
        logger.error(
            "Database schema is at Alembic revision %s but the code expects %s.\n%s",
            current, head, _UPGRADE_HINT,
        )
    return False
