"""SQLite renderings for the PostgreSQL-specific column types the models use.

SPEMCS runs on PostgreSQL. The models therefore declare
``sqlalchemy.dialects.postgresql.UUID`` and ``JSONB`` directly, which is the right thing for
production and the wrong thing for a hermetic test database: importing this module is what lets
the same ``Base.metadata`` build on SQLite so the suite does not have to reach a remote server to
exercise a query.

Only ``JSONB`` needs help. ``postgresql.UUID`` already compiles on SQLite (it renders as
``CHAR(32)`` and ``as_uuid=True`` still returns real :class:`uuid.UUID` objects), so a shim for it
would be redundant. ``JSONB`` has no SQLite rendering at all and raises
``CompileError: Compiler ... can't render element of type JSONB`` the moment
``create_all`` reaches ``vendor_profiles.required_domains``.

The mapping is to ``JSON``, not to ``TEXT``: SQLAlchemy's ``JSON`` type carries the
serialize/deserialize hooks, so a list round-trips as a list rather than as its ``repr``. What is
lost on SQLite is everything JSONB-specific - containment operators, GIN indexing, key ordering
normalisation. No SPEMCS query uses any of them today, and a test that starts to needs a real
PostgreSQL instance rather than a wider shim here.

This module is import-time-only and dialect-scoped: registering a ``sqlite`` rendering cannot
change what PostgreSQL emits, so importing it in production would be inert. It is imported by the
test conftest and by the Alembic environment, not by the application.
"""

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles

__all__ = ["install_sqlite_compat"]

_installed = False


@compiles(JSONB, "sqlite")
def _render_jsonb_as_json_on_sqlite(type_, compiler, **kw):  # pragma: no cover - DDL hook
    """Render JSONB as SQLite's JSON so `Base.metadata.create_all` succeeds off PostgreSQL."""
    return "JSON"


def install_sqlite_compat() -> None:
    """No-op entry point that makes the import above an explicit, greppable dependency.

    The ``@compiles`` decorator has already run by the time this module finishes importing, so
    this function exists only so a caller can say *why* it imported the module and so a linter
    does not remove the import as unused.
    """
    global _installed
    _installed = True
