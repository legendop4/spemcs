"""network_policies: add the signed-envelope columns approved_browser, key_id, schema_version

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-05

Each of these three values travels inside the RSA-PSS signed canonical payload, so distribution has
to read them back from the row to reproduce byte-identical signed bytes (see
``services/policy_service.rebuild_signed_payload``). They were added to the model with the
browser-scoping and key-rotation work but never reached the deployed table, because
``Base.metadata.create_all`` adds tables and never columns. The visible symptom was that every
INSERT into ``network_policies`` failed with ``UndefinedColumn`` - policy compilation was broken
outright against the deployed database, and ten backend tests failed on it.

**The backfill value for the pre-existing rows is the empty string, on purpose.** The model declares
all three ``nullable=False``, so an ``ADD COLUMN`` on a non-empty table needs *some* value, and
there is no correct one: those rows were signed before the columns existed, so any plausible-looking
value (``'edge'``, the current key id, the current schema version) would produce canonical bytes
that differ from the bytes that were actually signed. The policy would then be distributed and the
endpoint agent would reject it with an opaque signature failure.

``rebuild_signed_payload`` already refuses a row with a falsy ``key_id`` or ``approved_browser`` and
says "Recompile the policy for this exam", which ``/api/policies/distribute/...`` surfaces as 409.
Empty string therefore routes every legacy row into that explicit, legible refusal instead of into a
silent verification failure on the endpoint. It is a tombstone, not a default.

No ``server_default`` is left behind: the column is added nullable, backfilled, and then made
``NOT NULL``. A lingering ``server_default`` would be real schema that the model does not declare,
and ``tests/test_migrations.py`` compares the two.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (column, type, tombstone value for rows that predate the column)
_SIGNED_COLUMNS = (
    ("approved_browser", sa.String(length=20), ""),
    ("key_id", sa.String(length=64), ""),
    ("schema_version", sa.String(length=10), ""),
)


def upgrade() -> None:
    for name, type_, _ in _SIGNED_COLUMNS:
        op.add_column("network_policies", sa.Column(name, type_, nullable=True))

    # Backfill before the NOT NULL, or the ALTER fails on any table that already has rows.
    for name, _, tombstone in _SIGNED_COLUMNS:
        op.execute(
            sa.text(
                f"UPDATE network_policies SET {name} = :value WHERE {name} IS NULL"
            ).bindparams(value=tombstone)
        )

    # Batch mode so this revision also runs on SQLite, which cannot ALTER a column in place.
    # It is a no-op wrapper on PostgreSQL.
    with op.batch_alter_table("network_policies", schema=None) as batch_op:
        for name, type_, _ in _SIGNED_COLUMNS:
            batch_op.alter_column(name, existing_type=type_, nullable=False)


def downgrade() -> None:
    # Dropping these loses the ability to verify any signature issued while they existed. That is
    # inherent to reverting the feature, not an oversight: a policy whose key_id is gone cannot be
    # reconstructed, and the correct recovery is to recompile.
    with op.batch_alter_table("network_policies", schema=None) as batch_op:
        for name, _, _tombstone in reversed(_SIGNED_COLUMNS):
            batch_op.drop_column(name)
