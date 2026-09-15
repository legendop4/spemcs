"""devices: widen pc_number from VARCHAR(10) to VARCHAR(50)

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-08

The endpoint agent derives ``pc_number`` from the machine name or setup wizard input, and values
longer than 10 characters (e.g. ``testingforspemcsnew``) caused device registration to fail with
``StringDataRightTruncation``. Widening to 50 characters matches the size of ``building_name``
and ``lab_name`` and gives comfortable headroom for any realistic PC identifier.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.alter_column(
            "pc_number",
            existing_type=sa.String(length=10),
            type_=sa.String(length=50),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.alter_column(
            "pc_number",
            existing_type=sa.String(length=50),
            type_=sa.String(length=10),
            existing_nullable=True,
        )
