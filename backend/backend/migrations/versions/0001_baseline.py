"""baseline: the schema as deployed before Alembic was introduced

Revision ID: 0001
Revises:
Create Date: 2026-09-05

This revision reproduces the schema that ``Base.metadata.create_all`` had already built on the
deployed database, so that database can be brought under version control by **stamping** rather
than by running this revision:

    cd backend
    python -m alembic stamp 0001      # existing database: record that it is already at 0001
    python -m alembic upgrade head    # then apply 0002 onward

A fresh database instead runs this revision for real and reaches the same place.

Two deliberate omissions, both of which would otherwise make the stamp a lie:

* ``network_policies`` has no ``approved_browser``, ``key_id`` or ``schema_version`` column here.
  Those three arrived with the browser-scoping and key-rotation work *after* the deployed schema
  was created, and the deployed table does not have them. Adding them to this baseline would make
  ``stamp 0001`` claim columns the database does not have, and the migration that needs to add them
  would then be skipped. They are added by 0002, which also handles the rows already present.
* The deployed ``events`` table carries nine columns the model does not declare, and the deployed
  database carries three tables the model does not declare. Neither appears here, because this
  baseline describes the models. ``migrations/env.py`` filters them out of autogenerate so no
  future revision proposes dropping them.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '0001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('devices',
    sa.Column('device_id', sa.UUID(), nullable=False),
    sa.Column('hardware_uuid', sa.String(length=100), nullable=True),
    sa.Column('device_name', sa.String(length=100), nullable=False),
    sa.Column('building_name', sa.String(length=50), nullable=True),
    sa.Column('lab_name', sa.String(length=50), nullable=True),
    sa.Column('pc_number', sa.String(length=10), nullable=True),
    sa.Column('registered_ip', sa.String(length=50), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('device_id')
    )
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.create_index('ix_devices_building_lab', ['building_name', 'lab_name'], unique=False)
        batch_op.create_index('ix_devices_device_name', ['device_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_devices_hardware_uuid'), ['hardware_uuid'], unique=True)

    op.create_table('labs',
    sa.Column('lab_id', sa.UUID(), nullable=False),
    sa.Column('building_id', sa.String(), nullable=False),
    sa.Column('lab_name', sa.String(), nullable=False),
    sa.Column('description', sa.String(), nullable=True),
    sa.Column('capacity', sa.Integer(), nullable=False),
    sa.Column('spemcs_enabled', sa.Boolean(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('lab_id')
    )
    with op.batch_alter_table('labs', schema=None) as batch_op:
        batch_op.create_index('ix_labs_building_lab', ['building_id', 'lab_name'], unique=False)

    op.create_table('users',
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('password', sa.String(length=255), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('avatar_color', sa.String(length=20), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('user_id'),
    sa.UniqueConstraint('email')
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_username'), ['username'], unique=True)

    op.create_table('vendor_profiles',
    sa.Column('vendor_id', sa.UUID(), nullable=False),
    sa.Column('vendor_name', sa.String(length=100), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=True),
    sa.Column('required_domains', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('approved_ip_ranges', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('required_tcp_ports', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('required_udp_ports', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('vendor_id')
    )
    with op.batch_alter_table('vendor_profiles', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vendor_profiles_vendor_name'), ['vendor_name'], unique=True)

    op.create_table('audit_logs',
    sa.Column('log_id', sa.UUID(), nullable=False),
    sa.Column('user_id', sa.UUID(), nullable=True),
    sa.Column('action', sa.String(length=50), nullable=False),
    sa.Column('entity_type', sa.String(length=50), nullable=True),
    sa.Column('entity_id', sa.String(length=100), nullable=True),
    sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('ip_address', sa.String(length=50), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
    sa.PrimaryKeyConstraint('log_id')
    )
    op.create_table('exams',
    sa.Column('exam_id', sa.UUID(), nullable=False),
    sa.Column('exam_name', sa.String(length=150), nullable=False),
    sa.Column('section', sa.String(length=150), nullable=True),
    sa.Column('exam_link', sa.Text(), nullable=True),
    sa.Column('approved_browser', sa.String(length=20), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('network_enforcement', sa.Boolean(), nullable=False),
    sa.Column('vendor_profile_id', sa.UUID(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('ended_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['vendor_profile_id'], ['vendor_profiles.vendor_id'], ),
    sa.PrimaryKeyConstraint('exam_id')
    )
    with op.batch_alter_table('exams', schema=None) as batch_op:
        batch_op.create_index('ix_exams_exam_name', ['exam_name'], unique=False)
        batch_op.create_index('ix_exams_status', ['status'], unique=False)

    op.create_table('lab_devices',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('lab_id', sa.UUID(), nullable=False),
    sa.Column('device_id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.device_id'], ),
    sa.ForeignKeyConstraint(['lab_id'], ['labs.lab_id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('lab_devices', schema=None) as batch_op:
        batch_op.create_index('ix_lab_devices_device_id', ['device_id'], unique=False)
        batch_op.create_index('ix_lab_devices_lab_id', ['lab_id'], unique=False)

    op.create_table('exam_devices',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('exam_id', sa.UUID(), nullable=False),
    sa.Column('device_id', sa.UUID(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.device_id'], ),
    sa.ForeignKeyConstraint(['exam_id'], ['exams.exam_id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('exam_id', 'device_id', name='uq_exam_device')
    )
    with op.batch_alter_table('exam_devices', schema=None) as batch_op:
        batch_op.create_index('ix_exam_devices_exam_id', ['exam_id'], unique=False)

    op.create_table('exam_sessions',
    sa.Column('session_id', sa.UUID(), nullable=False),
    sa.Column('exam_id', sa.UUID(), nullable=False),
    sa.Column('device_id', sa.UUID(), nullable=False),
    sa.Column('student_roll_number', sa.String(length=50), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=False),
    sa.Column('ended_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['device_id'], ['devices.device_id'], ),
    sa.ForeignKeyConstraint(['exam_id'], ['exams.exam_id'], ),
    sa.PrimaryKeyConstraint('session_id')
    )
    with op.batch_alter_table('exam_sessions', schema=None) as batch_op:
        batch_op.create_index('ix_exam_sessions_device_id', ['device_id'], unique=False)
        batch_op.create_index('ix_exam_sessions_exam_id', ['exam_id'], unique=False)
        batch_op.create_index('ix_exam_sessions_session_id', ['session_id'], unique=False)

    op.create_table('network_policies',
    sa.Column('policy_id', sa.UUID(), nullable=False),
    sa.Column('exam_id', sa.UUID(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('vendor_profile_id', sa.UUID(), nullable=True),
    sa.Column('allowed_destinations', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('management_server', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('not_before', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('signature', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['exam_id'], ['exams.exam_id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vendor_profile_id'], ['vendor_profiles.vendor_id'], ),
    sa.PrimaryKeyConstraint('policy_id'),
    sa.UniqueConstraint('exam_id', 'version', name='uq_exam_policy_version')
    )
    with op.batch_alter_table('network_policies', schema=None) as batch_op:
        batch_op.create_index('ix_network_policies_exam_id', ['exam_id'], unique=False)

    op.create_table('reports',
    sa.Column('report_id', sa.UUID(), nullable=False),
    sa.Column('exam_id', sa.UUID(), nullable=False),
    sa.Column('generated_at', sa.DateTime(), nullable=False),
    sa.Column('summary', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('report_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('alert_count', sa.Integer(), nullable=False),
    sa.Column('event_count', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['exam_id'], ['exams.exam_id'], ),
    sa.PrimaryKeyConstraint('report_id')
    )
    op.create_table('device_policy_states',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('exam_id', sa.UUID(), nullable=False),
    sa.Column('device_id', sa.UUID(), nullable=False),
    sa.Column('policy_id', sa.UUID(), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('rules_installed', sa.Integer(), nullable=False),
    sa.Column('last_error', sa.String(length=255), nullable=True),
    sa.Column('applied_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.device_id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['exam_id'], ['exams.exam_id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['policy_id'], ['network_policies.policy_id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('exam_id', 'device_id', name='uq_device_policy_state')
    )
    with op.batch_alter_table('device_policy_states', schema=None) as batch_op:
        batch_op.create_index('ix_device_policy_states_device_id', ['device_id'], unique=False)
        batch_op.create_index('ix_device_policy_states_status', ['status'], unique=False)

    op.create_table('events',
    sa.Column('event_id', sa.UUID(), nullable=False),
    sa.Column('session_id', sa.UUID(), nullable=True),
    sa.Column('device_id', sa.UUID(), nullable=False),
    sa.Column('device_name', sa.String(), nullable=False),
    sa.Column('ip_address', sa.String(), nullable=True),
    sa.Column('student_roll_number', sa.String(), nullable=True),
    sa.Column('event_type', sa.String(), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.Column('process_name', sa.String(), nullable=True),
    sa.Column('pid', sa.Integer(), nullable=True),
    sa.Column('executable_path', sa.String(), nullable=True),
    sa.Column('classification', sa.String(), nullable=False),
    sa.Column('reason', sa.String(), nullable=True),
    sa.Column('resolution_status', sa.String(), nullable=True),
    sa.ForeignKeyConstraint(['device_id'], ['devices.device_id'], ),
    sa.ForeignKeyConstraint(['session_id'], ['exam_sessions.session_id'], ),
    sa.PrimaryKeyConstraint('event_id')
    )
    with op.batch_alter_table('events', schema=None) as batch_op:
        batch_op.create_index('ix_events_device_id', ['device_id'], unique=False)
        batch_op.create_index('ix_events_event_type', ['event_type'], unique=False)
        batch_op.create_index('ix_events_session_id', ['session_id'], unique=False)
        batch_op.create_index('ix_events_timestamp', ['timestamp'], unique=False)

    op.create_table('alerts',
    sa.Column('alert_id', sa.UUID(), nullable=False),
    sa.Column('event_id', sa.UUID(), nullable=False),
    # nullable: an alert from a device that is not currently sitting an ACTIVE exam has no exam.
    # See the comment on `Alert.exam_id`. Corrected 2026-09-05 after `alembic check` against the
    # live database reported this as the one schema drift: production has always had this column
    # nullable and holds a row that depends on it. Editing this baseline in place is safe because
    # on any database that predates it the revision is *stamped*, never executed; the body only
    # ever runs when a database is built from scratch, and it has to build the schema production
    # actually has.
    sa.Column('exam_id', sa.UUID(), nullable=True),
    sa.Column('device_id', sa.UUID(), nullable=False),
    sa.Column('agent_event_id', sa.String(length=100), nullable=True),
    sa.Column('severity', sa.String(length=20), nullable=False),
    sa.Column('message', sa.String(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.device_id'], ),
    sa.ForeignKeyConstraint(['event_id'], ['events.event_id'], ),
    sa.ForeignKeyConstraint(['exam_id'], ['exams.exam_id'], ),
    sa.PrimaryKeyConstraint('alert_id'),
    sa.UniqueConstraint('event_id')
    )
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_alerts_agent_event_id'), ['agent_event_id'], unique=True)
        batch_op.create_index('ix_alerts_device_id', ['device_id'], unique=False)
        batch_op.create_index('ix_alerts_exam_id', ['exam_id'], unique=False)
        batch_op.create_index('ix_alerts_status', ['status'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.drop_index('ix_alerts_status')
        batch_op.drop_index('ix_alerts_exam_id')
        batch_op.drop_index('ix_alerts_device_id')
        batch_op.drop_index(batch_op.f('ix_alerts_agent_event_id'))

    op.drop_table('alerts')
    with op.batch_alter_table('events', schema=None) as batch_op:
        batch_op.drop_index('ix_events_timestamp')
        batch_op.drop_index('ix_events_session_id')
        batch_op.drop_index('ix_events_event_type')
        batch_op.drop_index('ix_events_device_id')

    op.drop_table('events')
    with op.batch_alter_table('device_policy_states', schema=None) as batch_op:
        batch_op.drop_index('ix_device_policy_states_status')
        batch_op.drop_index('ix_device_policy_states_device_id')

    op.drop_table('device_policy_states')
    op.drop_table('reports')
    with op.batch_alter_table('network_policies', schema=None) as batch_op:
        batch_op.drop_index('ix_network_policies_exam_id')

    op.drop_table('network_policies')
    with op.batch_alter_table('exam_sessions', schema=None) as batch_op:
        batch_op.drop_index('ix_exam_sessions_session_id')
        batch_op.drop_index('ix_exam_sessions_exam_id')
        batch_op.drop_index('ix_exam_sessions_device_id')

    op.drop_table('exam_sessions')
    with op.batch_alter_table('exam_devices', schema=None) as batch_op:
        batch_op.drop_index('ix_exam_devices_exam_id')

    op.drop_table('exam_devices')
    with op.batch_alter_table('lab_devices', schema=None) as batch_op:
        batch_op.drop_index('ix_lab_devices_lab_id')
        batch_op.drop_index('ix_lab_devices_device_id')

    op.drop_table('lab_devices')
    with op.batch_alter_table('exams', schema=None) as batch_op:
        batch_op.drop_index('ix_exams_status')
        batch_op.drop_index('ix_exams_exam_name')

    op.drop_table('exams')
    op.drop_table('audit_logs')
    with op.batch_alter_table('vendor_profiles', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vendor_profiles_vendor_name'))

    op.drop_table('vendor_profiles')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_username'))

    op.drop_table('users')
    with op.batch_alter_table('labs', schema=None) as batch_op:
        batch_op.drop_index('ix_labs_building_lab')

    op.drop_table('labs')
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_devices_hardware_uuid'))
        batch_op.drop_index('ix_devices_device_name')
        batch_op.drop_index('ix_devices_building_lab')

    op.drop_table('devices')
