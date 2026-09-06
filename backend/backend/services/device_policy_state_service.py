"""Per-device network-enforcement state (``device_policy_states``).

The table has existed since M1 and nothing ever wrote a row to it. That absence was the reason a
proctor could not answer the only question that matters at the start of an enforcement exam -
*which of these workstations is actually locked down right now* - and the reason P1-S's activation
precondition had nothing to check.

**What the states mean.** They track the endpoint's enforcement lifecycle, not the message:

``PENDING``
    A row exists for this (exam, device) but nothing has been sent.
``APPLYING``
    The signed policy was handed to the device's WebSocket. This is *not* "applied": it says the
    bytes left the server, and the endpoint may still reject the signature, fail to install the
    firewall rules, or never have been listening.
``APPLIED``
    The endpoint reported that enforcement is live, with the rule count it installed.
``FAILED``
    Either distribution could not happen (device not connected) or the endpoint reported a
    failure. ``last_error`` says which.
``ROLLED_BACK``
    The endpoint reported that it removed its rules and restored the pre-exam baseline.

**Why APPLYING and APPLIED are separate, and why that is the whole point.** Before this, the
distribute endpoint returned ``{"status": "SENT"}`` and that was the last anybody heard. A
dashboard reading "SENT" describes the *server's* action; enforcement being live is a claim only
the endpoint can make. Collapsing the two would let an exam start on the strength of a successful
``send()``.

**Honest limitation, and it is a real one.** ``APPLIED`` depends on the endpoint reporting back
over the agent WebSocket, and the shipped C# agent does not currently send
``POLICY_VALIDATION_RESULT`` - it sends ``REGISTER`` and ``HEARTBEAT_PONG``. The backend handler
for that message exists and now persists here rather than only broadcasting, so the loop closes as
soon as the agent side is written; until then rows will sit at ``APPLYING`` after a successful
distribution. That is why P1-S's precondition is stated over ``APPLYING`` rather than ``APPLIED``:
a precondition nothing can ever satisfy would either block every exam or, far worse, be quietly
relaxed later into meaning nothing.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.models.device import Device
from backend.models.policy import DevicePolicyState

logger = logging.getLogger(__name__)

STATUS_PENDING = "PENDING"
STATUS_APPLYING = "APPLYING"
STATUS_APPLIED = "APPLIED"
STATUS_FAILED = "FAILED"
STATUS_ROLLED_BACK = "ROLLED_BACK"

VALID_STATUSES = frozenset(
    {STATUS_PENDING, STATUS_APPLYING, STATUS_APPLIED, STATUS_FAILED, STATUS_ROLLED_BACK}
)

#: Statuses in which a device is NOT enforcing. Named as the complement of "armed" so a new status
#: is treated as not-armed until somebody decides otherwise - the safe direction for a value that
#: gates whether an exam may start.
_NOT_ARMED = frozenset({STATUS_PENDING, STATUS_FAILED, STATUS_ROLLED_BACK})

#: last_error is String(255); a longer message would raise DataError on PostgreSQL and lose the
#: state update entirely - so the diagnostic is truncated rather than the row being dropped.
_MAX_ERROR_LENGTH = 255


def is_armed(status: Optional[str]) -> bool:
    """Whether a status means the device is enforcing, or is expected to be.

    ``APPLYING`` counts as armed. See the module docstring: the endpoint does not yet report
    ``APPLIED``, so requiring it would make every enforcement exam unstartable. This is the single
    place that decision lives, so tightening it later is a one-line change with tests attached.
    """
    return status is not None and status not in _NOT_ARMED


def _truncate(message: Optional[str]) -> Optional[str]:
    if message is None:
        return None
    text = str(message)
    return text if len(text) <= _MAX_ERROR_LENGTH else text[: _MAX_ERROR_LENGTH - 3] + "..."


def record_state(
    db: Session,
    *,
    exam_id: UUID,
    device_id: UUID,
    policy_id: UUID,
    status: str,
    rules_installed: Optional[int] = None,
    last_error: Optional[str] = None,
    commit: bool = True,
) -> DevicePolicyState:
    """Create or update the (exam, device) enforcement state.

    An upsert rather than an insert because ``UNIQUE(exam_id, device_id)`` allows exactly one row
    per pairing: a redistribution after a failure has to *move* the state, not accumulate history
    alongside it. Audit history is the audit log's job.
    """
    if status not in VALID_STATUSES:
        raise ValueError(f"Unknown device policy status: {status!r}")

    state = (
        db.query(DevicePolicyState)
        .filter(
            DevicePolicyState.exam_id == exam_id,
            DevicePolicyState.device_id == device_id,
        )
        .first()
    )

    if state is None:
        state = DevicePolicyState(exam_id=exam_id, device_id=device_id, policy_id=policy_id)
        db.add(state)

    # policy_id is overwritten on every update: a recompiled policy supersedes the old one, and a
    # state row pointing at a superseded policy would misreport which bytes the device holds.
    state.policy_id = policy_id
    state.status = status
    if rules_installed is not None:
        state.rules_installed = rules_installed
    # last_error is cleared on any non-failure transition. Leaving a stale message on an APPLIED
    # row makes a recovered device look permanently broken on the dashboard.
    state.last_error = _truncate(last_error) if status == STATUS_FAILED else None
    state.applied_at = datetime.utcnow() if status == STATUS_APPLIED else None
    state.updated_at = datetime.utcnow()

    if commit:
        db.commit()
        db.refresh(state)
    return state


def record_state_for_hardware_uuid(
    db: Session,
    *,
    exam_id: UUID,
    hardware_uuid: str,
    policy_id: UUID,
    status: str,
    rules_installed: Optional[int] = None,
    last_error: Optional[str] = None,
) -> Optional[DevicePolicyState]:
    """``record_state`` keyed by the identifier the WebSocket layer actually has.

    Returns ``None`` when no device row matches. The agent socket auto-registers devices on
    connect, so this should not happen; it is not raised because a state-tracking failure must not
    take down the message handler that was doing the real work.
    """
    device = _resolve_device(db, hardware_uuid)
    if device is None:
        logger.warning(
            "No device row for hardware_uuid %s; enforcement state not recorded.", hardware_uuid
        )
        return None

    return record_state(
        db,
        exam_id=exam_id,
        device_id=device.device_id,
        policy_id=policy_id,
        status=status,
        rules_installed=rules_installed,
        last_error=last_error,
    )


def _resolve_device(db: Session, hardware_uuid: str) -> Optional[Device]:
    """Find a device by hardware UUID, falling back to device_name.

    The fallback is not defensive padding: ``realtime_manager`` addresses endpoints by
    ``hardware_uuid or device_name`` (see ``exam_service.activate_exam``), so a device registered
    without a hardware UUID is reachable over the socket under its name and would otherwise be
    invisible to state tracking.
    """
    device = db.query(Device).filter(Device.hardware_uuid == hardware_uuid).first()
    if device is None:
        device = db.query(Device).filter(Device.device_name == hardware_uuid).first()
    return device


def get_states_for_exam(db: Session, exam_id: UUID) -> list[DevicePolicyState]:
    """Every recorded enforcement state for an exam, newest update first."""
    return (
        db.query(DevicePolicyState)
        .filter(DevicePolicyState.exam_id == exam_id)
        .order_by(DevicePolicyState.updated_at.desc())
        .all()
    )


def get_state(db: Session, exam_id: UUID, device_id: UUID) -> Optional[DevicePolicyState]:
    """The enforcement state for one (exam, device) pairing, or None."""
    return (
        db.query(DevicePolicyState)
        .filter(
            DevicePolicyState.exam_id == exam_id,
            DevicePolicyState.device_id == device_id,
        )
        .first()
    )


def count_armed_devices(db: Session, exam_id: UUID) -> int:
    """How many devices are enforcing, or are expected to be. Used by the activation precondition."""
    return sum(1 for state in get_states_for_exam(db, exam_id) if is_armed(state.status))
