"""Server-side enforcement precondition for exam activation (P1-S).

**What was wrong.** The entire "is this exam safe to start" decision lived in the browser.
``frontend/src/pages/ExamShieldPage.tsx::handleActivate`` compiled a policy, fetched the assigned
devices, distributed to the online ones, and *then* called ``POST /api/exams/{id}/activate`` - and
the server did none of that. It set the exam ACTIVE, marked every assigned device ``MONITORING``,
and returned ``{"status": "activated"}`` unconditionally. So:

* a direct ``POST`` with any staff token produced an ACTIVE network-enforcement exam with no policy
  compiled at all;
* every distribution in that loop could fail - the loop catches each error and only shows a toast -
  and the activation on the next line still succeeded;
* devices that received nothing were reported as ``MONITORING``, which is the dashboard's word for
  "this workstation is under exam control".

None of those are edge cases: the middle one happens whenever a workstation is offline.

**What this module does instead.** It answers the same question on the server, from persisted
state, and it answers it in a way that can refuse. The checks are ordered cheapest-first and every
failure is reported as a code plus a human sentence, because an operator who is told "cannot
activate" and not *why* will reach for whatever bypass exists.

**Why the signature is re-verified here rather than trusted.** ``rebuild_signed_payload`` rebuilds
the canonical bytes from the persisted columns; verifying those bytes against the stored signature
proves the row can still produce a policy the endpoint will accept. That is not a theoretical
concern - migration ``0002`` backfills ``key_id``/``approved_browser``/``schema_version`` with an
empty tombstone for rows signed before those columns existed, and such a row would be distributed
happily and rejected by every endpoint. Verifying here turns that into a refusal naming the exam,
before any candidate sits down.

**Enforcement exams only.** An exam with ``network_enforcement`` false is not making any lockdown
claim, so it activates exactly as it did before. Widening this to ordinary proctoring exams would
be a behaviour change nobody asked for and would block activation on machines that are merely
offline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

from sqlalchemy.orm import Session

from backend.models.device import Device
from backend.models.exam import Exam, ExamDevice
from backend.services import device_policy_state_service as dps
from backend.services import policy_service
from backend.services.policy_compiler import PolicyCompilationError
from backend.services.policy_signer import (
    ExpiredPolicyError,
    InvalidSignatureError,
    KeyMismatchError,
    NotYetValidPolicyError,
    PolicyVerificationError,
)
from backend.services.signing_key_manager import (
    SigningKeyManager,
    SigningKeyUnavailableError,
    get_signing_key_manager,
)

logger = logging.getLogger(__name__)

# Problem codes. Stable identifiers so the UI can react to a specific cause; the message is for
# the operator. Deliberately granular - "not ready" is not actionable, "the signing key that
# signed this policy has been revoked" is.
NO_POLICY = "NO_POLICY"
POLICY_UNSIGNED = "POLICY_UNSIGNED"
POLICY_NOT_REPRODUCIBLE = "POLICY_NOT_REPRODUCIBLE"
POLICY_KEY_UNKNOWN = "POLICY_KEY_UNKNOWN"
POLICY_KEY_REVOKED = "POLICY_KEY_REVOKED"
POLICY_EXPIRED = "POLICY_EXPIRED"
POLICY_NOT_YET_VALID = "POLICY_NOT_YET_VALID"
POLICY_SIGNATURE_INVALID = "POLICY_SIGNATURE_INVALID"
POLICY_INVALID = "POLICY_INVALID"
SIGNING_KEYS_UNAVAILABLE = "SIGNING_KEYS_UNAVAILABLE"
NO_ASSIGNED_DEVICES = "NO_ASSIGNED_DEVICES"
NO_ARMED_DEVICES = "NO_ARMED_DEVICES"

#: Not a refusal. The deployment is misconfigured in a way that will bite after the next restart,
#: which is worth saying out loud at activation time without cancelling the exam in front of a
#: room full of candidates.
EPHEMERAL_SIGNING_KEY = "EPHEMERAL_SIGNING_KEY"


@dataclass(frozen=True)
class ReadinessProblem:
    code: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True)
class EnforcementReadiness:
    """The full answer, not just the verdict.

    ``ready`` is what the activation route branches on; everything else is what it reports, so an
    operator refused at 09:00 knows which of "no policy", "policy expired" and "nothing is
    listening" they are looking at.
    """

    exam_id: UUID
    enforcement_required: bool
    ready: bool
    problems: List[ReadinessProblem] = field(default_factory=list)
    warnings: List[ReadinessProblem] = field(default_factory=list)
    policy_id: Optional[UUID] = None
    policy_version: Optional[int] = None
    assigned_device_ids: Set[UUID] = field(default_factory=set)
    armed_device_ids: Set[UUID] = field(default_factory=set)

    @property
    def unarmed_device_ids(self) -> Set[UUID]:
        return self.assigned_device_ids - self.armed_device_ids

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exam_id": str(self.exam_id),
            "enforcement_required": self.enforcement_required,
            "ready": self.ready,
            "problems": [p.to_dict() for p in self.problems],
            "warnings": [w.to_dict() for w in self.warnings],
            "policy_id": str(self.policy_id) if self.policy_id else None,
            "policy_version": self.policy_version,
            "devices_assigned": len(self.assigned_device_ids),
            "devices_armed": len(self.armed_device_ids),
        }


def evaluate_exam_readiness(
    db: Session,
    exam: Exam,
    *,
    keys: Optional[SigningKeyManager] = None,
    now: Optional[datetime] = None,
) -> EnforcementReadiness:
    """Decide whether ``exam`` may be activated, and say why not when it may not.

    ``keys`` and ``now`` are injectable for tests only; production passes neither.
    """
    assigned_device_ids = {
        row.device_id
        for row in db.query(ExamDevice).filter(ExamDevice.exam_id == exam.exam_id).all()
        if row.device_id
    }

    if not bool(getattr(exam, "network_enforcement", False)):
        # No lockdown claim is being made, so there is no lockdown precondition. Every assigned
        # device is a launch target, exactly as before this module existed.
        return EnforcementReadiness(
            exam_id=exam.exam_id,
            enforcement_required=False,
            ready=True,
            assigned_device_ids=assigned_device_ids,
            armed_device_ids=set(assigned_device_ids),
        )

    problems: List[ReadinessProblem] = []
    warnings: List[ReadinessProblem] = []

    policy = policy_service.get_latest_exam_policy(db, exam.exam_id)
    policy_id = policy.policy_id if policy else None
    policy_version = policy.version if policy else None

    if policy is None:
        problems.append(ReadinessProblem(
            NO_POLICY,
            "No network policy has been compiled for this exam. Compile and sign a policy before "
            "activating it.",
        ))
    else:
        problems.extend(_check_policy(policy, keys=keys, now=now, warnings=warnings))

    # Armed devices are intersected with the assignment list rather than counted straight off
    # device_policy_states: distribution is addressed by hardware UUID and does not itself check
    # assignment, so a state row can exist for a workstation this exam never included.
    armed_device_ids = {
        state.device_id
        for state in dps.get_states_for_exam(db, exam.exam_id)
        if dps.is_armed(state.status)
    } & assigned_device_ids

    if not assigned_device_ids:
        problems.append(ReadinessProblem(
            NO_ASSIGNED_DEVICES,
            "No devices are assigned to this exam, so there is nothing to enforce a policy on.",
        ))
    elif not armed_device_ids:
        problems.append(ReadinessProblem(
            NO_ARMED_DEVICES,
            "The signed policy has not reached any assigned device. Distribute the policy to the "
            "online workstations, then activate.",
        ))

    return EnforcementReadiness(
        exam_id=exam.exam_id,
        enforcement_required=True,
        ready=not problems,
        problems=problems,
        warnings=warnings,
        policy_id=policy_id,
        policy_version=policy_version,
        assigned_device_ids=assigned_device_ids,
        armed_device_ids=armed_device_ids,
    )


def _check_policy(
    policy,
    *,
    keys: Optional[SigningKeyManager],
    now: Optional[datetime],
    warnings: List[ReadinessProblem],
) -> List[ReadinessProblem]:
    """Everything that can be wrong with the policy row itself."""
    if not policy.signature:
        return [ReadinessProblem(
            POLICY_UNSIGNED,
            f"Policy version {policy.version} carries no signature. Recompile the policy for this "
            "exam.",
        )]

    try:
        payload = policy_service.rebuild_signed_payload(policy)
    except PolicyCompilationError as err:
        # The tombstoned rows from migration 0002 land here, as do any future rows missing a
        # signed field. The message from rebuild_signed_payload already ends in "Recompile the
        # policy for this exam."
        return [ReadinessProblem(POLICY_NOT_REPRODUCIBLE, str(err))]

    try:
        manager = keys if keys is not None else get_signing_key_manager()
        keyring = {d.key_id: d for d in manager.keyring()}
        ephemeral = manager.is_ephemeral
        verifier = manager.verifier()
    except SigningKeyUnavailableError as err:
        return [ReadinessProblem(
            SIGNING_KEYS_UNAVAILABLE,
            f"The policy signing keyring is unavailable, so this policy cannot be checked: {err}",
        )]

    if ephemeral:
        warnings.append(ReadinessProblem(
            EPHEMERAL_SIGNING_KEY,
            "The active signing key exists only in this process's memory and will not survive a "
            "restart. Configure SIGNING_KEY_DIR so endpoints can keep verifying issued policies.",
        ))

    # Unknown and revoked are checked before verification so they can be reported as themselves.
    # The verifier is seeded only with keys trusted for verification, so both would otherwise
    # collapse into the same KeyMismatchError - and "we have never heard of this key" and "this key
    # was revoked because it may be compromised" call for different responses.
    descriptor = keyring.get(policy.key_id)
    if descriptor is None:
        return [ReadinessProblem(
            POLICY_KEY_UNKNOWN,
            f"Policy version {policy.version} was signed by key '{policy.key_id}', which this "
            "server does not have. Recompile the policy for this exam.",
        )]
    if descriptor.is_revoked:
        reason = descriptor.revocation_reason or "no reason recorded"
        return [ReadinessProblem(
            POLICY_KEY_REVOKED,
            f"Policy version {policy.version} was signed by key '{policy.key_id}', which has been "
            f"revoked ({reason}). Recompile the policy for this exam with the current key.",
        )]

    current_time = now or datetime.now(timezone.utc)
    try:
        verifier.verify_policy(payload, policy.signature, current_time=current_time)
    except NotYetValidPolicyError as err:
        return [ReadinessProblem(
            POLICY_NOT_YET_VALID,
            f"Policy version {policy.version} is not valid yet: {err}",
        )]
    except ExpiredPolicyError as err:
        return [ReadinessProblem(
            POLICY_EXPIRED,
            f"Policy version {policy.version} has expired: {err} Recompile the policy for this "
            "exam.",
        )]
    except (InvalidSignatureError, KeyMismatchError) as err:
        return [ReadinessProblem(
            POLICY_SIGNATURE_INVALID,
            f"Policy version {policy.version} does not verify against its recorded signature: "
            f"{err} The stored policy row has been altered since it was signed; recompile it.",
        )]
    except PolicyVerificationError as err:
        return [ReadinessProblem(
            POLICY_INVALID,
            f"Policy version {policy.version} failed verification: {err}",
        )]

    return []


def describe_unarmed_devices(db: Session, readiness: EnforcementReadiness) -> List[Dict[str, Any]]:
    """Names for the assigned devices that are not enforcing, for the activation response.

    Reported rather than silently dropped: an operator who launches an exam on 40 seats and gets
    38 needs the other two named, not a count.
    """
    unarmed = readiness.unarmed_device_ids
    if not unarmed:
        return []
    devices = db.query(Device).filter(Device.device_id.in_(unarmed)).all()
    known = {
        d.device_id: {
            "device_id": str(d.device_id),
            "device_name": d.device_name,
            "hardware_uuid": d.hardware_uuid,
        }
        for d in devices
    }
    return [
        known.get(device_id, {"device_id": str(device_id), "device_name": None,
                              "hardware_uuid": None})
        for device_id in sorted(unarmed, key=str)
    ]
