"""Coercion of externally supplied identifiers into ``uuid.UUID``.

Every primary key in SPEMCS is a UUID column, and most of them are reached through a FastAPI path
parameter annotated ``UUID``, so FastAPI has already parsed and rejected malformed input before any
handler runs. Three places take an identifier that FastAPI never validated - the ``sub`` claim of a
JWT (twice) and the ``labId`` field of the device-enrolment body - and those passed the raw
**string** straight into a comparison against a UUID column.

That works on PostgreSQL, which casts the literal for you, and it is why the pattern survived. It is
still wrong for two reasons:

* **It defers input validation to the database.** A ``sub`` claim that is not a UUID reaches
  PostgreSQL and raises ``InvalidTextRepresentation``, which aborts the request's transaction and
  surfaces as a 500 from the global exception handler - where the honest answer is 401. Parsing the
  claim first turns a malformed identifier into "not authenticated" instead of "server error".
* **It is not portable, and the non-portability hides real defects.** Off PostgreSQL the same
  comparison raises ``AttributeError: 'str' object has no attribute 'hex'``. In
  ``device_service.register_device`` that exception was being swallowed by a bare ``except
  Exception`` whose fallback silently produced "no such lab" - which silently skipped the
  ``(lab, pc_number)`` uniqueness check, so a second workstation could claim a seat that was already
  taken. The hermetic test database is what exposed it; the fail-open was there either way.

``parse_uuid`` returns ``None`` rather than raising, because all three callers already have a
correct answer for "this identifier cannot be valid" (401, or fall back to a name lookup) and none
of them wants an exception.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

__all__ = ["parse_uuid"]


def parse_uuid(value: Any) -> Optional[uuid.UUID]:
    """Return ``value`` as a :class:`uuid.UUID`, or ``None`` if it cannot be one.

    Accepts a ``UUID`` unchanged and any string form ``uuid.UUID`` accepts (with or without
    hyphens, with or without a ``urn:uuid:`` prefix). Anything else - ``None``, an int, a
    non-UUID string - is ``None``.
    """
    if isinstance(value, uuid.UUID):
        return value
    if not isinstance(value, str):
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None
