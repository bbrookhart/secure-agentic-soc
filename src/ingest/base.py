"""The ingestion trust boundary and the source contract.

Everything downstream treats alert content as attacker-influenced.  This is
where that content first enters, and the single rule of this package is that
**every adapter terminates in :func:`parse_alert`**.  However an alert arrives
-- a file, a SIEM query, a webhook -- it becomes a :class:`SecurityAlert` by
passing through one strict validator, so there is exactly one place to reason
about what a hostile payload can be.

An adapter that constructs a ``SecurityAlert`` by hand, or that "helpfully"
repairs a malformed field before validation, has moved the boundary without
moving the review that goes with it.  Adapters map vendor fields onto a plain
dict and hand it over; they do not decide what is valid.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Protocol

from pydantic import ValidationError

from src.state import SecurityAlert


class AlertIngestError(ValueError):
    """Raised when an alert payload cannot be parsed into a valid alert."""


#: Refuse absurdly large payloads outright rather than parsing them.
MAX_ALERT_BYTES = 512 * 1024


def parse_alert(payload: dict[str, Any]) -> SecurityAlert:
    """Validate a raw alert dictionary. The only way into the system."""
    try:
        return SecurityAlert.model_validate(payload)
    except ValidationError as exc:
        raise AlertIngestError(
            f"alert failed schema validation with {exc.error_count()} error(s): "
            + "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]
            )
        ) from exc


class AlertSource(Protocol):
    """A place alerts come from.

    ``poll`` returns the alerts available now.  Implementations are expected to
    track their own position (a timestamp, a cursor, a last-seen id) so repeated
    calls do not re-emit the same alert -- deduplication downstream is a
    safety net, not a substitute.
    """

    name: str

    def poll(self, *, limit: int = 50) -> Iterator[SecurityAlert]: ...


class SourceError(RuntimeError):
    """Raised when a source cannot be reached or returns something unusable."""
