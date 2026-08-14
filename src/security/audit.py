"""Structured, tamper-evident audit logging.

Design goals:

* **Complete** -- every routing decision, LLM call, tool invocation, policy
  evaluation and approval is recorded.  Nothing an agent does is invisible.
* **Structured** -- a closed action vocabulary (:class:`~src.enums.AuditAction`)
  plus typed fields, emitted as JSONL so it can be shipped to a SIEM as-is.
* **Tamper-evident** -- each event carries a SHA-256 hash chained to its
  predecessor.  Editing or removing a historical line breaks verification.
  This is *evidence of* tampering, not prevention; real deployments would ship
  events to append-only storage (see docs/THREAT_MODEL.md).
* **Redacted** -- every payload passes through the secret redactor on the way
  in, so the audit log can never become the place secrets leak.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.enums import AgentRole, AuditAction
from src.security.redaction import redact_obj

GENESIS_HASH = "0" * 64


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuditEvent(BaseModel):
    """A single immutable audit record."""

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=_utc_now)
    thread_id: str
    sequence: int = Field(ge=0, description="Monotonic position within the run.")
    actor: AgentRole
    action: AuditAction
    summary: str = Field(description="One-line human-readable description.")
    details: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float | None = None
    success: bool = True
    # Tamper-evidence chain.
    prev_hash: str = GENESIS_HASH
    event_hash: str = ""

    def payload_for_hash(self) -> dict[str, Any]:
        """Canonical subset hashed into the chain (everything but the hash itself)."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "thread_id": self.thread_id,
            "sequence": self.sequence,
            "actor": self.actor.value,
            "action": self.action.value,
            "summary": self.summary,
            "details": self.details,
            "duration_ms": self.duration_ms,
            "success": self.success,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        canonical = json.dumps(self.payload_for_hash(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_jsonl(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, default=str)

    def render(self) -> str:
        """Compact single-line rendering for CLI output."""
        status = "ok" if self.success else "FAIL"
        took = f" ({self.duration_ms:.0f}ms)" if self.duration_ms is not None else ""
        return f"[{self.sequence:03d}] {self.actor.value:<12} {self.action.value:<24} {self.summary}{took} [{status}]"


class AuditLogger:
    """Append-only JSONL audit sink with an in-process hash chain.

    Thread-safe: the Streamlit UI and the graph can both hold a reference.
    """

    def __init__(self, path: Path | None = None, *, echo: bool = False) -> None:
        self._path = path
        self._echo = echo
        self._lock = threading.Lock()
        # Per-thread_id chain state, so concurrent runs do not interleave hashes.
        self._sequence: dict[str, int] = {}
        self._last_hash: dict[str, str] = {}
        #: Problems encountered while reading the log back (corrupt/edited lines).
        self.read_errors: list[str] = []
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        thread_id: str,
        actor: AgentRole,
        action: AuditAction,
        summary: str,
        details: dict[str, Any] | None = None,
        duration_ms: float | None = None,
        success: bool = True,
    ) -> AuditEvent:
        """Build, hash, persist and return a single audit event."""
        safe_details: dict[str, Any] = redact_obj(details or {})
        safe_summary = redact_obj(summary)

        with self._lock:
            sequence = self._sequence.get(thread_id, 0)
            prev_hash = self._last_hash.get(thread_id, GENESIS_HASH)

            event = AuditEvent(
                thread_id=thread_id,
                sequence=sequence,
                actor=actor,
                action=action,
                summary=safe_summary,
                details=safe_details,
                duration_ms=duration_ms,
                success=success,
                prev_hash=prev_hash,
            )
            event = event.model_copy(update={"event_hash": event.compute_hash()})

            self._sequence[thread_id] = sequence + 1
            self._last_hash[thread_id] = event.event_hash
            self._write(event)

        if self._echo:
            print(event.render(), flush=True)  # noqa: T201 - intentional CLI trace
        return event

    def _write(self, event: AuditEvent) -> None:
        if self._path is None:
            return
        # Line-buffered append + fsync-free write: durable enough for a local
        # demo, and each line is self-contained so a crash truncates at most
        # one record.
        with open(self._path, "a", encoding="utf-8") as handle:
            handle.write(event.to_jsonl() + "\n")

    # --- Reading / verification -----------------------------------------
    def read_events(self, thread_id: str | None = None) -> list[AuditEvent]:
        """Load persisted events, optionally filtered to one run."""
        if self._path is None or not self._path.exists():
            return []
        events: list[AuditEvent] = []
        corrupt: list[int] = []

        with open(self._path, encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = AuditEvent.model_validate_json(line)
                except Exception as exc:  # noqa: BLE001 - one bad line must not blind the reader
                    # A malformed line is itself security-relevant: it means the
                    # log was truncated or edited. Record it rather than
                    # silently skipping, so callers can surface it.
                    corrupt.append(line_number)
                    self.read_errors.append(f"line {line_number}: {type(exc).__name__}")
                    continue
                if thread_id is None or event.thread_id == thread_id:
                    events.append(event)

        if corrupt:
            # Sequence gaps from dropped lines are also caught by verify_chain;
            # this makes the cause explicit rather than inferred.
            self.read_errors.append(
                f"{len(corrupt)} unparseable audit line(s) at {corrupt[:10]}"
            )
        return events


def verify_chain(events: list[AuditEvent], *, expect_genesis: bool = True) -> tuple[bool, str]:
    """Verify the hash chain for a single run's events.

    Returns ``(ok, message)``.  Events must all belong to one ``thread_id``;
    the caller is expected to filter first.

    ``expect_genesis`` controls whether the first event must be sequence 0
    chained to the genesis hash.  Pass ``False`` when verifying a *slice* of a
    run (for example the events accumulated in graph state, which exclude
    events written directly to the logger).  A slice can still be checked for
    contiguity, link integrity and content integrity -- it simply cannot prove
    that nothing was removed from before the slice began, so callers wanting a
    complete guarantee should verify the persisted log instead.
    """
    if not events:
        return True, "no events to verify"

    ordered = sorted(events, key=lambda e: e.sequence)
    start = ordered[0].sequence

    if expect_genesis:
        if start != 0:
            return False, f"chain does not start at sequence 0 (found {start})"
        if ordered[0].prev_hash != GENESIS_HASH:
            return False, "first event is not chained to the genesis hash"

    expected_prev: str | None = GENESIS_HASH if expect_genesis else None

    for offset, event in enumerate(ordered):
        expected_sequence = start + offset
        if event.sequence != expected_sequence:
            return False, (
                f"sequence gap: expected {expected_sequence}, found {event.sequence} "
                "(an event was removed or reordered)"
            )
        if expected_prev is not None and event.prev_hash != expected_prev:
            return False, f"chain break at sequence {event.sequence}: prev_hash mismatch"
        if event.compute_hash() != event.event_hash:
            return False, f"content tampered at sequence {event.sequence}: hash mismatch"
        expected_prev = event.event_hash

    scope = "" if expect_genesis else f" (partial chain: slice starting at sequence {start})"
    return True, f"verified {len(ordered)} events{scope}"


# --- Process-wide default sink ------------------------------------------
_default_logger: AuditLogger | None = None
_default_lock = threading.Lock()


def get_audit_logger() -> AuditLogger:
    """Return the process-wide audit logger, creating it on first use."""
    global _default_logger
    if _default_logger is None:
        with _default_lock:
            if _default_logger is None:
                from src.config import get_settings

                settings = get_settings()
                settings.ensure_dirs()
                _default_logger = AuditLogger(
                    settings.audit_log_path,
                    echo=os.environ.get("SOC_ECHO_AUDIT", "").lower() in {"1", "true", "yes"},
                )
    return _default_logger


def set_audit_logger(logger: AuditLogger | None) -> None:
    """Override the default sink (used by tests)."""
    global _default_logger
    _default_logger = logger
