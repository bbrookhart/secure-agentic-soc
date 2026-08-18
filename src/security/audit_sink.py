"""Where audit events go.

The hash chain makes local edits *detectable*.  It cannot make them
*impossible*: an attacker holding both file write and code execution can
recompute the whole chain and leave it internally consistent.  The README calls
this the project's largest gap, and it is not something a cleverer hash solves.

What closes it is getting the event off the host before it can be retracted.
Once an event has reached an append-only store under different credentials, an
attacker who later rewrites the local file produces a divergence between the two
copies -- and divergence is exactly what an auditor can act on.

So this module separates *what* is recorded (``AuditLogger``, which owns the
chain) from *where it lands*:

* :class:`JsonlSink` -- the local record.  Holds one append handle and fsyncs,
  because an audit line that is still in a page cache when the box dies is not
  evidence.
* :class:`HttpSink` / :class:`SyslogSink` -- forwarders to storage the
  application cannot rewrite.
* :class:`FanOutSink` -- writes to several.  A forwarder that is down must never
  cost the local write, so failures are captured rather than raised.

Sinks are write-only by design.  Reading back is the local file's job, and
``AuditLogger`` keeps its own path for that.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from src.security.audit import AuditEvent


class AuditSink(Protocol):
    """Anything that can accept an audit event."""

    def write(self, event: AuditEvent) -> None: ...

    def close(self) -> None: ...


class JsonlSink:
    """Append-only JSONL file with a persistent handle and size-based rotation.

    ``durable=True`` flushes and fsyncs every event.  That costs a syscall per
    record and is the right default for an audit log: the events most worth
    having are the ones written immediately before something goes wrong.

    **Rotation does not break the chain.** Segments are numbered
    (``audit.jsonl``, ``audit.jsonl.1``, …) and a run's events may straddle a
    boundary, so verification has to read every segment -- which
    :meth:`AuditLogger.read_events` does, oldest first. Nothing is rewritten on
    rotation; the bytes simply move to a new name.

    **Retention deletes evidence, so it is bounded and deliberate** (NIST 800-53
    AU-11). ``max_segments`` caps disk use; anything discarded is gone, which is
    the argument for forwarding events off-host, where retention is somebody
    else's policy and not tied to this volume's size.
    """

    def __init__(
        self,
        path: Path,
        *,
        durable: bool = True,
        max_bytes: int = 0,
        max_segments: int = 10,
    ) -> None:
        self.path = Path(path)
        self.durable = durable
        self.max_bytes = max_bytes
        self.max_segments = max(1, max_segments)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle: Any = None
        self._lock = threading.Lock()

    def write(self, event: AuditEvent) -> None:
        line = event.to_jsonl() + "\n"
        with self._lock:
            self._rotate_if_needed(len(line.encode("utf-8")))
            handle = self._handle
            if handle is None:
                handle = open(self.path, "a", encoding="utf-8")  # noqa: SIM115 - held open deliberately
                self._handle = handle
            handle.write(line)
            handle.flush()
            if self.durable:
                os.fsync(handle.fileno())

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        """Roll to a new segment before the current one exceeds its budget."""
        if self.max_bytes <= 0:
            return
        try:
            current = self.path.stat().st_size
        except OSError:
            return
        if current + incoming_bytes <= self.max_bytes:
            return

        if self._handle is not None:
            self._handle.close()
            self._handle = None

        # Shift segments down; the oldest falls off the end.
        oldest = self.path.with_suffix(self.path.suffix + f".{self.max_segments}")
        if oldest.exists():
            oldest.unlink()
        for index in range(self.max_segments - 1, 0, -1):
            source = self.path.with_suffix(self.path.suffix + f".{index}")
            if source.exists():
                source.rename(self.path.with_suffix(self.path.suffix + f".{index + 1}"))
        if self.path.exists():
            self.path.rename(self.path.with_suffix(self.path.suffix + ".1"))

    def segments(self) -> list[Path]:
        """Every segment, oldest first. Verification must read all of them."""
        rotated: list[tuple[int, Path]] = []
        for candidate in self.path.parent.glob(self.path.name + ".*"):
            suffix = candidate.name.rsplit(".", 1)[-1]
            if suffix.isdigit():
                rotated.append((int(suffix), candidate))
        ordered = [path for _, path in sorted(rotated, reverse=True)]
        if self.path.exists():
            ordered.append(self.path)
        return ordered

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.close()
                self._handle = None


class HttpSink:
    """Forward events to an external collector over HTTP.

    Best-effort by construction: a collector outage must not stop an
    investigation, and must not stop the local write either.  Failures are
    counted and exposed on :attr:`failures` so the UI can show that forwarding
    has stopped -- silent forwarding failure would be worse than no forwarding,
    because it looks like protection that is not there.
    """

    def __init__(self, url: str, *, token: str | None = None, timeout: float = 2.0) -> None:
        self.url = url
        self.timeout = timeout
        self._headers = {"content-type": "application/json"}
        if token:
            self._headers["authorization"] = f"Bearer {token}"
        self.failures = 0
        self.last_error: str = ""

    def write(self, event: AuditEvent) -> None:
        try:
            import httpx

            response = httpx.post(
                self.url,
                content=event.to_jsonl(),
                headers=self._headers,
                timeout=self.timeout,
            )
            if response.status_code >= 400:
                raise RuntimeError(f"collector returned {response.status_code}")
        except Exception as exc:  # noqa: BLE001 - forwarding is best effort
            self.failures += 1
            self.last_error = f"{type(exc).__name__}: {exc}"

    def close(self) -> None:
        return None


class SyslogSink:
    """Forward events to syslog, which is often already shipped off-host."""

    def __init__(self, address: str = "/dev/log", *, facility: int | None = None) -> None:
        import logging
        import logging.handlers

        self.failures = 0
        self.last_error = ""
        self._logger = logging.getLogger("agentic-soc-audit")
        self._logger.propagate = False

        target: object = address
        if ":" in address and not address.startswith("/"):
            host, _, port = address.rpartition(":")
            target = (host, int(port))

        handler = logging.handlers.SysLogHandler(
            address=target,  # type: ignore[arg-type]
            facility=facility if facility is not None else logging.handlers.SysLogHandler.LOG_AUTH,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)

    def write(self, event: AuditEvent) -> None:
        try:
            self._logger.info(event.to_jsonl())
        except Exception as exc:  # noqa: BLE001 - forwarding is best effort
            self.failures += 1
            self.last_error = f"{type(exc).__name__}: {exc}"

    def close(self) -> None:
        for handler in list(self._logger.handlers):
            handler.close()
            self._logger.removeHandler(handler)


class FanOutSink:
    """Write one event to several sinks.

    Order matters: the local sink is written first and its failure *does*
    propagate, because losing the local record is a real failure.  Forwarders
    run afterwards and swallow their own errors.
    """

    def __init__(self, primary: AuditSink, *forwarders: AuditSink) -> None:
        self.primary = primary
        self.forwarders = list(forwarders)

    def write(self, event: AuditEvent) -> None:
        self.primary.write(event)
        for sink in self.forwarders:
            try:
                sink.write(event)
            except Exception:  # noqa: BLE001, S110 - forwarder faults are already counted
                pass

    def close(self) -> None:
        for sink in [self.primary, *self.forwarders]:
            sink.close()

    def forwarding_health(self) -> list[dict[str, object]]:
        """Per-forwarder failure counts, for the analyst UI."""
        return [
            {
                "sink": type(sink).__name__,
                "failures": getattr(sink, "failures", 0),
                "last_error": getattr(sink, "last_error", ""),
            }
            for sink in self.forwarders
        ]


def build_sink_from_settings(path: Path, *, durable: bool = True) -> AuditSink:
    """Assemble the configured sink chain: local file plus any forwarders."""
    from src.config import get_settings

    settings = get_settings()
    local = JsonlSink(
        path,
        durable=durable,
        max_bytes=settings.audit_max_segment_bytes,
        max_segments=settings.audit_max_segments,
    )
    forwarders: list[AuditSink] = []

    if settings.audit_forward_url:
        token = (
            settings.audit_forward_token.get_secret_value()
            if settings.audit_forward_token is not None
            else None
        )
        forwarders.append(HttpSink(settings.audit_forward_url, token=token))

    if settings.audit_syslog_address:
        try:
            forwarders.append(SyslogSink(settings.audit_syslog_address))
        except Exception as exc:  # noqa: BLE001 - an unreachable syslog must not stop startup
            # Loud, because an operator who configured forwarding needs to know
            # it is not running. Silence here would fake a control.
            print(  # noqa: T201 - startup diagnostic
                f"[audit] syslog forwarding to {settings.audit_syslog_address} unavailable: {exc}",
                file=sys.stderr,
            )

    if not forwarders:
        return local
    return FanOutSink(local, *forwarders)


def event_to_json(event: AuditEvent) -> str:
    """Canonical wire form, kept here so forwarders cannot drift from the file."""
    return json.dumps(event.model_dump(mode="json"), sort_keys=True, default=str)
