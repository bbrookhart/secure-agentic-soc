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
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from src.security.audit import AuditEvent


class AuditSink(Protocol):
    """Anything that can accept an audit event."""

    def write(self, event: AuditEvent) -> None: ...

    def close(self) -> None: ...


class JsonlSink:
    """Append-only JSONL file with a persistent handle.

    ``durable=True`` flushes and fsyncs every event.  That costs a syscall per
    record and is the right default for an audit log: the events most worth
    having are the ones written immediately before something goes wrong.
    """

    def __init__(self, path: Path, *, durable: bool = True) -> None:
        self.path = Path(path)
        self.durable = durable
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle: object | None = None
        self._lock = threading.Lock()

    def write(self, event: AuditEvent) -> None:
        with self._lock:
            handle = self._handle
            if handle is None:
                handle = open(self.path, "a", encoding="utf-8")  # noqa: SIM115 - held open deliberately
                self._handle = handle
            handle.write(event.to_jsonl() + "\n")  # type: ignore[attr-defined]
            handle.flush()  # type: ignore[attr-defined]
            if self.durable:
                os.fsync(handle.fileno())  # type: ignore[attr-defined]

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.close()  # type: ignore[attr-defined]
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
    local = JsonlSink(path, durable=durable)
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
