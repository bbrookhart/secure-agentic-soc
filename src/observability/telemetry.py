"""Operational telemetry -- deliberately separate from the audit log.

The two are often conflated and should not be. The audit log is *evidence*:
complete, hash-chained, signed, never sampled, written for someone who may not
trust us. Telemetry is *operations*: aggregated, sampled, lossy, written for
whoever is on call. Neither can do the other's job. Paging on the audit log
would be slow and wrong; reconstructing an incident from metrics would be
impossible.

**Telemetry is an egress path, and in this system the data is incident data.**
That makes label discipline a security control rather than a cardinality
concern. A metric labelled with a hostname or an alert id ships the contents of
an investigation to whatever backend the collector points at -- which may be a
vendor SaaS outside the trust boundary that the rest of this project works to
maintain.

So the rule here is absolute and tested: **attributes may only take values from
a closed vocabulary** -- severity, category, rule id, route, agent role, tool
name, outcome. Never an alert id, hostname, username, indicator, or any free
text. :func:`safe_attributes` enforces it at runtime and
``tests/test_observability.py`` enforces it at build time.

Disabled by default. An observability stack that ships incident metadata
somewhere unexpected is worse than no metrics, so turning it on is a decision.
"""

from __future__ import annotations

import threading
from typing import Any

#: Attribute keys permitted on spans and metrics. Anything else is dropped.
#:
#: Every one of these is low-cardinality and drawn from an enum or a fixed set
#: of names in this codebase. That is the point: the vocabulary is closed, so a
#: future caller cannot widen it by accident.
ALLOWED_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "actor",  # AgentRole
        "route",  # supervisor Route
        "rule_id",  # policy / authz rule identifier
        "effect",  # PolicyEffect
        "severity",  # Severity
        "category",  # AlertCategory
        "verdict",  # Verdict
        "phase",  # Phase
        "tool",  # tool name from the registry
        "outcome",  # ok | denied | rate_limited | error | fallback
        "source",  # alert | tool
        "kind",  # input | output (tokens), error class
        "offline",  # bool
        "used_llm",  # bool
    }
)

#: Values are bounded too: an allowed key with an unbounded value is the same
#: leak. Anything longer than this is dropped rather than truncated, because a
#: truncated hostname is still a hostname.
MAX_ATTRIBUTE_LENGTH = 48

_lock = threading.Lock()
_initialised = False
_tracer: Any = None
_meter: Any = None


def safe_attributes(attributes: dict[str, Any] | None) -> dict[str, Any]:
    """Drop anything outside the closed vocabulary.

    Silently dropping is deliberate: the alternative is raising inside a metric
    call and turning an observability mistake into an outage. What is dropped is
    visible in tests, which is where it should be caught.
    """
    if not attributes:
        return {}

    safe: dict[str, Any] = {}
    for key, value in attributes.items():
        if key not in ALLOWED_ATTRIBUTES:
            continue
        if isinstance(value, bool | int | float):
            safe[key] = value
            continue
        text = str(value)
        if len(text) <= MAX_ATTRIBUTE_LENGTH:
            safe[key] = text
    return safe


def setup(*, service_name: str = "agentic-soc") -> bool:
    """Initialise tracing and metrics. Returns whether telemetry is active.

    Idempotent and failure-tolerant: a broken collector configuration must not
    stop an investigation, so any error here downgrades to no-op instruments.
    """
    global _initialised, _tracer, _meter

    with _lock:
        if _initialised:
            return _tracer is not None

        _initialised = True
        from src.config import get_settings

        settings = get_settings()
        if not settings.telemetry_enabled:
            return False

        try:
            from opentelemetry import metrics, trace
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            resource = Resource.create(
                {"service.name": service_name, "service.version": settings.app_version}
            )

            if settings.telemetry_endpoint:
                from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                    OTLPMetricExporter,
                )
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                    OTLPSpanExporter,
                )

                tracer_provider = TracerProvider(resource=resource)
                tracer_provider.add_span_processor(
                    BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.telemetry_endpoint))
                )
                meter_provider = MeterProvider(
                    resource=resource,
                    metric_readers=[
                        PeriodicExportingMetricReader(
                            OTLPMetricExporter(endpoint=settings.telemetry_endpoint)
                        )
                    ],
                )
            else:
                # In-process only: instruments record, nothing is exported.
                # Useful for tests and for confirming instrumentation before
                # pointing it at a collector.
                tracer_provider = TracerProvider(resource=resource)
                meter_provider = MeterProvider(resource=resource)

            trace.set_tracer_provider(tracer_provider)
            metrics.set_meter_provider(meter_provider)
            _tracer = trace.get_tracer(service_name)
            _meter = metrics.get_meter(service_name)
            return True

        except Exception as exc:  # noqa: BLE001 - telemetry must never break the pipeline
            import sys

            print(  # noqa: T201 - startup diagnostic
                f"[telemetry] disabled, setup failed: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            _tracer = None
            _meter = None
            return False


def get_tracer() -> Any:
    """The tracer, or None when telemetry is off."""
    if not _initialised:
        setup()
    return _tracer


def get_meter() -> Any:
    """The meter, or None when telemetry is off."""
    if not _initialised:
        setup()
    return _meter


def reset() -> None:
    """Test hook: forget initialisation state."""
    global _initialised, _tracer, _meter
    with _lock:
        _initialised = False
        _tracer = None
        _meter = None
