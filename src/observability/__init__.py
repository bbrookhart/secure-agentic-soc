"""Operational telemetry, health checks, and structured application logging.

Separate from ``src/security/audit.py`` on purpose. The audit log is evidence:
complete, chained, signed, never sampled. This is operations: aggregated,
sampled, lossy. Conflating them produces a log that is bad evidence and bad
telemetry at once.
"""

from __future__ import annotations

from src.observability.health import Check, readiness, render, run_checks
from src.observability.telemetry import ALLOWED_ATTRIBUTES, safe_attributes, setup

__all__ = [
    "ALLOWED_ATTRIBUTES",
    "Check",
    "readiness",
    "render",
    "run_checks",
    "safe_attributes",
    "setup",
]
