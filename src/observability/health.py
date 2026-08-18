"""Readiness checks that mean something.

The container healthcheck currently asks Streamlit whether Streamlit is up. That
answers "is the web server listening", not "can this system triage an alert" --
a process with an unwritable state volume, a broken audit chain and no model
would pass it happily.

These checks answer the second question. They are deliberately split by
severity, because not all of them should take a container out of service:

* **Critical** -- the system cannot do its job safely. An unwritable audit path
  means investigations would run unrecorded, which is worse than not running
  them. Failing readiness is correct.
* **Degraded** -- the system works at reduced quality. No model server means the
  deterministic floor, which still triages, still gates, still reports. Pulling
  the instance out of rotation for that would turn a quality drop into an
  outage.

Checks never raise and never touch alert content.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Status = Literal["ok", "degraded", "critical"]


@dataclass(frozen=True)
class Check:
    """One readiness probe."""

    name: str
    status: Status
    detail: str

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _writable(path: Path) -> tuple[bool, str]:
    """Can this process actually write here? Test it rather than assume."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, prefix=".healthcheck-", delete=True):
            return True, "writable"
    except Exception as exc:  # noqa: BLE001 - the failure is the answer
        return False, f"{type(exc).__name__}: {exc}"


def check_audit_writable() -> Check:
    """Critical: an unrecorded investigation is worse than no investigation."""
    from src.config import get_settings

    ok, detail = _writable(get_settings().audit_log_path.parent)
    return Check("audit_writable", "ok" if ok else "critical", detail)


def check_state_writable() -> Check:
    """Critical: without checkpoints the approval gate cannot suspend and resume."""
    from src.config import get_settings

    ok, detail = _writable(get_settings().state_dir)
    return Check("state_writable", "ok" if ok else "critical", detail)


def check_signing_key() -> Check:
    """Critical when signing is on: silently unsigned records are a false assurance."""
    from src.config import get_settings

    settings = get_settings()
    if not settings.audit_signing_enabled:
        return Check("signing_key", "ok", "signing disabled")

    path = settings.audit_signing_key_path
    if not path.exists():
        return Check("signing_key", "ok", "not yet generated; created on first write")

    mode = path.stat().st_mode
    if mode & 0o077:
        return Check(
            "signing_key",
            "critical",
            f"key is readable beyond its owner ({oct(mode & 0o777)}); anyone who reads it can forge",
        )
    return Check("signing_key", "ok", "present, owner-only")


def check_case_store() -> Check:
    """Degraded: correlation stops, triage continues."""
    try:
        from src.memory import get_case_store

        # A trivial query, so this probes the connection rather than the import.
        get_case_store().history_for_entity("healthcheck-probe", limit=1)
        return Check("case_store", "ok", "reachable")
    except Exception as exc:  # noqa: BLE001
        return Check("case_store", "degraded", f"{type(exc).__name__}: {exc}")


def check_model() -> Check:
    """Degraded: the deterministic floor still triages, gates and reports."""
    from src.config import get_settings
    from src.llm import is_available

    settings = get_settings()
    if settings.offline_mode:
        return Check("model", "ok", "offline mode; deterministic path by configuration")
    if is_available():
        return Check("model", "ok", f"{settings.ollama_model} reachable")
    return Check(
        "model",
        "degraded",
        "model server unreachable; running on deterministic fallbacks with reduced analysis quality",
    )


def check_audit_forwarding() -> Check:
    """Degraded: forwarding that fails silently would fake a control."""
    from src.security.audit import get_audit_logger

    health = get_audit_logger().forwarding_health()
    if not health:
        return Check("audit_forwarding", "ok", "no forwarder configured")

    failing = [entry for entry in health if int(entry.get("failures", 0)) > 0]
    if failing:
        names = ", ".join(str(entry["sink"]) for entry in failing)
        return Check("audit_forwarding", "degraded", f"forwarding failures: {names}")
    return Check("audit_forwarding", "ok", f"{len(health)} forwarder(s) healthy")


def check_encryption_declaration() -> Check:
    """Purely declarative, and reported as such (SC-28)."""
    from src.config import get_settings

    if get_settings().state_volume_encrypted:
        return Check("state_encryption", "ok", "declared encrypted by the operator (unverified)")
    return Check(
        "state_encryption",
        "degraded",
        "state volume not declared encrypted; checkpoints and audit logs rest in the clear",
    )


ALL_CHECKS = (
    check_state_writable,
    check_audit_writable,
    check_signing_key,
    check_case_store,
    check_model,
    check_audit_forwarding,
    check_encryption_declaration,
)


def run_checks() -> list[Check]:
    """Every check, never raising."""
    results: list[Check] = []
    for check in ALL_CHECKS:
        try:
            results.append(check())
        except Exception as exc:  # noqa: BLE001 - a broken probe is a degraded answer
            results.append(Check(check.__name__, "degraded", f"probe failed: {exc}"))
    return results


def readiness() -> tuple[bool, list[Check]]:
    """``(ready, checks)``. Only a critical failure withholds readiness.

    Degraded is deliberately still ready: taking an instance out of rotation
    because the model is down would convert reduced analysis quality into a
    total outage, and the deterministic floor exists precisely so that is not
    necessary.
    """
    checks = run_checks()
    return not any(check.status == "critical" for check in checks), checks


def render(checks: list[Check]) -> str:
    """Plain-text report for the CLI and the container healthcheck."""
    icon = {"ok": "ok      ", "degraded": "DEGRADED", "critical": "CRITICAL"}
    lines = [f"  {icon[c.status]}  {c.name:<22} {c.detail}" for c in checks]
    return "\n".join(lines)
