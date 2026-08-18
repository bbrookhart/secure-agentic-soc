"""The signals worth watching, and the recording helpers that emit them.

Golden signals are here because every service needs them. The ones that justify
the module are the *security* signals -- in a SOC tool the interesting question
is rarely "is latency up", it is:

* **Is injection detection spiking?** A jump means either an active campaign or
  a broken sanitiser, and both need someone now.
* **How old is the oldest pending approval?** A gate nobody answers is a failed
  control that looks identical to a working one. This is the metric most likely
  to reveal that the human-in-the-loop design has quietly become a queue.
* **Are approvals being refused?** Repeated authorization denials are either
  misconfigured roles or someone reaching for authority they do not have.
* **Is the model falling back?** Every fallback is an investigation done at the
  deterministic floor, which is a real quality drop the metrics should show
  rather than hide.
* **Is audit forwarding failing?** Forwarding that fails silently is worse than
  none, because it looks like a control that is not running.

Every helper is a no-op when telemetry is disabled, and every attribute passes
through :func:`~src.observability.telemetry.safe_attributes` -- so no caller can
put an alert id or a hostname on a metric even by accident.
"""

from __future__ import annotations

import threading
from typing import Any

from src.observability.telemetry import get_meter, safe_attributes

_lock = threading.Lock()
_instruments: dict[str, Any] = {}
_built = False


def _build() -> None:
    """Create the instruments once, if telemetry is on."""
    global _built
    with _lock:
        if _built:
            return
        _built = True

        meter = get_meter()
        if meter is None:
            return

        _instruments.update(
            {
                # --- Golden signals ------------------------------------------
                "runs_started": meter.create_counter(
                    "soc.runs.started", description="Investigations started."
                ),
                "runs_completed": meter.create_counter(
                    "soc.runs.completed", description="Investigations finished, by final phase."
                ),
                "run_duration": meter.create_histogram(
                    "soc.run.duration", unit="ms", description="Wall-clock time per investigation."
                ),
                "errors": meter.create_counter(
                    "soc.errors", description="Errors, by class."
                ),
                # --- Security signals ----------------------------------------
                "injection_detected": meter.create_counter(
                    "soc.injection.detected",
                    description="Injection heuristics matched, by source (alert or tool).",
                ),
                "policy_decisions": meter.create_counter(
                    "soc.policy.decisions",
                    description="Policy outcomes, by effect and rule.",
                ),
                "authz_denials": meter.create_counter(
                    "soc.authz.denials",
                    description="Approvals refused, by authorization rule.",
                ),
                "approvals_requested": meter.create_counter(
                    "soc.approvals.requested", description="Human approval gates opened."
                ),
                "approvals_decided": meter.create_counter(
                    "soc.approvals.decided", description="Approval decisions, by outcome."
                ),
                "approval_wait": meter.create_histogram(
                    "soc.approval.wait",
                    unit="s",
                    description="Time an approval gate stayed open. A gate nobody answers is a failed control.",
                ),
                # --- Model and tools -----------------------------------------
                "llm_calls": meter.create_counter(
                    "soc.llm.calls", description="LLM calls, by actor and outcome."
                ),
                "llm_duration": meter.create_histogram(
                    "soc.llm.duration", unit="ms", description="LLM call latency."
                ),
                "llm_tokens": meter.create_counter(
                    "soc.llm.tokens", description="Tokens consumed, by actor and direction."
                ),
                "tool_calls": meter.create_counter(
                    "soc.tool.calls", description="Tool invocations, by tool and outcome."
                ),
                "tool_duration": meter.create_histogram(
                    "soc.tool.duration", unit="ms", description="Tool latency."
                ),
                # --- Audit ----------------------------------------------------
                "audit_forward_failures": meter.create_counter(
                    "soc.audit.forward.failures",
                    description="Audit events that failed to reach an external sink.",
                ),
                "chain_verifications": meter.create_counter(
                    "soc.audit.chain.verifications",
                    description="Chain verification attempts, by result.",
                ),
            }
        )


def _add(name: str, value: float = 1, **attributes: Any) -> None:
    _build()
    instrument = _instruments.get(name)
    if instrument is None:
        return
    try:
        instrument.add(value, safe_attributes(attributes))
    except Exception:  # noqa: BLE001, S110 - telemetry must never break the pipeline
        pass


def _observe(name: str, value: float, **attributes: Any) -> None:
    _build()
    instrument = _instruments.get(name)
    if instrument is None:
        return
    try:
        instrument.record(value, safe_attributes(attributes))
    except Exception:  # noqa: BLE001, S110 - telemetry must never break the pipeline
        pass


# --- Runs -------------------------------------------------------------------
def run_started(*, offline: bool) -> None:
    _add("runs_started", offline=offline)


def run_completed(*, phase: str, verdict: str = "", duration_ms: float = 0.0) -> None:
    _add("runs_completed", phase=phase, verdict=verdict)
    if duration_ms:
        _observe("run_duration", duration_ms, phase=phase)


def error(*, kind: str) -> None:
    _add("errors", kind=kind)


# --- Security ---------------------------------------------------------------
def injection_detected(*, source: str) -> None:
    """``source`` is 'alert' or 'tool' -- never the tool's content."""
    _add("injection_detected", source=source)


def policy_decision(*, effect: str, rule_id: str) -> None:
    _add("policy_decisions", effect=effect, rule_id=rule_id)


def authorization_denied(*, rule_id: str) -> None:
    _add("authz_denials", rule_id=rule_id)


def approval_requested(*, rule_id: str, severity: str) -> None:
    _add("approvals_requested", rule_id=rule_id, severity=severity)


def approval_decided(*, outcome: str, waited_seconds: float = 0.0) -> None:
    _add("approvals_decided", outcome=outcome)
    if waited_seconds > 0:
        _observe("approval_wait", waited_seconds, outcome=outcome)


# --- Model and tools --------------------------------------------------------
def llm_call(*, actor: str, outcome: str, duration_ms: float = 0.0) -> None:
    _add("llm_calls", actor=actor, outcome=outcome)
    if duration_ms:
        _observe("llm_duration", duration_ms, actor=actor)


def llm_tokens(*, actor: str, input_tokens: int = 0, output_tokens: int = 0) -> None:
    """Token spend, so cost per investigation is knowable rather than guessed."""
    if input_tokens:
        _add("llm_tokens", input_tokens, actor=actor, kind="input")
    if output_tokens:
        _add("llm_tokens", output_tokens, actor=actor, kind="output")


def tool_call(*, tool: str, outcome: str, duration_ms: float = 0.0) -> None:
    _add("tool_calls", tool=tool, outcome=outcome)
    if duration_ms:
        _observe("tool_duration", duration_ms, tool=tool)


# --- Audit ------------------------------------------------------------------
def audit_forward_failure() -> None:
    _add("audit_forward_failures")


def chain_verified(*, outcome: str) -> None:
    _add("chain_verifications", outcome=outcome)


def reset() -> None:
    """Test hook: rebuild instruments on next use."""
    global _built
    with _lock:
        _built = False
        _instruments.clear()
