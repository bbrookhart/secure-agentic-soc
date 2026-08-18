"""Shared agent scaffolding.

Each specialist agent is a plain LangGraph node function, not an autonomous
ReAct loop.  That is a deliberate architectural choice:

* **Explicit control flow.** The order of operations in each agent is written
  in Python and can be read, reviewed and tested.  The LLM is used for
  judgement (severity, narrative, correlation), not for deciding which
  capability to reach for next.
* **Bounded tool use.** Tool calls happen at points we chose, within budgets we
  set, through the guarded broker.  There is no loop for an injected
  instruction to steer.
* **Deterministic fallback.** Every agent can complete its job with the LLM
  switched off, so the pipeline has a floor below which it cannot degrade.

``src/agents/baseline.py`` keeps the single-ReAct-agent implementation this
design replaced, so the two can be compared directly.
"""

from __future__ import annotations

from typing import Any

from src.enums import AgentRole, AuditAction
from src.prompts import SECURITY_PREAMBLE as _SECURITY_PREAMBLE
from src.security.audit import AuditEvent, AuditLogger
from src.security.identity import AgentIdentity, get_identity
from src.security.sanitizer import UntrustedContent, sanitize_untrusted
from src.state import SecurityAlert
from src.tools.base import ToolBroker

#: Prepended to every agent system prompt.
#:
#: The text lives in ``src/prompts`` so it is versioned, hashed and covered by
#: CODEOWNERS. It is still the weakest of the injection controls -- least
#: privilege and the policy gate are what hold -- but weakening it is now a
#: visible diff against a reviewed artefact rather than an edit in passing.
SECURITY_PREAMBLE = _SECURITY_PREAMBLE.text


class AgentContext:
    """Everything a node needs to do its job, assembled once per run.

    Bundling identity, broker and audit sink together means an agent cannot
    accidentally act as a different principal: it uses the identity it was
    constructed with.
    """

    def __init__(
        self,
        role: AgentRole,
        broker: ToolBroker,
        audit: AuditLogger,
        thread_id: str,
    ) -> None:
        self.role = role
        self.identity: AgentIdentity = get_identity(role)
        self.broker = broker
        self.audit = audit
        self.thread_id = thread_id

    # --- Auditing ---------------------------------------------------------
    def log(
        self,
        action: AuditAction,
        summary: str,
        details: dict[str, Any] | None = None,
        *,
        success: bool = True,
        duration_ms: float | None = None,
    ) -> AuditEvent:
        return self.audit.record(
            thread_id=self.thread_id,
            actor=self.role,
            action=action,
            summary=summary,
            details=details or {},
            success=success,
            duration_ms=duration_ms,
        )

    # --- Tools ------------------------------------------------------------
    def call_tool(self, tool_name: str, **arguments: Any) -> Any:
        """Invoke a tool through the broker as this agent's principal.

        Returns the full :class:`~src.tools.base.ToolResult` so callers can see
        denials, injection flags and audit events rather than just data.
        """
        return self.broker.invoke(
            tool_name,
            arguments,
            principal=self.role,
            thread_id=self.thread_id,
        )

    def tool_budget_remaining(self) -> int:
        used = self.broker.calls_used(self.thread_id)
        return max(0, min(self.identity.max_tool_calls, self.broker.max_calls_per_run - used))


def contain_alert(alert: SecurityAlert) -> UntrustedContent:
    """Sanitise an alert into a labelled, flagged :class:`UntrustedContent`.

    The alert is attacker-influenced in exactly the same way a log line is --
    an adversary who can trigger a detection often controls the filename,
    username or command line that ends up in it.  So it gets the same
    containment treatment.

    Callers get the whole :class:`UntrustedContent` rather than just the
    rendered block because ``injection_flags`` is security-relevant state: it
    has to reach the policy engine (via ``TriageResult``), not merely decorate
    a prompt.  Discarding it here is what previously left alert-borne injection
    invisible to the approval gate.
    """
    assets = "\n".join(
        f"  - {asset.name} ({asset.asset_type}, criticality={asset.criticality}"
        f"{', ip=' + asset.ip_address if asset.ip_address else ''})"
        for asset in alert.assets
    ) or "  (none recorded)"

    indicators = "\n".join(
        f"  - {indicator.indicator_type.value}: {indicator.value}"
        f"{' -- ' + indicator.context if indicator.context else ''}"
        for indicator in alert.indicators
    ) or "  (none recorded)"

    raw_fields = "\n".join(f"  {key}: {value}" for key, value in list(alert.raw_event.items())[:15])

    body = (
        f"Alert ID: {alert.alert_id}\n"
        f"Source: {alert.source}\n"
        f"Detected at: {alert.detected_at.isoformat()}\n"
        f"Reported severity: {alert.reported_severity.value}\n"
        f"Title: {alert.title}\n\n"
        f"Description:\n{alert.description}\n\n"
        f"Assets:\n{assets}\n\n"
        f"Indicators:\n{indicators}\n\n"
        f"Raw detection fields:\n{raw_fields or '  (none)'}"
    )

    return sanitize_untrusted(body, source=f"alert:{alert.alert_id}")


def render_alert_for_prompt(alert: SecurityAlert) -> str:
    """Render an alert as a labelled untrusted-data block for a prompt.

    Thin wrapper over :func:`contain_alert` for callers that only need the
    prompt text.  Anything that must *act* on the alert's injection flags
    should call :func:`contain_alert` directly.
    """
    return contain_alert(alert).as_prompt_block(label=f"alert:{alert.alert_id}")


def alert_summary_text(alert: SecurityAlert) -> str:
    """Flat text used as input to the deterministic classifier tool."""
    parts = [
        alert.title,
        alert.description,
        f"reported severity {alert.reported_severity.value}",
        " ".join(f"{asset.name} {asset.asset_type} {asset.criticality}" for asset in alert.assets),
        " ".join(indicator.value + " " + (indicator.context or "") for indicator in alert.indicators),
        " ".join(f"{key}={value}" for key, value in alert.raw_event.items()),
    ]
    return " \n".join(part for part in parts if part)
