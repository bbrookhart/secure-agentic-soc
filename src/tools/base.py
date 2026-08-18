"""Tool contract and the guarded invocation broker.

**No agent ever calls a tool function directly.**  Every invocation goes
through :class:`ToolBroker`, which applies the same six controls in the same
order, every time:

1. **Authorisation** -- the calling principal must hold the tool in its
   identity (`security.identity`).  Least privilege is enforced in code, not in
   a prompt, so a persuaded or injected agent gains nothing.
2. **Rate limiting** -- per-(principal, tool) token bucket bounds runaway loops.
3. **Budget** -- a per-run ceiling on total tool calls.
4. **Input validation** -- arguments are parsed by the tool's Pydantic schema.
   Anything malformed is rejected before the handler sees it.
5. **Output containment** -- results are treated as untrusted: sanitised,
   injection-scanned, secret-redacted and truncated before they can reach a
   prompt.
6. **Audit** -- the call, its arguments, its outcome and its timing are all
   recorded on the tamper-evident audit chain.

Centralising this means a new tool inherits every control by construction; the
only way to write an unguarded tool is to bypass the broker deliberately.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from src.enums import ActionRisk, AgentRole, AuditAction
from src.security.audit import AuditEvent, AuditLogger, get_audit_logger
from src.security.identity import AuthorizationError, get_identity
from src.security.ratelimit import RateLimiter, RateLimitExceeded
from src.security.sanitizer import sanitize_obj


class ToolExecutionError(RuntimeError):
    """Raised when a tool handler fails."""


class ToolBudgetExceeded(RuntimeError):
    """Raised when a run exhausts its total tool-call budget."""


@dataclass(frozen=True)
class SOCTool:
    """A narrow, purpose-built capability.

    Deliberately *not* a general-purpose interface: there is no shell tool, no
    arbitrary HTTP tool, and no code execution tool anywhere in this system.
    Every tool answers one question or drafts one proposal.
    """

    name: str
    description: str
    input_model: type[BaseModel]
    handler: Callable[[Any], Any]
    risk: ActionRisk = ActionRisk.READ_ONLY
    #: Whether the handler's output is attacker-influenceable.  Almost always
    #: True -- log lines, intel records and alert text all qualify.
    returns_untrusted: bool = True

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "risk": self.risk.value,
            "input_schema": self.input_model.model_json_schema(),
        }


class ToolResult(BaseModel):
    """Outcome of a guarded tool invocation."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    tool: str
    ok: bool
    data: Any = None
    error: str | None = None
    duration_ms: float = 0.0
    injection_flags: tuple[str, ...] = ()
    truncated: bool = False
    audit_events: list[AuditEvent] = Field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return bool(self.injection_flags)


@dataclass
class ToolBroker:
    """Guarded gateway between agents and tools."""

    registry: dict[str, SOCTool]
    audit: AuditLogger = field(default_factory=get_audit_logger)
    rate_limiter: RateLimiter | None = None
    max_calls_per_run: int = 40
    #: Per-thread tally of tool calls, enforcing the run budget.
    _calls_used: dict[str, int] = field(default_factory=dict)
    #: Guards ``_calls_used``; several runs may be in flight at once.
    _budget_lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.rate_limiter is None:
            from src.config import get_settings

            self.rate_limiter = RateLimiter(get_settings().tool_rate_limit_per_minute)

    # --- Introspection ---------------------------------------------------
    def available_tools(self, principal: AgentRole) -> list[SOCTool]:
        """Tools this principal is permitted to see and call."""
        identity = get_identity(principal)
        return [tool for name, tool in self.registry.items() if identity.can_use(name)]

    def calls_used(self, thread_id: str) -> int:
        with self._budget_lock:
            return self._calls_used.get(thread_id, 0)

    def seed_budget(self, thread_id: str, used: int) -> None:
        """Restore a run's spend from checkpointed state.

        The tally lives in this process, but a run does not -- it can suspend at
        the approval interrupt and resume in a different process entirely.
        Without seeding, the resumed half would start from zero and the run
        could spend its budget over again, which is also how the persisted
        ``tool_calls_used`` was previously overwritten with 0 on resume.
        Only ever moves the tally forward.
        """
        if used <= 0:
            return
        with self._budget_lock:
            self._calls_used[thread_id] = max(self._calls_used.get(thread_id, 0), used)

    def reset_budget(self, thread_id: str) -> None:
        with self._budget_lock:
            self._calls_used.pop(thread_id, None)

    # --- Invocation ------------------------------------------------------
    def invoke(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        principal: AgentRole,
        thread_id: str,
    ) -> ToolResult:
        """Run a tool under the full control stack.

        Never raises for an expected denial: authorisation failures, rate
        limits, budget exhaustion and validation errors all come back as a
        failed :class:`ToolResult` so the calling agent can adapt (and so the
        denial is recorded rather than crashing the run).
        """
        events: list[AuditEvent] = []
        started = time.perf_counter()

        def _fail(action: AuditAction, message: str, **details: Any) -> ToolResult:
            events.append(
                self.audit.record(
                    thread_id=thread_id,
                    actor=principal,
                    action=action,
                    summary=f"{tool_name}: {message}",
                    details={"tool": tool_name, **details},
                    success=False,
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            )
            return ToolResult(
                tool=tool_name,
                ok=False,
                error=message,
                duration_ms=(time.perf_counter() - started) * 1000,
                audit_events=events,
            )

        # --- 1. Does the tool exist? -------------------------------------
        tool = self.registry.get(tool_name)
        if tool is None:
            return _fail(AuditAction.TOOL_DENIED, f"unknown tool '{tool_name}'")

        # --- 2. Authorisation --------------------------------------------
        try:
            identity = get_identity(principal)
            identity.authorize(tool_name)
        except AuthorizationError as exc:
            return _fail(
                AuditAction.TOOL_DENIED,
                str(exc),
                principal=principal.value,
                reason="least_privilege_violation",
            )

        # An agent may never invoke a tool whose risk exceeds its ceiling.
        risk_order = [ActionRisk.READ_ONLY, ActionRisk.LOW_IMPACT, ActionRisk.DISRUPTIVE, ActionRisk.DESTRUCTIVE]
        if risk_order.index(tool.risk) > risk_order.index(identity.max_action_risk):
            return _fail(
                AuditAction.TOOL_DENIED,
                f"tool risk '{tool.risk.value}' exceeds principal ceiling '{identity.max_action_risk.value}'",
                reason="risk_ceiling_violation",
            )

        # --- 3. Budgets and rate limits ----------------------------------
        used = self.calls_used(thread_id)
        if used >= self.max_calls_per_run:
            return _fail(
                AuditAction.RATE_LIMITED,
                f"run tool budget exhausted ({used}/{self.max_calls_per_run})",
                reason="run_budget_exhausted",
            )

        if self.rate_limiter is None:  # pragma: no cover - set in __post_init__
            raise RuntimeError("ToolBroker has no rate limiter configured")
        try:
            self.rate_limiter.check(principal.value, tool_name)
        except RateLimitExceeded as exc:
            return _fail(
                AuditAction.RATE_LIMITED,
                str(exc),
                retry_after_seconds=round(exc.retry_after, 2),
                reason="rate_limited",
            )

        # --- 4. Input validation -----------------------------------------
        try:
            validated = tool.input_model.model_validate(arguments or {})
        except ValidationError as exc:
            return _fail(
                AuditAction.TOOL_DENIED,
                f"invalid arguments: {exc.error_count()} validation error(s)",
                reason="schema_validation_failed",
                errors=[
                    {"field": ".".join(str(p) for p in err["loc"]), "problem": err["msg"]}
                    for err in exc.errors()[:5]
                ],
            )

        # --- 5. Claim budget, then log the invocation BEFORE running it --
        # The claim is re-checked under the lock: the earlier check was a fast
        # rejection, but with several runs in flight only an atomic
        # check-and-increment actually bounds the spend.  Charging happens here
        # rather than at the first check so a schema-rejected call costs
        # nothing.
        with self._budget_lock:
            used = self._calls_used.get(thread_id, 0)
            over_budget = used >= self.max_calls_per_run
            if not over_budget:
                self._calls_used[thread_id] = used + 1
        if over_budget:
            return _fail(
                AuditAction.RATE_LIMITED,
                f"run tool budget exhausted ({used}/{self.max_calls_per_run})",
                reason="run_budget_exhausted",
            )

        # Ordering matters: a handler that hangs or crashes the process still
        # leaves evidence that it was called.
        events.append(
            self.audit.record(
                thread_id=thread_id,
                actor=principal,
                action=AuditAction.TOOL_CALL,
                summary=f"invoke {tool_name}",
                details={
                    "tool": tool_name,
                    "risk": tool.risk.value,
                    "arguments": validated.model_dump(mode="json"),
                    "call_number": used + 1,
                },
            )
        )

        # --- 6. Execute ---------------------------------------------------
        try:
            raw = tool.handler(validated)
        except Exception as exc:  # noqa: BLE001 - a tool fault must not kill the run
            return _fail(
                AuditAction.ERROR,
                f"handler raised {type(exc).__name__}: {exc}",
                reason="handler_exception",
            )

        duration_ms = (time.perf_counter() - started) * 1000

        # --- 7. Contain the output ---------------------------------------
        flags: tuple[str, ...] = ()
        data = raw
        if tool.returns_untrusted:
            data, flags = sanitize_obj(raw, source=f"tool:{tool_name}")

        if flags:
            events.append(
                self.audit.record(
                    thread_id=thread_id,
                    actor=principal,
                    action=AuditAction.UNTRUSTED_CONTENT_FLAGGED,
                    summary=f"{tool_name} returned content matching injection heuristics",
                    details={"tool": tool_name, "flags": list(flags)},
                    success=False,
                )
            )

        events.append(
            self.audit.record(
                thread_id=thread_id,
                actor=principal,
                action=AuditAction.TOOL_RESULT,
                summary=f"{tool_name} completed",
                details={
                    "tool": tool_name,
                    "result_summary": _summarise(data),
                    "injection_flags": list(flags),
                },
                duration_ms=duration_ms,
            )
        )

        return ToolResult(
            tool=tool_name,
            ok=True,
            data=data,
            duration_ms=duration_ms,
            injection_flags=flags,
            audit_events=events,
        )


def _summarise(data: Any) -> str:
    """Compact description of a tool result for the audit log.

    The audit log records *what shape* came back, not the full payload -- the
    payload is already in state, and duplicating megabytes of log text into the
    audit trail would make it unreadable.
    """
    if isinstance(data, dict):
        return f"dict with keys: {sorted(data)[:8]}"
    if isinstance(data, list):
        return f"list of {len(data)} item(s)"
    text = str(data)
    return text[:200] + ("..." if len(text) > 200 else "")
