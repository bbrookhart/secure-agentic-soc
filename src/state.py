"""Strongly-typed graph state.

Everything that flows between agents is a validated Pydantic model.  This is a
security control as much as an engineering one:

* agents cannot smuggle arbitrary structures into shared state -- an LLM that
  returns something unexpected fails validation at the boundary rather than
  corrupting downstream reasoning;
* the original alert is **frozen and fingerprinted**, so an agent (or an
  injected instruction) cannot rewrite the evidence it was asked to analyse;
* phase transitions are explicitly validated, so "report before triage" or
  "finish while an approval is pending" are unrepresentable rather than merely
  discouraged.
"""

from __future__ import annotations

import hashlib
import json
import operator
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Any

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.enums import (
    ActionRisk,
    AgentRole,
    AlertCategory,
    ApprovalStatus,
    IndicatorType,
    Severity,
    Verdict,
)
from src.security.audit import AuditEvent


def _utc_now() -> datetime:
    return datetime.now(UTC)


class InvalidStateTransition(ValueError):
    """Raised when a node attempts a phase transition the workflow forbids."""


# ---------------------------------------------------------------------------
# Workflow phases
# ---------------------------------------------------------------------------
class Phase(str, Enum):
    """Lifecycle phases of a single alert investigation."""

    INGESTED = "ingested"
    TRIAGING = "triaging"
    TRIAGED = "triaged"
    ENRICHING = "enriching"
    ENRICHED = "enriched"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    REPORTING = "reporting"
    COMPLETE = "complete"
    HALTED = "halted"


#: Legal phase transitions.  Anything not listed here is a bug, not a feature.
ALLOWED_TRANSITIONS: dict[Phase, frozenset[Phase]] = {
    Phase.INGESTED: frozenset({Phase.TRIAGING, Phase.HALTED}),
    Phase.TRIAGING: frozenset({Phase.TRIAGED, Phase.HALTED}),
    Phase.TRIAGED: frozenset({Phase.ENRICHING, Phase.AWAITING_APPROVAL, Phase.REPORTING, Phase.HALTED}),
    Phase.ENRICHING: frozenset({Phase.ENRICHED, Phase.HALTED}),
    Phase.ENRICHED: frozenset({Phase.AWAITING_APPROVAL, Phase.REPORTING, Phase.HALTED}),
    Phase.AWAITING_APPROVAL: frozenset({Phase.APPROVED, Phase.REJECTED, Phase.HALTED}),
    Phase.APPROVED: frozenset({Phase.REPORTING, Phase.ENRICHING, Phase.HALTED}),
    Phase.REJECTED: frozenset({Phase.REPORTING, Phase.HALTED}),
    Phase.REPORTING: frozenset({Phase.COMPLETE, Phase.HALTED}),
    Phase.COMPLETE: frozenset(),
    Phase.HALTED: frozenset(),
}


def validate_transition(current: Phase, target: Phase) -> None:
    """Raise :class:`InvalidStateTransition` if ``current -> target`` is illegal."""
    if target == current:
        return
    allowed = ALLOWED_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise InvalidStateTransition(
            f"illegal phase transition {current.value} -> {target.value}; "
            f"allowed: {sorted(p.value for p in allowed) or 'none (terminal)'}"
        )


# ---------------------------------------------------------------------------
# Alert input models (immutable)
# ---------------------------------------------------------------------------
class Asset(BaseModel):
    """A host, account or service referenced by an alert."""

    model_config = ConfigDict(frozen=True)

    name: str
    asset_type: str = Field(default="host", description="host | user | service | network")
    ip_address: str | None = None
    criticality: str = Field(default="standard", description="standard | important | critical")
    owner: str | None = None

    @property
    def is_critical(self) -> bool:
        return self.criticality.lower() == "critical"


class Indicator(BaseModel):
    """An indicator of compromise extracted from an alert."""

    model_config = ConfigDict(frozen=True)

    value: str = Field(min_length=1, max_length=2048)
    indicator_type: IndicatorType
    context: str | None = Field(default=None, max_length=512)


class SecurityAlert(BaseModel):
    """The immutable alert under investigation.

    ``frozen=True`` plus :meth:`fingerprint` means the evidence cannot be
    altered mid-run; :class:`SOCState` re-checks the fingerprint on every
    update so silent substitution is detected.
    """

    model_config = ConfigDict(frozen=True)

    alert_id: str = Field(min_length=1, max_length=128)
    source: str = Field(description="Detection source, e.g. 'EDR', 'SIEM', 'Email Gateway'.")
    title: str = Field(min_length=1, max_length=512)
    description: str = Field(default="", max_length=8192)
    detected_at: datetime = Field(default_factory=_utc_now)
    reported_severity: Severity = Severity.MEDIUM
    assets: tuple[Asset, ...] = ()
    indicators: tuple[Indicator, ...] = ()
    raw_event: dict[str, Any] = Field(
        default_factory=dict,
        description="Original detection payload, retained verbatim for evidence.",
    )

    @field_validator("assets", "indicators", mode="before")
    @classmethod
    def _coerce_sequence(cls, value: Any) -> Any:
        # JSON gives lists; the model wants tuples for immutability.
        return tuple(value) if isinstance(value, list) else value

    def fingerprint(self) -> str:
        """Stable SHA-256 over the alert's canonical JSON."""
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def has_critical_asset(self) -> bool:
        return any(asset.is_critical for asset in self.assets)

    def summary_line(self) -> str:
        assets = ", ".join(asset.name for asset in self.assets) or "unknown"
        return f"[{self.source}] {self.title} (reported={self.reported_severity.value}, assets={assets})"


# ---------------------------------------------------------------------------
# Agent outputs
# ---------------------------------------------------------------------------
class MitreTechnique(BaseModel):
    """A MITRE ATT&CK technique mapping."""

    model_config = ConfigDict(frozen=True)

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactic: str
    description: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    rationale: str = ""

    @property
    def url(self) -> str:
        base, _, sub = self.technique_id.partition(".")
        path = f"{base}/{sub}" if sub else base
        return f"https://attack.mitre.org/techniques/{path}/"


class TriageResult(BaseModel):
    """Structured output of the triage agent."""

    model_config = ConfigDict(frozen=True)

    severity: Severity
    category: AlertCategory
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1, max_length=4000)
    key_observations: tuple[str, ...] = ()
    suggested_techniques: tuple[str, ...] = Field(
        default=(),
        description="Candidate ATT&CK technique IDs for the hunter to verify.",
    )
    recommended_next_step: str = ""
    # Raised when the alert's own text tripped the injection heuristics.  The
    # alert is attacker-influenced in exactly the way a log line is, so a flag
    # here must reach the policy engine even on runs that skip enrichment.
    untrusted_content_flagged: bool = False
    injection_flags: tuple[str, ...] = ()
    produced_by: AgentRole = AgentRole.TRIAGE
    produced_at: datetime = Field(default_factory=_utc_now)
    used_llm: bool = True

    @field_validator("key_observations", "suggested_techniques", "injection_flags", mode="before")
    @classmethod
    def _coerce_sequence(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class IOCEnrichment(BaseModel):
    """Reputation and context for a single indicator."""

    model_config = ConfigDict(frozen=True)

    indicator: str
    indicator_type: IndicatorType
    known_malicious: bool = False
    reputation_score: int = Field(default=0, ge=0, le=100, description="0 = benign, 100 = confirmed bad.")
    threat_names: tuple[str, ...] = ()
    first_seen: str | None = None
    last_seen: str | None = None
    sources: tuple[str, ...] = ()
    notes: str = ""

    @field_validator("threat_names", "sources", mode="before")
    @classmethod
    def _coerce_sequence(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class LogSearchHit(BaseModel):
    """A semantic-search hit from the historical log corpus."""

    model_config = ConfigDict(frozen=True)

    log_id: str
    timestamp: str
    host: str = ""
    message: str
    relevance: float = Field(ge=0.0, le=1.0)
    source: str = "log_corpus"


class ProposedAction(BaseModel):
    """A response action **draft**.

    Nothing in this system executes actions.  A ``ProposedAction`` is inert
    data: it exists to be reviewed, approved and then carried out by a human in
    whatever system actually holds that authority.
    """

    model_config = ConfigDict(frozen=True)

    action_id: str = Field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:8]}")
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(max_length=2000)
    risk: ActionRisk
    target: str = Field(description="Asset or indicator the action would affect.")
    rationale: str = ""
    # Constant by construction -- kept explicit so the invariant is visible in
    # serialised state, reports and the UI.
    execution_mode: str = Field(default="proposal_only", frozen=True)
    proposed_by: AgentRole = AgentRole.ENRICHMENT
    proposed_at: datetime = Field(default_factory=_utc_now)

    @field_validator("execution_mode")
    @classmethod
    def _proposal_only(cls, value: str) -> str:
        if value != "proposal_only":
            raise ValueError("execution_mode must remain 'proposal_only'")
        return value


class EnrichmentResults(BaseModel):
    """Structured output of the enrichment / hunter agent."""

    model_config = ConfigDict(frozen=True)

    ioc_enrichments: tuple[IOCEnrichment, ...] = ()
    mitre_techniques: tuple[MitreTechnique, ...] = ()
    log_hits: tuple[LogSearchHit, ...] = ()
    proposed_actions: tuple[ProposedAction, ...] = ()
    hunt_summary: str = ""
    pivot_suggestions: tuple[str, ...] = ()
    # Raised when any tool output tripped the injection heuristics.
    untrusted_content_flagged: bool = False
    injection_flags: tuple[str, ...] = ()
    produced_by: AgentRole = AgentRole.ENRICHMENT
    produced_at: datetime = Field(default_factory=_utc_now)
    used_llm: bool = True

    @field_validator(
        "ioc_enrichments",
        "mitre_techniques",
        "log_hits",
        "proposed_actions",
        "pivot_suggestions",
        "injection_flags",
        mode="before",
    )
    @classmethod
    def _coerce_sequence(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @property
    def malicious_indicator_count(self) -> int:
        return sum(1 for e in self.ioc_enrichments if e.known_malicious)

    @property
    def max_proposed_risk(self) -> ActionRisk:
        order = [ActionRisk.READ_ONLY, ActionRisk.LOW_IMPACT, ActionRisk.DISRUPTIVE, ActionRisk.DESTRUCTIVE]
        risks = [a.risk for a in self.proposed_actions]
        return max(risks, key=order.index) if risks else ActionRisk.READ_ONLY


class TimelineEntry(BaseModel):
    """One row of the incident timeline."""

    model_config = ConfigDict(frozen=True)

    timestamp: str
    description: str
    source: str = ""


class IncidentReport(BaseModel):
    """Final analyst-facing incident report."""

    model_config = ConfigDict(frozen=True)

    title: str
    executive_summary: str = Field(min_length=1, max_length=4000)
    verdict: Verdict
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    timeline: tuple[TimelineEntry, ...] = ()
    key_findings: tuple[str, ...] = ()
    mitre_techniques: tuple[MitreTechnique, ...] = ()
    recommended_actions: tuple[str, ...] = ()
    proposed_actions: tuple[ProposedAction, ...] = ()
    analyst_notes: str = ""
    caveats: tuple[str, ...] = ()
    produced_by: AgentRole = AgentRole.REPORTER
    produced_at: datetime = Field(default_factory=_utc_now)
    used_llm: bool = True

    @field_validator(
        "timeline", "key_findings", "mitre_techniques", "recommended_actions",
        "proposed_actions", "caveats", mode="before",
    )
    @classmethod
    def _coerce_sequence(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    def to_markdown(self) -> str:
        """Render the report as Markdown for the CLI and the dashboard."""
        lines: list[str] = [
            f"# {self.title}",
            "",
            f"**Verdict:** {self.verdict.value.replace('_', ' ').title()}  ",
            f"**Severity:** {self.severity.value.upper()}  ",
            f"**Confidence:** {self.confidence:.0%}  ",
            f"**Generated:** {self.produced_at.isoformat(timespec='seconds')}",
            "",
            "## Executive Summary",
            "",
            self.executive_summary,
            "",
        ]

        if self.timeline:
            lines += ["## Timeline", "", "| Time | Event | Source |", "|---|---|---|"]
            lines += [f"| {e.timestamp} | {e.description} | {e.source} |" for e in self.timeline]
            lines.append("")

        if self.key_findings:
            lines += ["## Key Findings", ""]
            lines += [f"{i}. {finding}" for i, finding in enumerate(self.key_findings, 1)]
            lines.append("")

        if self.mitre_techniques:
            lines += ["## MITRE ATT&CK Mapping", "", "| Technique | Name | Tactic | Confidence |", "|---|---|---|---|"]
            lines += [
                f"| [{t.technique_id}]({t.url}) | {t.name} | {t.tactic} | {t.confidence:.0%} |"
                for t in self.mitre_techniques
            ]
            lines.append("")

        if self.recommended_actions:
            lines += ["## Recommended Next Steps", ""]
            lines += [f"- {action}" for action in self.recommended_actions]
            lines.append("")

        if self.proposed_actions:
            lines += [
                "## Proposed Containment Actions (PROPOSAL ONLY -- NOT EXECUTED)",
                "",
                "| Action | Target | Risk | Status |",
                "|---|---|---|---|",
            ]
            lines += [
                f"| {a.title} | {a.target} | {a.risk.value} | {a.execution_mode} |"
                for a in self.proposed_actions
            ]
            lines.append("")

        if self.caveats:
            lines += ["## Caveats and Limitations", ""]
            lines += [f"- {caveat}" for caveat in self.caveats]
            lines.append("")

        if self.analyst_notes:
            lines += ["## Analyst Notes", "", self.analyst_notes, ""]

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Human-in-the-loop models
# ---------------------------------------------------------------------------
class ApprovalRequest(BaseModel):
    """The payload surfaced to a human when the graph interrupts."""

    model_config = ConfigDict(frozen=True)

    request_id: str = Field(default_factory=lambda: f"APR-{uuid.uuid4().hex[:8]}")
    rule_id: str
    reason: str
    severity: Severity
    alert_title: str
    summary: str
    proposed_actions: tuple[ProposedAction, ...] = ()
    requested_at: datetime = Field(default_factory=_utc_now)

    @field_validator("proposed_actions", mode="before")
    @classmethod
    def _coerce_sequence(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class ApprovalDecision(BaseModel):
    """A human analyst's response to an :class:`ApprovalRequest`."""

    model_config = ConfigDict(frozen=True)

    request_id: str = ""
    approved: bool
    decided_by: str = Field(default="analyst", max_length=128)
    # How ``decided_by`` was established. An approval trail whose "who" is
    # self-asserted answers nothing, so the provenance of the identity is
    # recorded alongside it rather than left implicit.
    identity_source: str = Field(default="unauthenticated", max_length=64)
    # Roles the proxy asserted for this approver. Carried on the decision
    # because only the console can verify them -- a CLI operator naming a
    # role would be self-granting authority.
    roles: tuple[str, ...] = ()
    notes: str = Field(default="", max_length=2000)
    approved_action_ids: tuple[str, ...] = ()
    decided_at: datetime = Field(default_factory=_utc_now)

    @field_validator("approved_action_ids", "roles", mode="before")
    @classmethod
    def _coerce_sequence(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class RunMetadata(BaseModel):
    """Provenance for one investigation run."""

    thread_id: str
    started_at: datetime = Field(default_factory=_utc_now)
    completed_at: datetime | None = None
    model_name: str = "unknown"
    offline_mode: bool = False
    app_version: str = "0.1.0"
    alert_fingerprint: str = ""
    # Who started this investigation. Recorded so the approval gate can
    # refuse to let the same person sign off their own run (AC-5).
    initiated_by: str = ""

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()


# ---------------------------------------------------------------------------
# The graph state
# ---------------------------------------------------------------------------
class SOCState(BaseModel):
    """Shared state for the LangGraph supervisor workflow.

    Fields annotated with a reducer (``operator.add`` / ``add_messages``) are
    accumulated across nodes; everything else is last-write-wins.
    """

    model_config = ConfigDict(validate_assignment=True)

    # --- Immutable input --------------------------------------------------
    alert: SecurityAlert

    # --- Reasoning history ------------------------------------------------
    messages: Annotated[list[AnyMessage], add_messages] = Field(default_factory=list)
    audit_log: Annotated[list[AuditEvent], operator.add] = Field(default_factory=list)

    # --- Agent outputs ----------------------------------------------------
    triage_result: TriageResult | None = None
    enrichment_results: EnrichmentResults | None = None
    final_report: IncidentReport | None = None

    # --- Control flow -----------------------------------------------------
    phase: Phase = Phase.INGESTED
    next_agent: str | None = None
    completed_agents: Annotated[list[str], operator.add] = Field(default_factory=list)
    supervisor_turns: int = Field(default=0, ge=0)
    tool_calls_used: int = Field(default=0, ge=0)

    # --- Cross-run context ------------------------------------------------
    # Counts drawn from prior investigations touching the same entities.
    # Structured values only: these reach the policy engine, which holds no
    # free-text fields precisely so a poisoned history cannot become an
    # injection channel into the one component that is not persuadable.
    related_confirmed_malicious: int = Field(default=0, ge=0)
    related_false_positives: int = Field(default=0, ge=0)
    related_run_count: int = Field(default=0, ge=0)
    case_id: str = ""
    duplicate_of: str = ""

    # --- Human in the loop ------------------------------------------------
    requires_approval: bool = False
    approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED
    approval_reason: str = ""
    approval_rule_id: str = ""
    approval_request: ApprovalRequest | None = None
    approval_decision: ApprovalDecision | None = None
    # Every approval recorded so far. Usually one; two-person integrity for
    # disruptive actions on critical assets needs the gate to reopen until a
    # second, distinct approver has signed.
    recorded_approvals: tuple[ApprovalDecision, ...] = ()
    # Refused approval attempts. A caller that keeps resubmitting the same
    # unauthorised answer would otherwise spin the gate until the turn limit.
    authorization_denials: int = Field(default=0, ge=0)

    # --- Diagnostics ------------------------------------------------------
    errors: Annotated[list[str], operator.add] = Field(default_factory=list)
    run: RunMetadata

    # --- Invariants -------------------------------------------------------
    @model_validator(mode="after")
    def _check_invariants(self) -> SOCState:
        # 1. The evidence must not change under us.
        if self.run.alert_fingerprint and self.run.alert_fingerprint != self.alert.fingerprint():
            raise ValueError(
                "alert fingerprint mismatch: the immutable alert was modified during the run"
            )

        # 2. A pending approval must block completion.
        if self.approval_status is ApprovalStatus.PENDING and self.phase is Phase.COMPLETE:
            raise ValueError("cannot complete a run while an approval is still pending")

        # 3. Approval bookkeeping must be coherent.
        if self.approval_status in {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}:
            if self.approval_decision is None:
                raise ValueError(
                    f"approval_status is '{self.approval_status.value}' but no "
                    "ApprovalDecision is recorded"
                )
            if self.approval_decision.approved != (self.approval_status is ApprovalStatus.APPROVED):
                raise ValueError("approval_status contradicts the recorded ApprovalDecision")

        # 4. A report must rest on completed triage.
        if self.final_report is not None and self.triage_result is None:
            raise ValueError("final_report produced without a triage_result")

        return self

    # --- Convenience ------------------------------------------------------
    @property
    def thread_id(self) -> str:
        return self.run.thread_id

    @property
    def is_terminal(self) -> bool:
        return self.phase in {Phase.COMPLETE, Phase.HALTED}

    @property
    def asset_is_critical(self) -> bool:
        return self.alert.has_critical_asset

    def audit_tail(self, limit: int = 20) -> list[AuditEvent]:
        return self.audit_log[-limit:]

    @classmethod
    def bootstrap(
        cls,
        alert: SecurityAlert,
        *,
        thread_id: str | None = None,
        model_name: str = "unknown",
        offline_mode: bool = False,
        initiated_by: str = "",
    ) -> SOCState:
        """Create the initial state for a new investigation."""
        resolved_thread = thread_id or f"run-{uuid.uuid4().hex[:12]}"
        return cls(
            alert=alert,
            run=RunMetadata(
                thread_id=resolved_thread,
                model_name=model_name,
                offline_mode=offline_mode,
                alert_fingerprint=alert.fingerprint(),
                initiated_by=initiated_by,
            ),
        )
