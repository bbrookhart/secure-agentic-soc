"""Human-in-the-loop policy engine.

The policy engine is deliberately **deterministic and LLM-free**.  Whether a
human must approve an incident is far too important to delegate to a model that
can be talked out of it by the very content it is analysing.  Agents produce
*facts* (severity, confidence, proposed actions); this module applies *rules*.

Rules are ordered by precedence.  DENY beats REQUIRE_APPROVAL beats ALLOW, and
the first matching rule of the winning effect is reported as the rationale.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from pydantic import BaseModel, ConfigDict, Field

from src.enums import ActionRisk, PolicyEffect, Severity, at_least


class PolicyInput(BaseModel):
    """Everything the policy engine is allowed to consider.

    Note the absence of free-text fields from the alert or from tool output:
    policy decisions are made on structured, validated values only, so injected
    text in a log line cannot influence the gate.
    """

    model_config = ConfigDict(frozen=True)

    severity: Severity = Severity.INFO
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    asset_is_critical: bool = False
    proposed_action_risks: tuple[ActionRisk, ...] = ()
    tool_calls_used: int = 0
    max_tool_calls: int = 40
    untrusted_content_flagged: bool = False
    #: Counts drawn from prior investigations touching the same entities.
    #: Counts only, never titles or notes -- see the class docstring. History
    #: is wired to *escalate*; nothing here can talk the gate down, because a
    #: suppressing rule would be trainable by anyone able to generate
    #: benign-looking alerts.
    related_confirmed_malicious: int = Field(default=0, ge=0)
    #: True when the operator has narrowed autonomy system-wide.
    autonomy_suspended: bool = False


class PolicyDecision(BaseModel):
    """Outcome of a policy evaluation, recorded verbatim in the audit log."""

    model_config = ConfigDict(frozen=True)

    effect: PolicyEffect
    rule_id: str
    reason: str
    matched_rules: tuple[str, ...] = ()

    @property
    def requires_approval(self) -> bool:
        return self.effect is PolicyEffect.REQUIRE_APPROVAL

    @property
    def denied(self) -> bool:
        return self.effect is PolicyEffect.DENY


class PolicyRule(BaseModel):
    """A single named rule."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    rule_id: str
    effect: PolicyEffect
    reason: str
    predicate: Callable[[PolicyInput], bool]


class ApprovalPolicy:
    """Evaluates :class:`PolicyInput` against an ordered rule set."""

    def __init__(
        self,
        *,
        severity_threshold: Severity = Severity.HIGH,
        min_confidence: float = 0.55,
        rules: Sequence[PolicyRule] | None = None,
    ) -> None:
        self.severity_threshold = severity_threshold
        self.min_confidence = min_confidence
        self._rules: list[PolicyRule] = list(rules) if rules is not None else self._default_rules()

    def _default_rules(self) -> list[PolicyRule]:
        threshold = self.severity_threshold
        min_confidence = self.min_confidence

        return [
            # --- DENY: hard stops -------------------------------------------------
            PolicyRule(
                rule_id="DENY-001-destructive-action",
                effect=PolicyEffect.DENY,
                reason=(
                    "A destructive action was proposed. This system operates in "
                    "proposal-only mode and never executes destructive changes."
                ),
                predicate=lambda i: ActionRisk.DESTRUCTIVE in i.proposed_action_risks,
            ),
            PolicyRule(
                rule_id="DENY-002-tool-budget-exhausted",
                effect=PolicyEffect.DENY,
                reason="Per-run tool call budget exhausted; halting to bound runaway loops.",
                predicate=lambda i: i.tool_calls_used >= i.max_tool_calls,
            ),
            # --- REQUIRE_APPROVAL: human gates ------------------------------------
            # First, because it is the most specific reason to stop: an
            # operator has deliberately taken autonomy away, and an analyst
            # should be told that rather than a severity threshold.
            PolicyRule(
                rule_id="HITL-000-autonomy-suspended",
                effect=PolicyEffect.REQUIRE_APPROVAL,
                reason=(
                    "Autonomous completion is suspended system-wide; every run requires "
                    "human review until the operating mode returns to normal."
                ),
                predicate=lambda i: i.autonomy_suspended,
            ),
            PolicyRule(
                rule_id="HITL-001-high-severity",
                effect=PolicyEffect.REQUIRE_APPROVAL,
                reason=f"Severity is at or above the '{threshold.value}' approval threshold.",
                predicate=lambda i: at_least(i.severity, threshold),
            ),
            PolicyRule(
                rule_id="HITL-002-disruptive-proposal",
                effect=PolicyEffect.REQUIRE_APPROVAL,
                reason="A disruptive containment action was drafted and needs analyst sign-off.",
                predicate=lambda i: ActionRisk.DISRUPTIVE in i.proposed_action_risks,
            ),
            PolicyRule(
                rule_id="HITL-003-critical-asset",
                effect=PolicyEffect.REQUIRE_APPROVAL,
                reason="Alert involves an asset tagged business-critical.",
                predicate=lambda i: i.asset_is_critical,
            ),
            PolicyRule(
                rule_id="HITL-004-low-confidence",
                effect=PolicyEffect.REQUIRE_APPROVAL,
                reason=(
                    f"Triage confidence is below {min_confidence:.2f}; a human should "
                    "confirm rather than let a low-confidence verdict stand."
                ),
                predicate=lambda i: i.confidence < min_confidence,
            ),
            PolicyRule(
                rule_id="HITL-005-untrusted-content",
                effect=PolicyEffect.REQUIRE_APPROVAL,
                reason=(
                    "Suspected prompt-injection content was detected in tool or log "
                    "output; agent conclusions may be unreliable."
                ),
                predicate=lambda i: i.untrusted_content_flagged,
            ),
            # Last of the approval rules: it is the least specific reason to
            # stop, so when it fires alongside another the other is the one
            # worth showing the analyst.
            PolicyRule(
                rule_id="HITL-006-recent-confirmed-incident",
                effect=PolicyEffect.REQUIRE_APPROVAL,
                reason=(
                    "An asset or indicator in this alert was part of a recently confirmed "
                    "incident. A second alert on the same entity is not an independent event."
                ),
                predicate=lambda i: i.related_confirmed_malicious > 0,
            ),
        ]

    def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        """Apply all rules and return the highest-precedence decision."""
        matched = [rule for rule in self._rules if rule.predicate(policy_input)]

        for effect in (PolicyEffect.DENY, PolicyEffect.REQUIRE_APPROVAL):
            winners = [rule for rule in matched if rule.effect is effect]
            if winners:
                primary = winners[0]
                return PolicyDecision(
                    effect=effect,
                    rule_id=primary.rule_id,
                    reason=primary.reason,
                    matched_rules=tuple(rule.rule_id for rule in matched),
                )

        return PolicyDecision(
            effect=PolicyEffect.ALLOW,
            rule_id="ALLOW-000-default",
            reason="No approval rule matched; autonomous completion permitted.",
            matched_rules=tuple(rule.rule_id for rule in matched),
        )

    def describe(self) -> list[dict[str, str]]:
        """Rule set as data, for documentation and the analyst UI."""
        return [
            {"rule_id": rule.rule_id, "effect": rule.effect.value, "reason": rule.reason}
            for rule in self._rules
        ]


def default_policy() -> ApprovalPolicy:
    """Build the policy configured by application settings."""
    from src.config import get_settings

    settings = get_settings()
    return ApprovalPolicy(
        severity_threshold=settings.hitl_severity_threshold,
        min_confidence=settings.hitl_min_confidence,
    )
