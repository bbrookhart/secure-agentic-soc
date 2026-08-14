"""Agent identity and least-privilege tool authorisation.

Every agent in this system is a *principal* with an explicit, statically
declared capability set.  Authorisation is enforced at the tool broker
(`src.tools.broker`), not inside the prompt: an agent that is talked into
calling a tool it does not hold is refused by code, not by persuasion.

This is the "separation between reasoning and authority" requirement -- the LLM
proposes, the broker disposes.  A prompt-injected agent gains nothing beyond
the capabilities its identity already had.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from src.enums import ActionRisk, AgentRole


class AuthorizationError(PermissionError):
    """Raised when a principal attempts an action outside its capability set."""


class UnknownPrincipalError(AuthorizationError):
    """Raised when an unregistered agent id is used."""


class AgentIdentity(BaseModel):
    """Immutable capability declaration for a single agent."""

    model_config = ConfigDict(frozen=True)

    role: AgentRole
    display_name: str
    purpose: str
    # Tool names this principal may invoke.  Empty = no tool access at all.
    allowed_tools: frozenset[str] = Field(default_factory=frozenset)
    # Highest action risk this principal may even *propose*.  Nothing above
    # READ_ONLY is ever executed; see src/tools/response.py.
    max_action_risk: ActionRisk = ActionRisk.READ_ONLY
    # Per-run ceiling on tool invocations, to bound runaway loops.
    max_tool_calls: int = 0
    # Only the supervisor may open a human-approval gate.
    may_request_approval: bool = False

    def can_use(self, tool_name: str) -> bool:
        return tool_name in self.allowed_tools

    def authorize(self, tool_name: str) -> None:
        """Raise :class:`AuthorizationError` unless this principal holds ``tool_name``."""
        if not self.can_use(tool_name):
            raise AuthorizationError(
                f"principal '{self.role.value}' is not authorized to call tool "
                f"'{tool_name}' (granted: {sorted(self.allowed_tools) or 'none'})"
            )


# ---------------------------------------------------------------------------
# The capability matrix.
#
# Read this table as the security posture of the whole system.  Note that:
#   * the supervisor holds NO tools -- it routes and enforces policy only, so a
#     compromised supervisor cannot itself touch data or propose actions;
#   * triage cannot reach the network-ish enrichment tools;
#   * only enrichment can draft containment proposals, and only as proposals;
#   * the reporter is write-only prose: it holds no tools whatsoever, so the
#     component most exposed to untrusted enrichment text has zero authority.
# ---------------------------------------------------------------------------
AGENT_IDENTITIES: dict[AgentRole, AgentIdentity] = {
    AgentRole.SUPERVISOR: AgentIdentity(
        role=AgentRole.SUPERVISOR,
        display_name="Supervisor",
        purpose="Route work between specialists and enforce human-in-the-loop policy.",
        allowed_tools=frozenset(),
        max_action_risk=ActionRisk.READ_ONLY,
        max_tool_calls=0,
        may_request_approval=True,
    ),
    AgentRole.TRIAGE: AgentIdentity(
        role=AgentRole.TRIAGE,
        display_name="Triage Analyst",
        purpose="Classify severity, category and initial risk for an incoming alert.",
        allowed_tools=frozenset({"classify_alert"}),
        max_action_risk=ActionRisk.READ_ONLY,
        max_tool_calls=4,
    ),
    AgentRole.ENRICHMENT: AgentIdentity(
        role=AgentRole.ENRICHMENT,
        display_name="Enrichment / Threat Hunter",
        purpose="Enrich indicators, map to MITRE ATT&CK, and search historical logs.",
        allowed_tools=frozenset(
            {"enrich_ioc", "lookup_mitre", "query_vector_logs", "draft_containment_proposal"}
        ),
        # May *draft* disruptive proposals; execution is impossible by design.
        max_action_risk=ActionRisk.DISRUPTIVE,
        max_tool_calls=24,
    ),
    AgentRole.REPORTER: AgentIdentity(
        role=AgentRole.REPORTER,
        display_name="Incident Reporter",
        purpose="Synthesise validated findings into an analyst-ready incident report.",
        allowed_tools=frozenset(),
        max_action_risk=ActionRisk.READ_ONLY,
        max_tool_calls=0,
    ),
    AgentRole.HUMAN_ANALYST: AgentIdentity(
        role=AgentRole.HUMAN_ANALYST,
        display_name="Human Analyst",
        purpose="Approve, reject or annotate agent proposals.",
        allowed_tools=frozenset(),
        max_action_risk=ActionRisk.DESTRUCTIVE,
        max_tool_calls=0,
        may_request_approval=True,
    ),
    AgentRole.BASELINE: AgentIdentity(
        role=AgentRole.BASELINE,
        display_name="Baseline Single Agent",
        purpose="Reference single-agent implementation retained for comparison.",
        allowed_tools=frozenset({"classify_alert", "enrich_ioc", "lookup_mitre", "query_vector_logs"}),
        max_action_risk=ActionRisk.READ_ONLY,
        max_tool_calls=20,
    ),
}


def get_identity(role: AgentRole | str) -> AgentIdentity:
    """Look up a principal by role, raising on unknown ids."""
    if isinstance(role, str):
        try:
            role = AgentRole(role)
        except ValueError as exc:
            raise UnknownPrincipalError(f"unknown principal '{role}'") from exc
    identity = AGENT_IDENTITIES.get(role)
    if identity is None:
        raise UnknownPrincipalError(f"unknown principal '{role}'")
    return identity


def capability_matrix() -> list[dict[str, object]]:
    """Render the capability table for docs and the analyst UI."""
    return [
        {
            "agent": identity.display_name,
            "role": identity.role.value,
            "tools": sorted(identity.allowed_tools) or ["-"],
            "max_action_risk": identity.max_action_risk.value,
            "max_tool_calls": identity.max_tool_calls,
            "may_request_approval": identity.may_request_approval,
        }
        for identity in AGENT_IDENTITIES.values()
    ]
