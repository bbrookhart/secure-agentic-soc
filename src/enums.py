"""Core domain enumerations.

This module deliberately sits at the very bottom of the import graph: it is
imported by both the state models (`src.state`) and the security policy engine
(`src.security.policy`) without creating a cycle between them.  Keeping the
vocabulary in one place also means severity strings cannot drift between the
agent that assigns them and the policy that acts on them.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Alert / incident severity, ordered from lowest to highest impact.

    Note: we intentionally do NOT override the comparison dunders inherited
    from ``str``.  Severity ordering is expressed explicitly via ``.rank`` and
    :func:`at_least` so that a stray ``>=`` never silently performs a
    lexicographic string comparison ("critical" < "low" alphabetically, which
    would invert a security decision).
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank (0 = INFO ... 4 = CRITICAL) for use in policy rules."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def at_least(severity: Severity, threshold: Severity) -> bool:
    """Return True when ``severity`` is at or above ``threshold``."""
    return severity.rank >= threshold.rank


def max_severity(*severities: Severity) -> Severity:
    """Return the highest severity supplied (INFO when called with nothing)."""
    return max(severities, key=lambda s: s.rank, default=Severity.INFO)


class AlertCategory(str, Enum):
    """Coarse incident taxonomy used by the triage agent."""

    MALWARE = "malware"
    PHISHING = "phishing"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    RECONNAISSANCE = "reconnaissance"
    POLICY_VIOLATION = "policy_violation"
    BENIGN_OR_FALSE_POSITIVE = "benign_or_false_positive"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    """Final disposition of an alert."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    INCONCLUSIVE = "inconclusive"


class IndicatorType(str, Enum):
    """Indicator-of-compromise types accepted by the enrichment tools."""

    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    MD5 = "md5"
    EMAIL = "email"


class AgentRole(str, Enum):
    """Stable identifiers for every agent identity in the system."""

    SUPERVISOR = "supervisor"
    TRIAGE = "triage"
    ENRICHMENT = "enrichment"
    REPORTER = "reporter"
    # Non-agent principal used when a human analyst acts on the graph.
    HUMAN_ANALYST = "human_analyst"
    # Used by the baseline single-agent reference implementation.
    BASELINE = "baseline"


class ActionRisk(str, Enum):
    """Impact class of a proposed response action.

    Drives the human-in-the-loop policy: anything above ``READ_ONLY`` is a
    *proposal only* and is never executed by this system.
    """

    READ_ONLY = "read_only"
    LOW_IMPACT = "low_impact"
    DISRUPTIVE = "disruptive"
    DESTRUCTIVE = "destructive"


class ApprovalStatus(str, Enum):
    """Lifecycle of a human-in-the-loop approval gate."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class PolicyEffect(str, Enum):
    """Outcome of a policy evaluation."""

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class AuditAction(str, Enum):
    """Closed vocabulary of auditable actions.

    A closed enum (rather than free text) means the audit trail can be queried
    and alerted on reliably -- an audit log you cannot query is decoration.
    """

    RUN_STARTED = "run_started"
    RUN_COMPLETED = "run_completed"
    AGENT_STARTED = "agent_started"
    AGENT_COMPLETED = "agent_completed"
    ROUTING_DECISION = "routing_decision"
    LLM_CALL = "llm_call"
    LLM_FALLBACK = "llm_fallback"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    TOOL_DENIED = "tool_denied"
    RATE_LIMITED = "rate_limited"
    POLICY_EVALUATED = "policy_evaluated"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    UNTRUSTED_CONTENT_FLAGGED = "untrusted_content_flagged"
    # "Someone tried and was refused" -- the event a reviewer looks for, and
    # which had no representation before human authorization existed.
    AUTHORIZATION_DENIED = "authorization_denied"
    # A signed statement of where the chain stood, forwarded off-host so a
    # later local rewrite has something it cannot retract to disagree with.
    AUDIT_ANCHOR = "audit_anchor"
    STATE_TRANSITION = "state_transition"
    ERROR = "error"
