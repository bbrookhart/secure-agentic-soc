"""Who may approve what.

[`identity.py`](identity.py) declares what each *agent* may do. This is the same
idea applied to *people*: a statically declared authority matrix, enforced in
code, readable as data. Authentication -- establishing who someone is -- happens
in [`approval_identity.py`](approval_identity.py); this module decides what that
person is allowed to sign off.

Until now there was no such decision. Any identity the proxy asserted could
approve anything: a junior analyst could sign off host isolation on a
business-critical asset, and the person who launched a run could approve their
own work. Authentication without authorization is a door with a nameplate and no
lock.

Four rules carry the weight, in the order they are evaluated:

* **A role that cannot approve, cannot approve.** A viewer sees investigations
  and signs nothing.
* **Separation of duties (NIST 800-53 AC-5).** Whoever initiated a run may not
  approve it. One person deciding both that an investigation happens and that its
  conclusions are accepted is the control collapsing into a formality.
* **Severity and risk ceilings (AC-6).** Authority is proportional to
  consequence. Approving a low-severity ticket and approving containment on a
  payment host are not the same act.
* **Two-person integrity**, optional, for disruptive proposals on critical
  assets.

Every decision is audited, denials included. *"Someone tried and was refused"* is
precisely the event a reviewer looks for, and it had no representation before.

Deny beats allow, and the first matching denial is reported -- so the analyst is
told the most specific reason they were stopped.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from src.enums import ActionRisk, Severity


class AnalystRole(str, Enum):
    """Roles an approver may hold. Ordered from least to most authority."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    SECURITY_ADMIN = "security_admin"


class RoleAuthority(BaseModel):
    """What one role may approve.

    Deliberately shaped like :class:`~src.security.identity.AgentIdentity`: the
    two matrices answer the same question about different principals, and an
    auditor should be able to read them the same way.
    """

    model_config = ConfigDict(frozen=True)

    role: AnalystRole
    display_name: str
    purpose: str
    may_approve: bool = False
    #: Highest triage severity this role may sign off. None = may not approve.
    max_severity: Severity | None = None
    #: Highest-risk proposed action this role may sign off.
    max_action_risk: ActionRisk = ActionRisk.READ_ONLY
    #: Whether this role may approve incidents touching business-critical assets.
    may_approve_critical_asset: bool = False


# ---------------------------------------------------------------------------
# The human authority matrix.
#
# Read this next to the agent capability matrix in identity.py. Together they
# are the whole authorization posture: what code may do, and what people may do.
# ---------------------------------------------------------------------------
ROLE_AUTHORITY: dict[AnalystRole, RoleAuthority] = {
    AnalystRole.VIEWER: RoleAuthority(
        role=AnalystRole.VIEWER,
        display_name="Viewer",
        purpose="Read investigations and reports. Signs nothing.",
        may_approve=False,
    ),
    AnalystRole.ANALYST: RoleAuthority(
        role=AnalystRole.ANALYST,
        display_name="SOC Analyst",
        purpose="Approve routine incidents on standard assets.",
        may_approve=True,
        max_severity=Severity.HIGH,
        # Low-impact actions only: an analyst may sign off a ticket, not the
        # isolation of a host.
        max_action_risk=ActionRisk.LOW_IMPACT,
        may_approve_critical_asset=False,
    ),
    AnalystRole.SENIOR_ANALYST: RoleAuthority(
        role=AnalystRole.SENIOR_ANALYST,
        display_name="Senior SOC Analyst",
        purpose="Approve any severity, including disruptive containment on critical assets.",
        may_approve=True,
        max_severity=Severity.CRITICAL,
        max_action_risk=ActionRisk.DISRUPTIVE,
        may_approve_critical_asset=True,
    ),
    AnalystRole.SECURITY_ADMIN: RoleAuthority(
        role=AnalystRole.SECURITY_ADMIN,
        display_name="Security Administrator",
        purpose="Full approval authority; owns policy and capability configuration.",
        may_approve=True,
        max_severity=Severity.CRITICAL,
        max_action_risk=ActionRisk.DISRUPTIVE,
        may_approve_critical_asset=True,
    ),
}

#: Group names a proxy may assert, mapped onto roles. Extend for local naming.
GROUP_ROLE_MAP: dict[str, AnalystRole] = {
    "soc-viewer": AnalystRole.VIEWER,
    "soc-analyst": AnalystRole.ANALYST,
    "soc-senior": AnalystRole.SENIOR_ANALYST,
    "soc-senior-analyst": AnalystRole.SENIOR_ANALYST,
    "soc-admin": AnalystRole.SECURITY_ADMIN,
    "security-admin": AnalystRole.SECURITY_ADMIN,
}


class AuthorizationDecision(BaseModel):
    """Outcome of an authorization check, recorded verbatim in the audit log."""

    model_config = ConfigDict(frozen=True)

    allowed: bool
    rule_id: str
    reason: str
    effective_role: AnalystRole | None = None
    matched_roles: tuple[AnalystRole, ...] = ()


class ApprovalContext(BaseModel):
    """Everything the authorization check may consider.

    Structured values only, mirroring :class:`~src.security.policy.PolicyInput`.
    No free text from the alert reaches this decision.
    """

    model_config = ConfigDict(frozen=True)

    approver: str = Field(description="Identity of the person approving.")
    roles: tuple[AnalystRole, ...] = ()
    severity: Severity = Severity.INFO
    action_risks: tuple[ActionRisk, ...] = ()
    asset_is_critical: bool = False
    initiated_by: str = ""
    #: Distinct identities that have already approved this request.
    prior_approvers: tuple[str, ...] = ()
    #: Whether the identity was established by the authenticating proxy rather
    #: than self-asserted at a CLI.
    identity_verified: bool = False
    #: Whether this deployment demands verified identities for approval.
    authentication_required: bool = True
    #: Whether the initiator of a run is barred from approving it (AC-5).
    separation_of_duties_required: bool = True


def roles_from_groups(groups: Sequence[str] | str | None) -> tuple[AnalystRole, ...]:
    """Map proxy-asserted group names onto roles.

    Unrecognised groups are ignored rather than guessed at: a user whose groups
    mean nothing here ends up with no authority, which is the safe direction.
    """
    if groups is None:
        return ()
    if isinstance(groups, str):
        raw = [part for part in groups.replace(";", ",").split(",")]
    else:
        raw = list(groups)

    found: list[AnalystRole] = []
    for item in raw:
        role = GROUP_ROLE_MAP.get(str(item).strip().lower())
        if role is not None and role not in found:
            found.append(role)
    return tuple(found)


def effective_authority(roles: Sequence[AnalystRole]) -> RoleAuthority | None:
    """The strongest authority among the roles held, or None if there is none."""
    ranked = [ROLE_AUTHORITY[role] for role in roles if role in ROLE_AUTHORITY]
    if not ranked:
        return None
    order = list(ROLE_AUTHORITY)
    return max(ranked, key=lambda authority: order.index(authority.role))


def _highest_risk(risks: Sequence[ActionRisk]) -> ActionRisk:
    order = [ActionRisk.READ_ONLY, ActionRisk.LOW_IMPACT, ActionRisk.DISRUPTIVE, ActionRisk.DESTRUCTIVE]
    return max(risks, key=order.index) if risks else ActionRisk.READ_ONLY


def authorize_approval(context: ApprovalContext) -> AuthorizationDecision:
    """Decide whether this person may approve this incident. Fails closed.

    Roles are only meaningful when something vouched for them. An identity
    asserted at a CLI could name any role it liked, so role ceilings are
    enforced exactly when the identity is proxy-verified:

    * **Verified identity** -- the full matrix applies.
    * **Unverified, and the deployment requires authentication** -- refused
      outright. In a hardened deployment the console is the approval surface and
      a self-asserted identity is not an approver.
    * **Unverified, and authentication is not required** -- local or demo mode.
      Role ceilings are skipped because they would be self-granted, and the
      decision is already recorded as ``unauthenticated`` in the audit trail.

    Separation of duties is checked in every case. It compares two names rather
    than trusting a claim of privilege, so it is still worth something even when
    the identity is self-asserted.
    """
    # --- Separation of duties (AC-5) --------------------------------------
    # First, and independent of authentication: this is a comparison, not a
    # privilege claim, so it holds even where roles cannot be trusted.
    if (
        context.separation_of_duties_required
        and context.initiated_by
        and context.approver == context.initiated_by
    ):
        return AuthorizationDecision(
            allowed=False,
            rule_id="AUTHZ-003-separation-of-duties",
            reason=(
                "The person who initiated this investigation may not approve it. "
                "Deciding both that a run happens and that its conclusions stand is "
                "one decision wearing two hats."
            ),
            matched_roles=tuple(context.roles),
        )

    if context.approver in context.prior_approvers:
        return AuthorizationDecision(
            allowed=False,
            rule_id="AUTHZ-007-duplicate-approver",
            reason="This identity has already approved this request; a second approver is required.",
            matched_roles=tuple(context.roles),
        )

    # --- Unverified identities --------------------------------------------
    if not context.identity_verified:
        if context.authentication_required:
            return AuthorizationDecision(
                allowed=False,
                rule_id="AUTHZ-008-unverified-identity",
                reason=(
                    "This approval was not made through the authenticating console, so the "
                    "approver's identity and roles are self-asserted. Approve from the console, "
                    "or set SOC_REQUIRE_AUTHENTICATED_APPROVAL=false for local single-user runs."
                ),
                matched_roles=tuple(context.roles),
            )
        return AuthorizationDecision(
            allowed=True,
            rule_id="AUTHZ-000-unauthenticated-local",
            reason=(
                "Authentication is not required in this deployment; role ceilings are not "
                "enforced because they would be self-granted. Recorded as unauthenticated."
            ),
            matched_roles=tuple(context.roles),
        )

    authority = effective_authority(context.roles)

    # --- No recognised authority ------------------------------------------
    if authority is None:
        return AuthorizationDecision(
            allowed=False,
            rule_id="AUTHZ-001-no-role",
            reason=(
                "No recognised SOC role. The approval console grants authority by group "
                "membership asserted by the authenticating proxy; this identity holds none."
            ),
            matched_roles=tuple(context.roles),
        )

    if not authority.may_approve:
        return AuthorizationDecision(
            allowed=False,
            rule_id="AUTHZ-002-role-may-not-approve",
            reason=f"Role '{authority.display_name}' has read access only and cannot approve.",
            effective_role=authority.role,
            matched_roles=tuple(context.roles),
        )

    # --- Authority proportional to consequence (AC-6) ---------------------
    ceiling = authority.max_severity
    if ceiling is None or context.severity.rank > ceiling.rank:
        return AuthorizationDecision(
            allowed=False,
            rule_id="AUTHZ-004-severity-ceiling",
            reason=(
                f"Severity '{context.severity.value}' exceeds the ceiling for role "
                f"'{authority.display_name}'"
                + (f" ('{ceiling.value}')." if ceiling else " (no severity authority).")
            ),
            effective_role=authority.role,
            matched_roles=tuple(context.roles),
        )

    highest = _highest_risk(context.action_risks)
    order = [ActionRisk.READ_ONLY, ActionRisk.LOW_IMPACT, ActionRisk.DISRUPTIVE, ActionRisk.DESTRUCTIVE]
    if order.index(highest) > order.index(authority.max_action_risk):
        return AuthorizationDecision(
            allowed=False,
            rule_id="AUTHZ-005-action-risk-ceiling",
            reason=(
                f"A '{highest.value}' action is proposed; role '{authority.display_name}' may "
                f"approve up to '{authority.max_action_risk.value}'."
            ),
            effective_role=authority.role,
            matched_roles=tuple(context.roles),
        )

    if context.asset_is_critical and not authority.may_approve_critical_asset:
        return AuthorizationDecision(
            allowed=False,
            rule_id="AUTHZ-006-critical-asset",
            reason=(
                f"This incident involves a business-critical asset; role "
                f"'{authority.display_name}' may not approve those."
            ),
            effective_role=authority.role,
            matched_roles=tuple(context.roles),
        )

    return AuthorizationDecision(
        allowed=True,
        rule_id="AUTHZ-000-permitted",
        reason=f"Role '{authority.display_name}' is authorised for this approval.",
        effective_role=authority.role,
        matched_roles=tuple(context.roles),
    )


def required_approvals(*, action_risks: Sequence[ActionRisk], asset_is_critical: bool) -> int:
    """How many distinct approvers this decision needs.

    Two-person integrity is configuration-gated and off by default: it doubles
    the cost of every disruptive approval, which is correct in some environments
    and pure friction in others.
    """
    from src.config import get_settings

    settings = get_settings()
    if not settings.require_two_person_approval:
        return 1

    disruptive = _highest_risk(action_risks) is ActionRisk.DISRUPTIVE
    return 2 if (disruptive and asset_is_critical) else 1


def authority_matrix() -> list[dict[str, object]]:
    """Render the human authority table for docs, the UI, and evidence."""
    return [
        {
            "role": authority.role.value,
            "display_name": authority.display_name,
            "purpose": authority.purpose,
            "may_approve": authority.may_approve,
            "max_severity": authority.max_severity.value if authority.max_severity else "-",
            "max_action_risk": authority.max_action_risk.value,
            "may_approve_critical_asset": authority.may_approve_critical_asset,
        }
        for authority in ROLE_AUTHORITY.values()
    ]
