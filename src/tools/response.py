"""``draft_containment_proposal`` -- drafts a response action. Never executes one.

This is the only tool in the system that touches the idea of "doing something",
and it is built so that doing something is **impossible**:

* it has no client, socket, credential or subprocess -- there is nothing here
  that could reach an EDR, a firewall or a directory service even if an agent
  were fully compromised;
* it returns an inert :class:`~src.state.ProposedAction` whose ``execution_mode``
  is pinned to ``proposal_only`` by a validator;
* the action type is a closed enum, so an agent cannot invent "run_script";
* every draft with disruptive impact forces the run through the human approval
  gate via policy rule ``HITL-002``.

The separation being demonstrated is between *reasoning* and *authority*: the
agent may reason its way to "isolate this host", and that conclusion travels to
a human who holds the authority to act on it.  The gap between those two things
is the control.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from src.enums import ActionRisk
from src.tools.base import SOCTool


class ContainmentActionType(str, Enum):
    """Closed set of response actions an agent may draft."""

    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    RESET_CREDENTIALS = "reset_credentials"
    BLOCK_INDICATOR = "block_indicator"
    QUARANTINE_FILE = "quarantine_file"
    REVOKE_SESSIONS = "revoke_sessions"
    OPEN_INVESTIGATION_TICKET = "open_investigation_ticket"
    NOTIFY_ASSET_OWNER = "notify_asset_owner"


#: Impact class per action type.  Drives the approval policy.
_ACTION_RISK: dict[ContainmentActionType, ActionRisk] = {
    ContainmentActionType.ISOLATE_HOST: ActionRisk.DISRUPTIVE,
    ContainmentActionType.DISABLE_ACCOUNT: ActionRisk.DISRUPTIVE,
    ContainmentActionType.RESET_CREDENTIALS: ActionRisk.DISRUPTIVE,
    ContainmentActionType.BLOCK_INDICATOR: ActionRisk.LOW_IMPACT,
    ContainmentActionType.QUARANTINE_FILE: ActionRisk.LOW_IMPACT,
    ContainmentActionType.REVOKE_SESSIONS: ActionRisk.DISRUPTIVE,
    ContainmentActionType.OPEN_INVESTIGATION_TICKET: ActionRisk.LOW_IMPACT,
    ContainmentActionType.NOTIFY_ASSET_OWNER: ActionRisk.LOW_IMPACT,
}

#: Human-readable description of what a human would have to do to execute it.
_ACTION_TEMPLATE: dict[ContainmentActionType, str] = {
    ContainmentActionType.ISOLATE_HOST: (
        "Network-isolate {target} via the EDR console, leaving only management "
        "connectivity so responders retain access."
    ),
    ContainmentActionType.DISABLE_ACCOUNT: "Disable the account {target} in the identity provider.",
    ContainmentActionType.RESET_CREDENTIALS: (
        "Force a credential reset for {target} and require re-registration of MFA methods."
    ),
    ContainmentActionType.BLOCK_INDICATOR: (
        "Add {target} to the perimeter blocklist (firewall, proxy and DNS sinkhole)."
    ),
    ContainmentActionType.QUARANTINE_FILE: "Quarantine the file {target} across the estate via EDR.",
    ContainmentActionType.REVOKE_SESSIONS: (
        "Revoke all active sessions and refresh tokens for {target}."
    ),
    ContainmentActionType.OPEN_INVESTIGATION_TICKET: (
        "Open a tracked investigation ticket for {target} and assign it to the on-call analyst."
    ),
    ContainmentActionType.NOTIFY_ASSET_OWNER: (
        "Notify the registered owner of {target} that their asset is under investigation."
    ),
}


class DraftContainmentInput(BaseModel):
    """Input schema for ``draft_containment_proposal``."""

    action_type: ContainmentActionType = Field(
        description="Which containment action to draft. Closed set; no free-form actions."
    )
    target: str = Field(
        min_length=1,
        max_length=256,
        description="Hostname, account, indicator or file hash the action would affect.",
    )
    justification: str = Field(
        min_length=10,
        max_length=1000,
        description="Evidence-based reason this action is warranted.",
    )

    @field_validator("target")
    @classmethod
    def _clean_target(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("target must not be blank")
        # Reject shell/path metacharacters outright.  Nothing downstream
        # executes this string, but a target that cannot express a command is
        # one fewer thing to reason about if that ever changes.
        forbidden = set(";|&$`><\n\r\t\\'\"")
        if forbidden & set(cleaned):
            raise ValueError("target contains forbidden characters")
        return cleaned


def draft_containment_proposal(payload: DraftContainmentInput) -> dict[str, Any]:
    """Draft an inert containment proposal for human review."""
    risk = _ACTION_RISK[payload.action_type]
    description = _ACTION_TEMPLATE[payload.action_type].format(target=payload.target)

    return {
        "action_type": payload.action_type.value,
        "title": payload.action_type.value.replace("_", " ").title() + f": {payload.target}",
        "description": description,
        "target": payload.target,
        "risk": risk.value,
        "rationale": payload.justification,
        "execution_mode": "proposal_only",
        "executed": False,
        "requires_human_approval": risk in {ActionRisk.DISRUPTIVE, ActionRisk.DESTRUCTIVE},
        "notice": (
            "DRAFT ONLY. This system has no capability to execute containment actions. "
            "A human analyst must review and perform this action in the relevant console."
        ),
    }


DRAFT_CONTAINMENT_TOOL = SOCTool(
    name="draft_containment_proposal",
    description=(
        "Draft a containment action proposal (isolate_host, disable_account, "
        "reset_credentials, block_indicator, quarantine_file, revoke_sessions, "
        "open_investigation_ticket, notify_asset_owner) for human review. "
        "DRAFTS ONLY -- this tool cannot execute anything."
    ),
    input_model=DraftContainmentInput,
    handler=draft_containment_proposal,
    # Declared at the impact level of the action it *describes*, so the broker's
    # risk-ceiling check keeps low-privilege agents away from it entirely.
    risk=ActionRisk.DISRUPTIVE,
    # Output is built from our templates plus the agent's justification text.
    returns_untrusted=True,
)
