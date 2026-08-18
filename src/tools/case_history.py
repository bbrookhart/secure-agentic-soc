"""``query_case_history`` -- what this environment has seen before.

An analyst's first question about a suspicious host is rarely "what is this
alert", it is "has this host been in trouble lately".  Until now the pipeline
could not answer that at all.

Note what comes back: prior alert titles, which originated in earlier
attacker-influenced alerts.  A payload planted in one alert could otherwise
resurface weeks later inside the enrichment prompt for a different
investigation.  It does not, because this is an ordinary tool -- its output
goes through the broker's sanitisation, injection scanning and truncation like
every other untrusted source, and a hit raises the same flag a hostile log line
would.  That is the argument for putting history behind a tool rather than
reading the store directly from an agent.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from src.enums import ActionRisk
from src.tools.base import SOCTool


class QueryCaseHistoryInput(BaseModel):
    """Input schema for ``query_case_history``."""

    entity: str = Field(
        min_length=3,
        max_length=256,
        description="Host name, account, IP or indicator to look up in prior investigations.",
    )
    days: int = Field(default=14, ge=1, le=365, description="How far back to look.")
    limit: int = Field(default=10, ge=1, le=50)

    @field_validator("entity")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("entity must not be blank")
        return value.strip()


def query_case_history(payload: QueryCaseHistoryInput) -> dict[str, Any]:
    """Return prior investigations touching this entity."""
    from datetime import timedelta

    from src.memory.case_store import get_case_store

    runs = get_case_store().history_for_entity(
        payload.entity,
        window=timedelta(days=payload.days),
        limit=payload.limit,
    )

    matches = [
        {
            "thread_id": run.thread_id,
            "alert_id": run.alert_id,
            "title": run.title,
            "severity": run.severity,
            "category": run.category,
            "verdict": run.verdict,
            "approval_status": run.approval_status,
            "recorded_at": run.recorded_at,
        }
        for run in runs
    ]

    return {
        "entity": payload.entity,
        "window_days": payload.days,
        "match_count": len(matches),
        "matches": matches,
        # Stated explicitly so an agent cannot read "no history" as "no risk".
        "note": (
            "No prior investigations found for this entity. Absence of history is not "
            "evidence of safety -- it may simply be the first time this entity was alerted on."
            if not matches
            else "Prior investigations involving this entity. Verdicts reflect earlier "
            "assessments, which may themselves have been wrong."
        ),
    }


QUERY_CASE_HISTORY_TOOL = SOCTool(
    name="query_case_history",
    description=(
        "Look up prior investigations involving a host, account, IP or indicator. "
        "Answers 'has this entity been involved in anything else recently'."
    ),
    input_model=QueryCaseHistoryInput,
    handler=query_case_history,
    risk=ActionRisk.READ_ONLY,
    returns_untrusted=True,
)
