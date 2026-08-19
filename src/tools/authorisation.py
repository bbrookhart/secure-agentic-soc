"""``verify_authorisation`` -- is this activity actually sanctioned?

Alerts routinely *claim* authorisation: "per change ticket CHG-44120", "inside
the approved maintenance window", "from the authorised red team range". Those
claims are the single most useful signal for suppressing a false positive, and
they are also the most dangerous thing in the alert, because **alert text is
attacker-influenceable**.

That is not a hypothetical. Treating claimed authorisation as real was measured
against this project's own corpus and would have wrongly suppressed four attack
cases, including ``INJ-002`` -- an alert deliberately written to read as a
routine VPN false positive, which scored higher on authorisation vocabulary
than most genuinely benign alerts. An attacker who can write alert text would
have gained a one-line suppression phrase for their own intrusion.

So authorisation is *verified*, never accepted:

* the claim is extracted from the alert (untrusted),
* the reference is looked up in change-management records (trusted),
* and the record must actually **cover this asset at this time** before the
  claim is honoured.

A missing record, a withdrawn record, a record for a different host, or a
record whose window has closed all come back unverified -- which leaves the
alert exactly as suspicious as it was before anyone read the claim.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, time, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from src.enums import ActionRisk
from src.tools.base import SOCTool

#: Change and exercise references as they appear in alert text. Deliberately
#: narrow: a reference is an identifier, not a sentence, so there is no way to
#: smuggle prose through this.
_REFERENCE_RE = re.compile(r"\b((?:CHG|CR|RFC|EX|BKP|MON)-[A-Z0-9]{2,16}(?:-[A-Z0-9]{1,12})?)\b", re.I)

#: Windows are compared with a little slack, because a detection timestamp is
#: rarely the same instant as the activity that triggered it.
_WINDOW_GRACE = timedelta(minutes=30)


class VerifyAuthorisationInput(BaseModel):
    """Input schema for ``verify_authorisation``."""

    claimed_reference: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "Change or exercise reference cited by the alert, e.g. 'CHG-44120'. "
            "Omit to search standing approvals covering the asset instead."
        ),
    )
    asset: str = Field(
        min_length=1,
        max_length=256,
        description="Asset the activity was observed on.",
    )
    occurred_at: str = Field(
        min_length=4,
        max_length=64,
        description="ISO-8601 timestamp of the observed activity.",
    )

    @field_validator("claimed_reference")
    @classmethod
    def _reference_shaped(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        cleaned = value.strip()
        if not _REFERENCE_RE.fullmatch(cleaned):
            raise ValueError("claimed_reference must be a change or exercise identifier")
        return cleaned.upper()


def extract_claimed_references(text: str, *, limit: int = 5) -> list[str]:
    """Pull candidate change references out of untrusted alert text.

    Extraction only. Nothing here decides anything -- a reference found in an
    alert is a *lead to check*, and is worthless until ``verify_authorisation``
    confirms a real record covers it.
    """
    seen: list[str] = []
    for match in _REFERENCE_RE.finditer(text or ""):
        reference = match.group(1).upper()
        if reference not in seen:
            seen.append(reference)
        if len(seen) >= limit:
            break
    return seen


@lru_cache(maxsize=1)
def _load_records(path_str: str) -> dict[str, Any]:
    path = Path(path_str)
    if not path.exists():
        return {"changes": [], "exercises": []}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"changes": [], "exercises": []}
    return {"changes": list(raw.get("changes", [])), "exercises": list(raw.get("exercises", []))}


def _records_path() -> str:
    from src.config import get_settings

    return str(get_settings().change_records_path)


def _parse(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _covers_asset(record: dict[str, Any], asset: str) -> bool:
    target = asset.strip().lower()
    if any(target == str(a).strip().lower() for a in record.get("assets", [])):
        return True
    # A scanner or management account is approved to *reach* everything, but the
    # approval still names the originating asset, which must have matched above.
    return False


def _within_window(record: dict[str, Any], moment: datetime) -> tuple[bool, str]:
    start = _parse(record.get("window_start", ""))
    end = _parse(record.get("window_end", ""))
    if start is None or end is None:
        return False, "record has no usable window"
    if not (start - _WINDOW_GRACE <= moment <= end + _WINDOW_GRACE):
        return False, f"activity at {moment.isoformat()} falls outside {start.isoformat()}..{end.isoformat()}"

    # Standing approvals additionally constrain the time of day.
    daily_start, daily_end = record.get("recurring_daily_start"), record.get("recurring_daily_end")
    if daily_start and daily_end:
        try:
            begin = time.fromisoformat(str(daily_start))
            finish = time.fromisoformat(str(daily_end))
        except ValueError:
            return True, "covered"
        observed = moment.timetz().replace(tzinfo=None)
        inside = begin <= observed <= finish if begin <= finish else (observed >= begin or observed <= finish)
        if not inside:
            return False, f"outside the recurring daily window {daily_start}-{daily_end}"
    return True, "covered"


def verify_authorisation(payload: VerifyAuthorisationInput) -> dict[str, Any]:
    """Check a claimed change reference against change-management records."""
    records = _load_records(_records_path())
    reference = payload.claimed_reference
    moment = _parse(payload.occurred_at)

    def unverified(reason: str, **extra: Any) -> dict[str, Any]:
        return {
            "claimed_reference": reference,
            "asset": payload.asset,
            "verified": False,
            "reason": reason,
            # Said explicitly so an agent cannot read "unverified" as "malicious"
            # either -- it means the claim was not substantiated, nothing more.
            "note": (
                "Authorisation was NOT substantiated. Treat the activity as if no "
                "change reference had been cited at all."
            ),
            **extra,
        }

    if moment is None:
        return unverified("occurred_at is not a parseable timestamp")

    everything = records["changes"] + records["exercises"]

    def _ref_of(record: dict[str, Any]) -> str:
        return str(record.get("change_ref") or record.get("exercise_ref") or "").upper()

    if reference:
        candidates = [r for r in everything if _ref_of(r) == reference]
        if not candidates:
            return unverified("no change or exercise record exists with this reference")
    else:
        # No reference cited. Fall back to standing approvals registered against
        # the asset itself -- a nightly backup or a health-check poller is
        # authorised by an ongoing arrangement, not by a per-occurrence ticket.
        # Only standing approvals are eligible: a one-off change must be cited
        # explicitly, or any alert on a host with any past ticket would inherit
        # an approval it has nothing to do with.
        candidates = [
            r for r in everything
            if str(r.get("change_type", "")) == "standing_approval" and _covers_asset(r, payload.asset)
        ]
        if not candidates:
            return unverified("no reference was cited and no standing approval covers this asset")

    for record in candidates:
        status = str(record.get("status", "")).lower()
        if status != "approved":
            return unverified(f"record exists but its status is '{status}', not 'approved'")
        if not _covers_asset(record, payload.asset):
            return unverified(
                "record exists but does not cover this asset",
                record_assets=list(record.get("assets", [])),
            )
        inside, why = _within_window(record, moment)
        if not inside:
            return unverified(f"record exists but {why}")

        return {
            "claimed_reference": reference,
            "asset": payload.asset,
            "verified": True,
            "reason": "an approved record covers this asset at this time",
            "title": str(record.get("title", "")),
            "change_type": str(record.get("change_type", record.get("status", ""))),
            # What this record can legitimately account for. An approval is not
            # a blanket amnesty for the host: ransomware during an approved
            # patch window is still ransomware, so the caller must check that
            # the behaviour it observed is one this change actually explains.
            "explains_categories": [str(c) for c in record.get("explains_categories", [])],
            "approver": str(record.get("approver", "")),
            "window_start": str(record.get("window_start", "")),
            "window_end": str(record.get("window_end", "")),
            "note": (
                "Authorisation substantiated against change-management records. The "
                "activity is expected. This does not certify that everything on the "
                "host is expected -- only the activity the record describes."
            ),
        }

    return unverified("no approved record covered this asset at this time")


VERIFY_AUTHORISATION_TOOL = SOCTool(
    name="verify_authorisation",
    description=(
        "Verify a change or exercise reference cited by an alert (e.g. 'CHG-44120') "
        "against change-management records, for a given asset and time. Returns "
        "whether an approved record actually covers the activity. Offline and read-only."
    ),
    input_model=VerifyAuthorisationInput,
    handler=verify_authorisation,
    risk=ActionRisk.READ_ONLY,
    # The records are ours, but the echoed reference came from the alert.
    returns_untrusted=True,
)
