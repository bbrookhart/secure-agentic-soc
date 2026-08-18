"""Durable memory across runs: what we have seen, and what a human decided.

Every investigation was previously an island.  The pipeline triaged the same
host for the fifth time with no idea it had done so, and the analyst's
approve/reject -- the single most expensive signal in the system, because a
person produced it -- was written to the audit log and never read again.

This store keeps three things:

* **Alert records** -- one row per completed run: the fingerprint, the verdict,
  and how it was dispositioned.
* **Entities** -- the hosts, accounts and indicators each run touched, which is
  what makes "has this host been involved in anything else lately" answerable.
* **Cases** -- groupings of runs that share an entity inside a time window.

Two deliberate limits on what this is allowed to do:

**Dedup is mechanical, never learned.**  An identical fingerprint inside a short
window is a duplicate of an alert already triaged, and re-running it produces a
second opinion on the same bytes.  That is safe because it compares an exact
hash, not a judgement.

**History escalates; it never suppresses.**  A rule that closed alerts because
similar ones were previously cleared would be trainable: an attacker who can
generate benign-looking alerts could establish a pattern and then hide inside
it.  So prior false positives are *reported* to the analyst and the report,
while only the escalating direction is wired into policy.  Feeding history into
a gate is only safe in the direction that asks for more human attention.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.enums import ApprovalStatus, Severity, Verdict
from src.state import SecurityAlert, SOCState

#: How far back correlation and dedup look by default.
DEFAULT_WINDOW = timedelta(days=14)
#: An identical alert inside this window is a duplicate, not a new incident.
DEDUP_WINDOW = timedelta(hours=6)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_records (
    thread_id        TEXT PRIMARY KEY,
    fingerprint      TEXT NOT NULL,
    alert_id         TEXT NOT NULL,
    source           TEXT NOT NULL DEFAULT '',
    title            TEXT NOT NULL DEFAULT '',
    detected_at      TEXT NOT NULL DEFAULT '',
    recorded_at      TEXT NOT NULL,
    severity         TEXT NOT NULL DEFAULT '',
    category         TEXT NOT NULL DEFAULT '',
    verdict          TEXT NOT NULL DEFAULT '',
    approval_status  TEXT NOT NULL DEFAULT '',
    decided_by       TEXT NOT NULL DEFAULT '',
    identity_source  TEXT NOT NULL DEFAULT '',
    case_id          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alert_fingerprint ON alert_records(fingerprint);
CREATE INDEX IF NOT EXISTS idx_alert_recorded ON alert_records(recorded_at);

CREATE TABLE IF NOT EXISTS entities (
    thread_id  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (thread_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_entity_value ON entities(value);

CREATE TABLE IF NOT EXISTS cases (
    case_id    TEXT PRIMARY KEY,
    opened_at  TEXT NOT NULL,
    title      TEXT NOT NULL DEFAULT ''
);
"""


def _utc_now() -> datetime:
    return datetime.now(UTC)


class PriorDispositions(BaseModel):
    """History projected into the structured shape a policy rule may read.

    Counts only.  :class:`~src.security.policy.PolicyInput` deliberately holds
    no free text, and history is no exception: prior alert titles are
    attacker-influenced strings, and letting them near the one component that
    cannot currently be talked into anything would open a fresh injection
    channel through the back door.
    """

    model_config = ConfigDict(frozen=True)

    duplicate_of: str = Field(default="", description="thread_id of an identical recent alert.")
    related_run_count: int = 0
    confirmed_malicious_count: int = Field(
        default=0, description="Related runs a human approved as real incidents."
    )
    confirmed_false_positive_count: int = Field(
        default=0, description="Related runs concluded benign. Reported, never used to suppress."
    )
    case_id: str = ""

    @property
    def is_duplicate(self) -> bool:
        return bool(self.duplicate_of)


class RelatedRun(BaseModel):
    """A prior run sharing an entity with the alert under investigation."""

    model_config = ConfigDict(frozen=True)

    thread_id: str
    alert_id: str
    title: str
    severity: str
    category: str
    verdict: str
    approval_status: str
    recorded_at: str
    shared_entities: tuple[str, ...] = ()


class CaseStore:
    """SQLite-backed history of investigations."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(str(self.path), check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.executescript(_SCHEMA)
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    # --- Writing ---------------------------------------------------------
    def record_run(self, state: SOCState) -> str:
        """Persist a completed run and attach it to a case. Returns the case id."""
        alert = state.alert
        entities = list(entities_of(alert))
        case_id = self._resolve_case(entities, alert) or self._open_case(alert)

        triage = state.triage_result
        report = state.final_report
        decision = state.approval_decision

        with self._lock:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO alert_records (
                    thread_id, fingerprint, alert_id, source, title, detected_at, recorded_at,
                    severity, category, verdict, approval_status, decided_by, identity_source, case_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    state.run.thread_id,
                    alert.fingerprint(),
                    alert.alert_id,
                    alert.source,
                    alert.title[:512],
                    alert.detected_at.isoformat(),
                    _utc_now().isoformat(),
                    triage.severity.value if triage else "",
                    triage.category.value if triage else "",
                    report.verdict.value if report else "",
                    state.approval_status.value,
                    decision.decided_by if decision else "",
                    decision.identity_source if decision else "",
                    case_id,
                ),
            )
            self._connection.executemany(
                "INSERT OR IGNORE INTO entities (thread_id, kind, value) VALUES (?, ?, ?)",
                [(state.run.thread_id, kind, value) for kind, value in entities],
            )
            self._connection.commit()

        return case_id

    def _open_case(self, alert: SecurityAlert) -> str:
        case_id = f"CASE-{uuid.uuid4().hex[:10]}"
        with self._lock:
            self._connection.execute(
                "INSERT INTO cases (case_id, opened_at, title) VALUES (?, ?, ?)",
                (case_id, _utc_now().isoformat(), alert.title[:512]),
            )
            self._connection.commit()
        return case_id

    def _resolve_case(self, entities: list[tuple[str, str]], alert: SecurityAlert) -> str:
        """Find an open case sharing an entity with this alert, if any."""
        related = self.related_runs(alert, window=DEFAULT_WINDOW)
        for run in related:
            row = self._fetchone(
                "SELECT case_id FROM alert_records WHERE thread_id = ?", (run.thread_id,)
            )
            if row and row["case_id"]:
                return str(row["case_id"])
        return ""

    # --- Reading ---------------------------------------------------------
    def _fetchone(self, sql: str, params: tuple[Any, ...]) -> sqlite3.Row | None:
        with self._lock:
            cursor = self._connection.execute(sql, params)
            return cursor.fetchone()

    def _fetchall(self, sql: str, params: tuple[Any, ...]) -> list[sqlite3.Row]:
        with self._lock:
            cursor = self._connection.execute(sql, params)
            return list(cursor.fetchall())

    def find_duplicate(self, alert: SecurityAlert, *, window: timedelta = DEDUP_WINDOW) -> str:
        """Thread id of an identical alert seen inside ``window``, or empty.

        Exact fingerprint match only. This compares bytes, not judgement, which
        is what makes it safe to act on automatically.
        """
        cutoff = (_utc_now() - window).isoformat()
        row = self._fetchone(
            """
            SELECT thread_id FROM alert_records
            WHERE fingerprint = ? AND recorded_at >= ?
            ORDER BY recorded_at DESC LIMIT 1
            """,
            (alert.fingerprint(), cutoff),
        )
        return str(row["thread_id"]) if row else ""

    def related_runs(
        self, alert: SecurityAlert, *, window: timedelta = DEFAULT_WINDOW, limit: int = 20
    ) -> list[RelatedRun]:
        """Prior runs sharing a host, account or indicator with this alert."""
        values = [value for _, value in entities_of(alert)]
        if not values:
            return []

        cutoff = (_utc_now() - window).isoformat()
        # The entity list is bound as a single JSON parameter rather than
        # interpolated as N placeholders. Entity values come from alert fields,
        # which are attacker-influenced; keeping the SQL text fully static means
        # there is no string-building step to get wrong later.
        rows = self._fetchall(
            """
            SELECT r.*, GROUP_CONCAT(DISTINCT e.value) AS shared
            FROM alert_records r
            JOIN entities e ON e.thread_id = r.thread_id
            WHERE e.value IN (SELECT value FROM json_each(?))
              AND r.recorded_at >= ?
              AND r.fingerprint != ?
            GROUP BY r.thread_id
            ORDER BY r.recorded_at DESC
            LIMIT ?
            """,
            (json.dumps(values), cutoff, alert.fingerprint(), limit),
        )

        return [
            RelatedRun(
                thread_id=str(row["thread_id"]),
                alert_id=str(row["alert_id"]),
                title=str(row["title"]),
                severity=str(row["severity"]),
                category=str(row["category"]),
                verdict=str(row["verdict"]),
                approval_status=str(row["approval_status"]),
                recorded_at=str(row["recorded_at"]),
                shared_entities=tuple((row["shared"] or "").split(",")[:10]),
            )
            for row in rows
        ]

    def history_for_entity(
        self, entity: str, *, window: timedelta = DEFAULT_WINDOW, limit: int = 10
    ) -> list[RelatedRun]:
        """Prior runs touching one named entity. Backs ``query_case_history``."""
        cutoff = (_utc_now() - window).isoformat()
        rows = self._fetchall(
            """
            SELECT r.*, e.value AS shared
            FROM alert_records r
            JOIN entities e ON e.thread_id = r.thread_id
            WHERE e.value = ? AND r.recorded_at >= ?
            GROUP BY r.thread_id
            ORDER BY r.recorded_at DESC
            LIMIT ?
            """,
            (entity.strip().lower(), cutoff, limit),
        )
        return [
            RelatedRun(
                thread_id=str(row["thread_id"]),
                alert_id=str(row["alert_id"]),
                title=str(row["title"]),
                severity=str(row["severity"]),
                category=str(row["category"]),
                verdict=str(row["verdict"]),
                approval_status=str(row["approval_status"]),
                recorded_at=str(row["recorded_at"]),
                shared_entities=(str(row["shared"]),),
            )
            for row in rows
        ]

    def dispositions(
        self, alert: SecurityAlert, *, window: timedelta = DEFAULT_WINDOW
    ) -> PriorDispositions:
        """Project history into the counts a policy rule may consider."""
        related = self.related_runs(alert, window=window)

        confirmed_malicious = sum(
            1
            for run in related
            if run.approval_status == ApprovalStatus.APPROVED.value
            or run.verdict == Verdict.TRUE_POSITIVE.value
        )
        confirmed_fp = sum(1 for run in related if run.verdict == Verdict.FALSE_POSITIVE.value)

        case_id = ""
        if related:
            row = self._fetchone(
                "SELECT case_id FROM alert_records WHERE thread_id = ?", (related[0].thread_id,)
            )
            case_id = str(row["case_id"]) if row else ""

        return PriorDispositions(
            duplicate_of=self.find_duplicate(alert),
            related_run_count=len(related),
            confirmed_malicious_count=confirmed_malicious,
            confirmed_false_positive_count=confirmed_fp,
            case_id=case_id,
        )


def entities_of(alert: SecurityAlert) -> Iterable[tuple[str, str]]:
    """The correlatable identifiers in an alert: assets, their IPs, indicators.

    Values are normalised to lower case so 'SRV-FILE-02' and 'srv-file-02'
    correlate. Very short values are dropped -- a one-character asset name
    would join half the corpus together.
    """
    seen: set[tuple[str, str]] = set()

    def _add(kind: str, value: str | None) -> None:
        if not value:
            return
        cleaned = str(value).strip().lower()
        if len(cleaned) < 3:
            return
        seen.add((kind, cleaned[:256]))

    for asset in alert.assets:
        _add("asset", asset.name)
        _add("ip", asset.ip_address)
    for indicator in alert.indicators:
        _add(indicator.indicator_type.value, indicator.value)

    return sorted(seen)


def severity_rank(value: str) -> int:
    """Rank a stored severity string, tolerating blanks from partial runs."""
    try:
        return Severity(value).rank
    except ValueError:
        return -1


def prune(store: CaseStore | None = None, *, older_than: timedelta | None = None) -> int:
    """Delete case history past the retention period. Returns rows removed.

    Retention here is a real trade-off rather than housekeeping: correlation can
    only see as far back as this window, so pruning aggressively makes the
    system forget that a host was compromised last quarter. The default is
    generous for that reason.
    """
    from src.config import get_settings

    resolved = store or get_case_store()
    # `is not None`, not `or`: timedelta(0) is falsy, and a zero window means
    # "prune everything" rather than "use the default".
    window = older_than if older_than is not None else timedelta(days=get_settings().case_retention_days)
    cutoff = (_utc_now() - window).isoformat()

    with resolved._lock:  # noqa: SLF001 - same module's connection
        connection = resolved._connection  # noqa: SLF001
        # Entities first: they are keyed on runs that are about to disappear.
        connection.execute(
            "DELETE FROM entities WHERE thread_id IN "
            "(SELECT thread_id FROM alert_records WHERE recorded_at < ?)",
            (cutoff,),
        )
        removed = connection.execute(
            "DELETE FROM alert_records WHERE recorded_at < ?", (cutoff,)
        ).rowcount or 0
        # Cases with nothing left pointing at them are dead weight.
        connection.execute(
            "DELETE FROM cases WHERE case_id NOT IN "
            "(SELECT DISTINCT case_id FROM alert_records WHERE case_id != '')"
        )
        connection.commit()

    return removed


def attach_case_context(state: SOCState, store: CaseStore | None = None) -> SOCState:
    """Populate a fresh run's cross-run context before the graph starts.

    Called by each entry point right after ``bootstrap``, rather than from
    inside the graph, so that the lookup happens exactly once per run and is
    visible at the call site. Only counts and ids are copied onto state --
    nothing free-text, because these values reach the policy engine.
    """
    resolved = store or get_case_store()
    dispositions = resolved.dispositions(state.alert)

    return state.model_copy(
        update={
            "related_confirmed_malicious": dispositions.confirmed_malicious_count,
            "related_false_positives": dispositions.confirmed_false_positive_count,
            "related_run_count": dispositions.related_run_count,
            "case_id": dispositions.case_id,
            "duplicate_of": dispositions.duplicate_of,
        }
    )


def record_run(state: SOCState, store: CaseStore | None = None) -> str:
    """Persist a finished run so the next one can see it."""
    resolved = store or get_case_store()
    return resolved.record_run(state)


# --- Process-wide default ---------------------------------------------------
_default_store: CaseStore | None = None
_store_lock = threading.Lock()


def get_case_store() -> CaseStore:
    """Return the process-wide case store, creating it on first use."""
    global _default_store
    if _default_store is None:
        with _store_lock:
            if _default_store is None:
                from src.config import get_settings

                settings = get_settings()
                settings.ensure_dirs()
                _default_store = CaseStore(settings.case_store_db)
    return _default_store


def set_case_store(store: CaseStore | None) -> None:
    """Override the default store (used by tests)."""
    global _default_store
    _default_store = store
