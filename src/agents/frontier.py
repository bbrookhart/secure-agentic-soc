"""What the investigation should look at next.

A single evidence pass answers "what does this alert look like". It does not
answer "what else is involved", which is the question that turns a
classification into an investigation: an alert names one host, its logs name a
second, and that second host is where the interesting activity actually is.

This module computes the **frontier** -- entities that evidence has surfaced but
that nothing has yet investigated. The router uses it to decide whether another
round is worth running (`R-023`).

Two properties make this safe to run in a loop:

**Pivots come from structured fields, never from prose.** Candidates are read
from ``LogSearchHit.host`` and ``IOCEnrichment.indicator``, which are typed
fields populated from a log record's own host column and from the indicator that
was looked up. They are not parsed out of ``message`` text, and they are not
taken from ``EnrichmentResults.pivot_suggestions`` -- that field is written by
the LLM, which reads attacker-controlled evidence, so a hostile log line could
otherwise name a host and have the system go investigate it. The model may
influence *ordering* through its suggestions; it may never add a target.

**The frontier only shrinks.** Every entity handed out is recorded as
investigated, so a second round cannot return the same host, and two hosts that
reference each other cannot ping-pong. Combined with the round cap in the
router, the loop terminates by construction rather than by budget exhaustion.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.memory.case_store import entities_of

if TYPE_CHECKING:  # pragma: no cover - import cycle at runtime only
    from src.state import SOCState

#: Most entities one round may add. Small on purpose: an investigation that
#: fans out to ten hosts per round is not following a lead, it is crawling the
#: estate, and each entity costs tool calls the run has a fixed budget of.
DEFAULT_FRONTIER_LIMIT = 3

#: A log hit must be at least this relevant before its host is worth pivoting
#: to. Mirrors ``enrichment.MIN_LOG_RELEVANCE``: a line too weak to be evidence
#: is also too weak to justify a whole extra round of investigation.
MIN_PIVOT_RELEVANCE = 0.12


def _normalise(value: str) -> str:
    """Match ``entities_of``'s normalisation so the two sets are comparable."""
    return str(value or "").strip().lower()[:256]


def covered_entities(state: SOCState) -> set[str]:
    """Everything already investigated: the alert's own entities plus prior rounds."""
    covered = {value for _kind, value in entities_of(state.alert)}
    covered.update(_normalise(e) for e in state.investigated_entities)
    return {c for c in covered if c}


def next_frontier(state: SOCState, *, limit: int = DEFAULT_FRONTIER_LIMIT) -> tuple[str, ...]:
    """Entities worth a further look, strongest evidence first.

    Returns an empty tuple when the investigation has nowhere left to go, which
    is the router's signal to stop.
    """
    enrichment = state.enrichment_results
    if enrichment is None:
        return ()

    covered = covered_entities(state)
    scored: dict[str, float] = {}

    # A confirmed-malicious indicator is the strongest possible reason to keep
    # going, so it outranks anything the log corpus merely mentioned.
    for record in enrichment.ioc_enrichments:
        if not record.known_malicious:
            continue
        name = _normalise(record.indicator)
        if name and name not in covered:
            scored[name] = max(scored.get(name, 0.0), 10.0 + record.reputation_score / 100.0)

    # Hosts that appeared in evidence strong enough to have been kept.
    for hit in enrichment.log_hits:
        if hit.relevance < MIN_PIVOT_RELEVANCE:
            continue
        name = _normalise(hit.host)
        if name and len(name) >= 3 and name not in covered:
            scored[name] = max(scored.get(name, 0.0), hit.relevance)

    # The model's suggestions may only reorder what evidence already produced.
    # Intersecting rather than unioning is what keeps this advisory: a pivot the
    # structured fields did not yield cannot be introduced here.
    suggested = {
        _normalise(token)
        for suggestion in enrichment.pivot_suggestions
        for token in str(suggestion).replace(",", " ").split()
    }
    for name in list(scored):
        if name in suggested:
            scored[name] += 0.5

    ranked = sorted(scored, key=lambda name: (-scored[name], name))
    return tuple(ranked[:limit])
