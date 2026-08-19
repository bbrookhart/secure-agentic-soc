"""``lookup_mitre`` -- offline MITRE ATT&CK technique lookup.

Backed by a curated local subset of the Enterprise matrix (see
``data/mitre/attack_knowledge.json``).  Two lookup modes:

* exact technique ID (``T1486``, ``T1003.001``) -- used when triage already has
  a candidate to verify;
* keyword search over name, description and curated keyword lists -- used when
  the hunter is exploring.

Keeping this offline matters for the same reason as ``enrich_ioc``: the tool
cannot be turned into an outbound request primitive, and technique lookups do
not disclose what the SOC is currently investigating.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from src.enums import ActionRisk
from src.tools.base import SOCTool
from src.tools.matching import matches

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9.-]*")


class LookupMitreInput(BaseModel):
    """Input schema for ``lookup_mitre``."""

    query: str = Field(
        min_length=2,
        max_length=512,
        description="A technique ID (e.g. 'T1486') or free-text keywords (e.g. 'shadow copy deletion').",
    )
    limit: int = Field(default=5, ge=1, le=10)

    @field_validator("query")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("query must not be blank")
        return value.strip()


@lru_cache(maxsize=1)
def _load_knowledge(path_str: str) -> list[dict[str, Any]]:
    path = Path(path_str)
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return list(raw.get("techniques", []))


def _knowledge_path() -> str:
    from src.config import get_settings

    return str(get_settings().mitre_path)


def _format(technique: dict[str, Any], confidence: float, rationale: str) -> dict[str, Any]:
    technique_id = technique["technique_id"]
    base, _, sub = technique_id.partition(".")
    path = f"{base}/{sub}" if sub else base
    return {
        "technique_id": technique_id,
        "name": technique["name"],
        "tactic": technique["tactic"],
        "description": technique.get("description", ""),
        "detection": technique.get("detection", ""),
        "mitigations": list(technique.get("mitigations", [])),
        "url": f"https://attack.mitre.org/techniques/{path}/",
        "confidence": round(confidence, 2),
        "rationale": rationale,
    }


def lookup_mitre(payload: LookupMitreInput) -> dict[str, Any]:
    """Resolve a technique ID or keyword query to ATT&CK techniques."""
    techniques = _load_knowledge(_knowledge_path())
    if not techniques:
        return {"query": payload.query, "match_type": "none", "results": [],
                "note": "Local ATT&CK knowledge base is unavailable."}

    query = payload.query.strip()

    # --- Exact technique ID ----------------------------------------------
    if _TECHNIQUE_ID_RE.match(query):
        target = query.upper()
        for technique in techniques:
            if technique["technique_id"].upper() == target:
                return {
                    "query": query,
                    "match_type": "exact_id",
                    "results": [_format(technique, 0.95, f"Exact match on technique ID {target}.")],
                }
        return {
            "query": query,
            "match_type": "exact_id_not_found",
            "results": [],
            "note": (
                f"{target} is not present in this curated ATT&CK subset. "
                "Absence here does not mean the technique is wrong."
            ),
        }

    # --- Keyword search ---------------------------------------------------
    query_terms = set(_WORD_RE.findall(query.lower()))
    if not query_terms:
        return {"query": query, "match_type": "keyword", "results": []}

    #: (score, technique, rationale, matched_a_curated_phrase, distinct_matched_terms)
    scored: list[tuple[float, dict[str, Any], str, bool, set[str]]] = []
    for technique in techniques:
        keywords = [str(k).lower() for k in technique.get("keywords", [])]
        name = str(technique.get("name", "")).lower()
        description = str(technique.get("description", "")).lower()

        score = 0.0
        hits: list[str] = []
        # Which distinct query terms actually carried the match, and whether a
        # curated multi-word phrase matched outright.  The score alone cannot
        # answer "how many independent reasons are there to believe this",
        # because one common word can earn points through several channels.
        matched_terms: set[str] = set()
        phrase_match = False

        # Curated keyword phrases are the strongest signal.
        lowered = query.lower()
        weak_terms: set[str] = set()
        for keyword in keywords:
            if matches(lowered, keyword):
                score += 3.0
                hits.append(keyword)
                phrase_match = True
            else:
                weak_terms |= set(_WORD_RE.findall(keyword)) & query_terms

        # Scored once per *distinct* query term, not once per keyword that
        # happens to contain it. Otherwise a technique's score rises simply
        # because its keyword list repeats a common word: adding the synonym
        # "port sweep" alongside "port scan" doubled T1018's score for every
        # alert mentioning a port, and pushed it into an unrelated C2 alert's
        # results. Curated lists are meant to be extended, so extending one
        # must not silently re-weight it.
        score += 1.0 * len(weak_terms)
        matched_terms |= weak_terms

        name_terms = set(_WORD_RE.findall(name))
        overlap = query_terms & name_terms
        score += 2.0 * len(overlap)
        hits.extend(sorted(overlap))
        matched_terms |= overlap

        description_terms = set(_WORD_RE.findall(description))
        score += 0.5 * len(query_terms & description_terms)

        if score > 0:
            rationale = (
                f"Matched on: {', '.join(sorted(set(hits))[:5])}."
                if hits
                else "Weak description-level term overlap."
            )
            scored.append((score, technique, rationale, phrase_match, matched_terms))

    # Relevance floor.  A mapping must rest on either a curated multi-word
    # phrase, or at least two *distinct* query terms.
    #
    # The score threshold alone was not enough, and the failure was not
    # theoretical: a benign red-team alert titled "Credential dumping tool
    # executed on WKS-9001" mapped to T1105 "Ingress Tool Transfer" on the
    # single word "tool", and any technique with "access" in its name mapped to
    # anything in the credential_access category on the single word "access".
    # Both landed at exactly 3.0, because one common word can score twice --
    # once through a keyword's word overlap and once through the name's.
    #
    # Counting distinct terms instead closes that: one generic word is one
    # reason, however many ways it earns points.  This matters more as the
    # corpus grows, since every technique added is another chance to collide,
    # and a spurious technique in a report reads as confirmed tradecraft.
    scored = [
        item for item in scored if item[0] >= 3.0 and (item[3] or len(item[4]) >= 2)
    ]

    scored.sort(key=lambda item: item[0], reverse=True)
    top = scored[: payload.limit]

    if not top:
        return {
            "query": query,
            "match_type": "keyword",
            "results": [],
            "note": "No technique in the curated subset matched these keywords.",
        }

    best = top[0][0]
    results = [
        # Normalise the top score to 0.9 and scale the rest relative to it, so
        # confidence reflects *relative* match strength rather than raw points.
        _format(technique, min(0.9, 0.35 + 0.55 * (score / best)), rationale)
        for score, technique, rationale, _phrase, _terms in top
    ]

    return {"query": query, "match_type": "keyword", "results": results}


LOOKUP_MITRE_TOOL = SOCTool(
    name="lookup_mitre",
    description=(
        "Look up MITRE ATT&CK techniques by exact technique ID (e.g. 'T1486') or by "
        "keywords (e.g. 'shadow copy deletion'). Returns technique name, tactic, "
        "description, detection guidance and mitigations. Offline and read-only."
    ),
    input_model=LookupMitreInput,
    handler=lookup_mitre,
    risk=ActionRisk.READ_ONLY,
    # The knowledge base is ours, but the echoed query is agent/attacker text.
    returns_untrusted=True,
)
