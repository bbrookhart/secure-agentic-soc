"""Keyword matching shared by the classifier and the ATT&CK lookup.

Both used plain substring containment (``term in text``), which matches a
keyword anywhere inside a longer word. That is not a hypothetical problem:
measured across the eval corpus, ``"lure"`` matched inside **"failure"** on two
cases, and ``"sam"`` (a credential-dumping keyword) matches inside "same".
Neither alert had anything to do with the technique it was being scored for.

The naive fix -- requiring a word boundary on both sides -- is worse, because
security keyword lists are written as stems on purpose. ``"encrypt"`` is meant
to match "encrypting" and "encryption"; ``"scan"`` is meant to match "scanner";
``"quarantine"`` is meant to match "quarantined". Demanding a trailing boundary
would throw all of those away.

So the rule is a **leading** word boundary with suffix tolerance: a keyword must
start where a word starts, and may run into the rest of it. "encrypt" still
matches "encrypting"; "lure" no longer matches "failure", because there the
match would have to begin mid-word.

Short keywords are the exception. A three-character fragment allowed to match
any word beginning with it is a coin toss, so terms under
``_STRICT_BELOW_LENGTH`` characters must match as whole words.
"""

from __future__ import annotations

import re
from functools import lru_cache

#: Terms shorter than this must match as complete words. Keyword lists contain
#: genuinely short entries -- "c$", "rdp", "smb", "sam", "gb" -- and those are
#: exactly the ones that collide with ordinary English when allowed to prefix.
_STRICT_BELOW_LENGTH = 4


@lru_cache(maxsize=2048)
def _pattern(term: str) -> re.Pattern[str]:
    """Compile the match rule for one keyword.

    Cached because the classifier scores every alert against a few hundred
    fixed terms, and recompiling them per alert is pure waste.
    """
    escaped = re.escape(term)

    # A boundary always excludes letters. It excludes *digits* only when the
    # term's own edge is a digit, which keeps two different cases right at once:
    # "gb" must match "41GB" (a unit follows a number, and that is a real token
    # boundary in log text), while the port keyword "445" must not match inside
    # "14450".
    lead = r"(?<![a-z])" + (r"(?<![0-9])" if term[0].isdigit() else "")
    trail = r"(?![a-z])" + (r"(?![0-9])" if term[-1].isdigit() else "")

    if len(term) < _STRICT_BELOW_LENGTH:
        # Whole word only.
        return re.compile(lead + escaped + trail)
    # Leading boundary, trailing suffix permitted.
    return re.compile(lead + escaped)


def matches(text: str, term: str) -> bool:
    """Whether ``term`` occurs in ``text`` as a word or a word's stem.

    ``text`` is expected to be lower-cased already; callers all normalise
    before scoring, and doing it again per term would be measurable.
    """
    if not term:
        return False
    return _pattern(term).search(text) is not None


def score_terms(text: str, signals: dict[str, float]) -> tuple[float, list[str]]:
    """Sum the weights of every keyword that matches, and report which did."""
    total = 0.0
    matched: list[str] = []
    for term, weight in signals.items():
        if matches(text, term):
            total += weight
            matched.append(term)
    return total, matched
