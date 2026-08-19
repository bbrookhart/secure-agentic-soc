"""Normalising model output onto our vocabulary, without widening it.

Models do not share our casing conventions. ``qwen3:8b`` answers ``"Critical"``
where :class:`~src.enums.Severity` expects ``"critical"``, and ``"True Positive"``
where :class:`~src.enums.Verdict` expects ``"true_positive"``. Every model-facing
enum was case-sensitive, so those answers failed validation, the retry chain
burned another call, and the run fell through to the deterministic rule-based
floor.

That failure was **silent and expensive**: the analysis was correct, we threw it
away, and the run recorded only ``used_llm=False``. Adopting a stronger model
would have made results worse while taking five to ten times longer, and nothing
would have said so.

The fix is narrow on purpose. This module normalises **presentation** -- case,
surrounding whitespace, and the separator between words -- and nothing else:

* ``"Critical"``, ``"CRITICAL"`` and ``" critical "`` all become ``critical``.
* ``"True Positive"`` and ``"true-positive"`` become ``true_positive``.
* ``"probably malware"``, ``"sev:high"`` and ``"unknown-ish"`` are still
  **rejected**.

That last line is the point. This is a trust boundary: relaxing it to guess at
near-misses would let a confused or manipulated model steer a value it never
actually produced, and the deterministic fallback is the correct outcome for a
model that did not answer the question. Normalising how a value is *written* is
not the same as deciding what it *means*.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, TypeVar

E = TypeVar("E", bound=Enum)

#: Characters models substitute for the underscore in a multi-word value.
_SEPARATORS = re.compile(r"[\s\-]+")


def normalise_enum_value(value: Any) -> Any:
    """Fold presentation differences. Non-strings pass through untouched.

    Enum members pass through too. Our enums subclass ``str``, so without this
    an already-correct member would be flattened back into a bare string.
    """
    if isinstance(value, Enum) or not isinstance(value, str):
        return value
    cleaned = _SEPARATORS.sub("_", value.strip()).lower()
    # Collapse repeats introduced by mixed separators ("true - positive").
    return re.sub(r"_+", "_", cleaned).strip("_")


def coerce_enum(enum_type: type[E], value: Any) -> Any:
    """Match ``value`` against ``enum_type`` after normalising presentation.

    Returns the enum member on an exact post-normalisation match, and otherwise
    returns the original value unchanged so Pydantic raises its own validation
    error. Deliberately no fuzzy matching, no prefix matching, no synonyms: a
    value we do not recognise is one the model did not produce.
    """
    if isinstance(value, enum_type):
        return value

    candidate = normalise_enum_value(value)
    if not isinstance(candidate, str):
        return value

    for member in enum_type:
        if str(member.value).lower() == candidate:
            return member
    return value


def enum_coercer(enum_type: type[E], *, unknown: E | None = None) -> Any:
    """A Pydantic ``mode="before"`` validator function for one enum field.

    ``unknown`` supplies a fallback member for fields where "we could not
    determine this" is a legitimate answer. Use it **only** where that is true,
    and the asymmetry is deliberate:

    * ``category`` gets a fallback. Models reach for reasonable words our
      vocabulary lacks -- ``llama3.2`` answered ``"unclassified"`` where the enum
      says ``"unknown"`` -- and mapping an unrecognised category onto *"not
      determined"* claims nothing. Category also holds no authority: the
      approval gate turns on severity, confidence, asset criticality and
      injection flags, never on this.
    * ``severity`` gets none, ever. It drives the gate, so an unrecognised value
      must fail the whole assessment and fall to the deterministic classifier --
      which produces its own severity from rules. Defaulting it would be
      inventing a verdict, and a quiet one.
    """

    def _coerce(value: Any) -> Any:
        coerced = coerce_enum(enum_type, value)
        if unknown is not None and not isinstance(coerced, enum_type):
            return unknown
        return coerced

    return _coerce
