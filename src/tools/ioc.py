"""``enrich_ioc`` -- indicator reputation lookup against a local intel corpus.

Deliberately **offline**.  A tool that took an arbitrary indicator and made a
network request would be an SSRF primitive an injected agent could aim at
internal services, and would leak the organisation's indicators to a third
party.  The lookup here reads a local, curated JSON corpus.

The strict per-type format validation is not cosmetic: it means the tool can
only ever be handed something shaped like an indicator, so there is no
smuggling of URLs or paths through the ``indicator`` argument.
"""

from __future__ import annotations

import ipaddress
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

from src.enums import ActionRisk, IndicatorType
from src.tools.base import SOCTool

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)
_EMAIL_RE = re.compile(r"^[a-z0-9._%+-]{1,64}@(?=.{1,253}$)[a-z0-9.-]+\.[a-z]{2,}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_MD5_RE = re.compile(r"^[a-f0-9]{32}$")
_URL_RE = re.compile(r"^https?://[a-z0-9.-]+(:\d{1,5})?(/[^\s]*)?$")


class EnrichIOCInput(BaseModel):
    """Input schema for ``enrich_ioc``, with per-type format enforcement."""

    indicator: str = Field(min_length=3, max_length=512)
    indicator_type: IndicatorType

    @model_validator(mode="after")
    def _validate_format(self) -> EnrichIOCInput:
        value = self.indicator.strip().lower()

        if self.indicator_type is IndicatorType.IPV4:
            try:
                ipaddress.IPv4Address(value)
            except ValueError as exc:
                raise ValueError(f"'{value}' is not a valid IPv4 address") from exc
        elif self.indicator_type is IndicatorType.DOMAIN:
            if not _DOMAIN_RE.match(value):
                raise ValueError(f"'{value}' is not a valid domain name")
        elif self.indicator_type is IndicatorType.URL:
            if not _URL_RE.match(value):
                raise ValueError("URL must be http(s) and well formed")
        elif self.indicator_type is IndicatorType.SHA256:
            if not _SHA256_RE.match(value):
                raise ValueError("SHA-256 must be exactly 64 hexadecimal characters")
        elif self.indicator_type is IndicatorType.MD5:
            if not _MD5_RE.match(value):
                raise ValueError("MD5 must be exactly 32 hexadecimal characters")
        elif self.indicator_type is IndicatorType.EMAIL:
            if not _EMAIL_RE.match(value):
                raise ValueError(f"'{value}' is not a valid email address")

        # Normalise so lookups are case-insensitive and whitespace-tolerant.
        object.__setattr__(self, "indicator", value)
        return self


@lru_cache(maxsize=1)
def _load_intel(path_str: str) -> dict[str, dict[str, Any]]:
    """Load and index the local intel corpus by indicator value."""
    path = Path(path_str)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return {
        str(record["indicator"]).lower(): record
        for record in raw.get("indicators", [])
        if record.get("indicator")
    }


def _intel_path() -> str:
    from src.config import get_settings

    return str(get_settings().intel_path)


def enrich_ioc(payload: EnrichIOCInput) -> dict[str, Any]:
    """Look up reputation and context for a single indicator."""
    corpus = _load_intel(_intel_path())
    record = corpus.get(payload.indicator)

    if record is None:
        # An unknown indicator is a real, useful answer -- not an error.  It is
        # reported as unknown rather than benign: absence of evidence is not
        # evidence of absence, and conflating the two is how analysts get burned.
        return {
            "indicator": payload.indicator,
            "indicator_type": payload.indicator_type.value,
            "found": False,
            "known_malicious": False,
            "reputation_score": 0,
            "threat_names": [],
            "sources": [],
            "notes": (
                "No record in the local intelligence corpus. Treat as UNKNOWN, not benign: "
                "this corpus has limited coverage."
            ),
        }

    return {
        "indicator": payload.indicator,
        "indicator_type": payload.indicator_type.value,
        "found": True,
        "known_malicious": bool(record.get("known_malicious", False)),
        "reputation_score": int(record.get("reputation_score", 0)),
        "threat_names": list(record.get("threat_names", [])),
        "first_seen": record.get("first_seen"),
        "last_seen": record.get("last_seen"),
        "sources": list(record.get("sources", [])),
        "notes": str(record.get("notes", "")),
    }


ENRICH_IOC_TOOL = SOCTool(
    name="enrich_ioc",
    description=(
        "Look up reputation, threat names and sighting dates for a single indicator "
        "(ipv4, domain, url, sha256, md5, email) in the local intelligence corpus. "
        "Offline and read-only: makes no network requests."
    ),
    input_model=EnrichIOCInput,
    handler=enrich_ioc,
    risk=ActionRisk.READ_ONLY,
    returns_untrusted=True,
)
