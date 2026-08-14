"""Alert ingestion.

The trust boundary of the whole system is here: everything downstream treats
alert content as attacker-influenced, and this is where that content is first
parsed and validated.  Parsing happens through the strict
:class:`~src.state.SecurityAlert` model, so a malformed or hostile payload is
rejected with a clear error rather than propagating half-valid data into the
graph.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from src.state import SecurityAlert


class AlertIngestError(ValueError):
    """Raised when an alert payload cannot be parsed into a valid alert."""


#: Refuse absurdly large payloads outright rather than parsing them.
MAX_ALERT_BYTES = 512 * 1024


def parse_alert(payload: dict) -> SecurityAlert:
    """Validate a raw alert dictionary."""
    try:
        return SecurityAlert.model_validate(payload)
    except ValidationError as exc:
        raise AlertIngestError(
            f"alert failed schema validation with {exc.error_count()} error(s): "
            + "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]
            )
        ) from exc


def load_alert_file(path: Path) -> SecurityAlert:
    """Load and validate a single alert from a JSON file."""
    path = Path(path)
    if not path.exists():
        raise AlertIngestError(f"alert file not found: {path}")

    size = path.stat().st_size
    if size > MAX_ALERT_BYTES:
        raise AlertIngestError(f"alert file is {size} bytes, exceeding the {MAX_ALERT_BYTES} byte limit")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AlertIngestError(f"{path.name} is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise AlertIngestError(f"{path.name} must contain a JSON object, got {type(payload).__name__}")

    return parse_alert(payload)


def list_sample_alerts() -> list[Path]:
    """Every bundled sample alert, sorted by filename."""
    from src.config import get_settings

    directory = get_settings().sample_alerts_dir
    if not directory.exists():
        return []
    return sorted(directory.glob("*.json"))


def resolve_alert(reference: str) -> SecurityAlert:
    """Resolve an alert from a path, a filename, or a bare sample name.

    Accepts ``data/sample_alerts/alert-001-ransomware.json``,
    ``alert-001-ransomware.json`` or ``alert-001-ransomware``.
    """
    candidate = Path(reference)
    if candidate.exists():
        return load_alert_file(candidate)

    from src.config import get_settings

    directory = get_settings().sample_alerts_dir
    for name in (reference, f"{reference}.json"):
        path = directory / name
        if path.exists():
            return load_alert_file(path)

    # Last resort: prefix match against the sample set.
    matches = [p for p in list_sample_alerts() if p.stem.startswith(reference)]
    if len(matches) == 1:
        return load_alert_file(matches[0])
    if len(matches) > 1:
        raise AlertIngestError(
            f"'{reference}' is ambiguous; matches: {', '.join(p.stem for p in matches)}"
        )

    available = ", ".join(p.stem for p in list_sample_alerts()) or "(none found)"
    raise AlertIngestError(f"could not resolve alert '{reference}'. Available samples: {available}")
