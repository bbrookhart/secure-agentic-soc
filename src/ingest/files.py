"""File-backed alert ingestion: the bundled samples and arbitrary JSON files."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from src.ingest.base import MAX_ALERT_BYTES, AlertIngestError, parse_alert
from src.state import SecurityAlert


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


class DirectorySource:
    """Watch a directory for alert files, newest first.

    Position is tracked by filename, so a file rewritten in place is not
    re-emitted. That is the conservative choice: re-running an investigation on
    edited evidence is worse than skipping it, and the edit is visible on disk.
    """

    name = "directory"

    def __init__(self, directory: Path, *, pattern: str = "*.json") -> None:
        self.directory = Path(directory)
        self.pattern = pattern
        self._seen: set[str] = set()

    def poll(self, *, limit: int = 50) -> Iterator[SecurityAlert]:
        if not self.directory.exists():
            return

        paths = sorted(
            self.directory.glob(self.pattern),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        emitted = 0
        for path in paths:
            if emitted >= limit:
                return
            if path.name in self._seen:
                continue
            self._seen.add(path.name)
            try:
                yield load_alert_file(path)
                emitted += 1
            except AlertIngestError:
                # A malformed file is skipped, not fatal: one bad alert must not
                # stop the queue. It stays on disk for a human to look at.
                continue
