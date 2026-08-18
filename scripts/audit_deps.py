#!/usr/bin/env python3
"""Run pip-audit against the lockfile, honouring the documented suppressions.

A thin wrapper, for one reason: the suppression list and the justification
document must not drift apart. `.pip-audit-ignore` is the single source of
truth, this script reads it, and `make audit-deps` and CI both go through here.
An ID suppressed on a command line somewhere would be a suppression nobody
argued for.

Exit codes: 0 clean, 1 findings, 2 could not run.
"""

from __future__ import annotations

import subprocess  # noqa: S404 - invoking the pinned scanner is this script's job
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IGNORE_FILE = ROOT / ".pip-audit-ignore"
LOCKFILE = ROOT / "requirements.lock"
JUSTIFICATION = ROOT / "docs" / "DEPENDENCY_EXCEPTIONS.md"


def read_suppressions() -> list[str]:
    """Vulnerability ids to ignore, from the documented list."""
    if not IGNORE_FILE.exists():
        return []
    ids: list[str] = []
    for raw in IGNORE_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            ids.append(line)
    return ids


def check_justified(ids: list[str]) -> list[str]:
    """Return suppressed ids that are not mentioned in the justification doc.

    A suppression that nobody wrote a reachability argument for is exactly the
    thing this whole arrangement exists to prevent, so it is treated as a
    failure rather than a warning.
    """
    if not JUSTIFICATION.exists():
        return ids
    text = JUSTIFICATION.read_text(encoding="utf-8")
    return [vuln_id for vuln_id in ids if vuln_id not in text]


def main() -> int:
    if not LOCKFILE.exists():
        print(f"lockfile not found: {LOCKFILE} (run `make lock`)", file=sys.stderr)
        return 2

    suppressed = read_suppressions()
    unjustified = check_justified(suppressed)
    if unjustified:
        print(
            "Suppressed without a written justification: "
            + ", ".join(unjustified)
            + f"\nEvery id in {IGNORE_FILE.name} needs a reachability argument in "
            f"{JUSTIFICATION.relative_to(ROOT)}.",
            file=sys.stderr,
        )
        return 2

    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "--strict",
        "--desc",
        "--requirement",
        str(LOCKFILE),
    ]
    for vuln_id in suppressed:
        command += ["--ignore-vuln", vuln_id]

    if suppressed:
        print(
            f"{len(suppressed)} finding(s) suppressed with justification "
            f"(see {JUSTIFICATION.relative_to(ROOT)}).\n"
        )

    return subprocess.call(command)  # noqa: S603 - fixed argv, no shell


if __name__ == "__main__":
    raise SystemExit(main())
