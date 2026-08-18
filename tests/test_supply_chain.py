"""Supply-chain posture: the lockfile, the suppression list, and the known checkpoint risk.

These do not reach the network. They assert the *arrangement* is intact -- that the
lockfile matches the manifest, that no vulnerability is suppressed without a written
reachability argument, and that the one known-reachable finding is still described
accurately. A suppression list nobody checks is how a scanner becomes decoration.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LOCKFILE = ROOT / "requirements.lock"
MANIFEST = ROOT / "requirements.txt"
IGNORE_FILE = ROOT / ".pip-audit-ignore"
JUSTIFICATION = ROOT / "docs" / "DEPENDENCY_EXCEPTIONS.md"

#: Reachable in this codebase, deliberately NOT suppressed. See the justification doc.
CHECKPOINT_RCE_IDS = ("PYSEC-2026-1527", "PYSEC-2026-2573", "PYSEC-2026-83")


def _suppressed_ids() -> list[str]:
    ids: list[str] = []
    for raw in IGNORE_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            ids.append(line)
    return ids


class TestLockfile:
    def test_lockfile_exists(self):
        assert LOCKFILE.exists(), "run `make lock` -- the image installs from the lockfile"

    def test_every_pin_carries_hashes(self):
        """--require-hashes is only meaningful if the hashes are actually there."""
        text = LOCKFILE.read_text(encoding="utf-8")
        pinned = [line for line in text.splitlines() if "==" in line and not line.startswith("#")]
        assert len(pinned) > 50, "lockfile looks truncated"
        assert text.count("--hash=sha256:") >= len(pinned)

    def test_every_direct_dependency_is_locked(self):
        """A manifest entry missing from the lock would install unpinned."""
        manifest_names = {
            line.split(">=")[0].split("==")[0].split("[")[0].strip().lower()
            for line in MANIFEST.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
        locked = LOCKFILE.read_text(encoding="utf-8").lower()
        missing = [name for name in manifest_names if f"\n{name}==" not in f"\n{locked}"]
        assert not missing, f"declared but not locked: {missing}"

    def test_dockerfile_installs_from_the_lock_with_hash_checking(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "--require-hashes" in dockerfile
        assert "requirements.lock" in dockerfile


class TestSuppressions:
    def test_every_suppression_is_justified(self):
        """No id may be suppressed without a reachability argument in the doc."""
        text = JUSTIFICATION.read_text(encoding="utf-8")
        unjustified = [vuln_id for vuln_id in _suppressed_ids() if vuln_id not in text]
        assert not unjustified, f"suppressed with no written justification: {unjustified}"

    @pytest.mark.parametrize("vuln_id", CHECKPOINT_RCE_IDS)
    def test_reachable_checkpoint_rce_is_not_suppressed(self, vuln_id: str):
        """The one finding with a live call site must stay visible.

        This system persists checkpoints with SqliteSaver and reloads them in a
        different process every time an analyst answers the approval gate, so
        the deserialization path is genuinely reached. Suppressing it to get a
        green build is the exact failure this file exists to prevent.
        """
        assert vuln_id not in _suppressed_ids()

    def test_the_accepted_risk_is_documented(self):
        text = JUSTIFICATION.read_text(encoding="utf-8")
        assert "Accepted risk" in text
        for vuln_id in CHECKPOINT_RCE_IDS:
            assert vuln_id in text


class TestCheckpointDeserialisation:
    """Pin the behaviour the accepted-risk entry describes.

    If a dependency bump changes either of these, the justification document is
    stale and must be re-argued -- which is the point of asserting them.
    """

    def test_constructor_revival_is_still_reachable_from_written_bytes(self):
        """Confirms the risk entry is still accurate. Benign target only."""
        from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

        payload = {
            "value": {
                "lc": 2,
                "type": "constructor",
                "id": ["datetime", "date"],
                "kwargs": {"year": 2026, "month": 1, "day": 1},
            }
        }
        revived = JsonPlusSerializer().loads_typed(("json", json.dumps(payload).encode()))

        import datetime

        if isinstance(revived.get("value"), datetime.date):
            pytest.xfail(
                "Constructor revival still reachable from written checkpoint bytes "
                "(PYSEC-2026-1527). Expected until langgraph-checkpoint >= 4.1.1; see "
                "docs/DEPENDENCY_EXCEPTIONS.md."
            )
        # Reaching here means an upgrade closed it -- update the justification doc.
        assert isinstance(revived.get("value"), dict)

    def test_alert_content_alone_cannot_reach_it(self):
        """The documented non-path: surrogates raise rather than falling back to JSON.

        If this ever stops raising, hostile alert content could steer the
        serializer into the vulnerable mode and the risk assessment changes
        materially.
        """
        from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

        with pytest.raises(TypeError, match="surrogate"):
            JsonPlusSerializer().dumps_typed({"note": "trigger \ud800"})
