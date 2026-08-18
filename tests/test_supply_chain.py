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
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
LOCKFILE = ROOT / "requirements.lock"
MANIFEST = ROOT / "requirements.txt"
IGNORE_FILE = ROOT / ".pip-audit-ignore"
JUSTIFICATION = ROOT / "docs" / "DEPENDENCY_EXCEPTIONS.md"

#: The checkpoint-deserialisation advisories. Resolved by upgrading; the version
#: floors and the msgpack allowlist below are what keep them resolved.
CHECKPOINT_RCE_IDS = ("PYSEC-2026-1527", "PYSEC-2026-2573", "PYSEC-2026-83")


class FakeCheckpointPayload(BaseModel):
    """A model defined outside the allowlisted modules, standing in for whatever
    an attacker would name in a crafted checkpoint payload."""

    marker: str


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
    def test_checkpoint_rce_is_never_suppressed(self, vuln_id: str):
        """These were reachable here and are fixed by version floor, not by silence.

        Suppressing one to get a green build after a future downgrade is the
        exact failure this arrangement exists to prevent.
        """
        assert vuln_id not in _suppressed_ids()

    def test_the_resolution_is_recorded(self):
        """The reasoning outlives the finding; a future reviewer needs it."""
        text = JUSTIFICATION.read_text(encoding="utf-8")
        for vuln_id in CHECKPOINT_RCE_IDS:
            assert vuln_id in text
        assert "allowed_msgpack_modules" in text, (
            "the msgpack allowlist is half the fix and must stay documented"
        )


class TestCheckpointDeserialisation:
    """The checkpoint store is integrity-sensitive; assert the fix that makes it so.

    PYSEC-2026-1527 / 2573 / 83 were reachable here because this system persists
    checkpoints and reloads them in a fresh process on every approval. The fix in
    langgraph-checkpoint >= 4.1.1 is an allowlist: safe types are still
    reconstructed, dangerous ones are not.

    So the property under test is not "nothing is revived" -- reviving a
    ``datetime`` is intended behaviour the framework relies on. It is that a
    payload naming an execution primitive comes back as inert data. These run
    against written bytes, which is the attacker position the advisory describes.
    """

    @pytest.mark.parametrize(
        ("target", "kwargs"),
        [
            (["os", "system"], {"command": "true"}),
            (["subprocess", "run"], {"args": ["true"]}),
            (["builtins", "eval"], {"source": "1"}),
            (["builtins", "exec"], {"source": "pass"}),
        ],
    )
    def test_execution_primitives_are_not_revived(self, target: list[str], kwargs: dict):
        """The RCE itself: a constructor payload naming os.system must stay a dict."""
        from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

        payload = {"value": {"lc": 2, "type": "constructor", "id": target, "kwargs": kwargs}}
        revived = JsonPlusSerializer().loads_typed(("json", json.dumps(payload).encode()))

        assert isinstance(revived.get("value"), dict), (
            f"{'.'.join(target)} was reconstructed from checkpoint bytes -- "
            "the allowlist is not in effect (see docs/DEPENDENCY_EXCEPTIONS.md)"
        )

    def test_safe_types_still_revive(self):
        """Guards against 'fixing' this by breaking checkpointing.

        A change that stopped reviving datetimes would pass the test above while
        quietly breaking every resumed run, so the intended behaviour is pinned too.
        """
        import datetime

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
        assert revived.get("value") == datetime.date(2026, 1, 1)

    def test_msgpack_allowlist_covers_the_state_vocabulary(self):
        """Everything checkpointed must be loadable, or resumed runs break."""
        from src.graph import checkpoint_allowlist

        allowed = set(checkpoint_allowlist())
        for entry in (
            ("src.state", "SecurityAlert"),
            ("src.state", "TriageResult"),
            ("src.state", "EnrichmentResults"),
            ("src.state", "IncidentReport"),
            ("src.state", "ApprovalDecision"),
            ("src.security.audit", "AuditEvent"),
            ("src.enums", "Severity"),
        ):
            assert entry in allowed, f"{entry} is checkpointed but not allowlisted"

    def test_msgpack_allowlist_admits_nothing_outside_this_project(self):
        """The allowlist is the msgpack half of the fix; it must not widen."""
        from src.graph import checkpoint_allowlist

        modules = {module for module, _ in checkpoint_allowlist()}
        assert modules <= {"src.state", "src.enums", "src.security.audit"}

    def test_restricted_serialiser_refuses_types_outside_the_allowlist(self):
        """The msgpack half of the fix, tested as behaviour rather than config.

        Models the real attacker position: bytes written by something permissive
        are loaded by our restricted configuration. A type from outside the three
        allowed modules must not be reconstructed.
        """
        from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

        from src.graph import _serializer

        # A class from a module the allowlist does not cover.
        payload = {"value": FakeCheckpointPayload(marker="reconstructed")}

        permissive = JsonPlusSerializer(allowed_msgpack_modules=True)
        written = permissive.dumps_typed(payload)

        loaded = _serializer().loads_typed(written)
        assert not isinstance(loaded.get("value"), FakeCheckpointPayload), (
            "a type outside src.state / src.enums / src.security.audit was "
            "reconstructed from checkpoint bytes"
        )

    def test_restricted_serialiser_still_round_trips_our_own_state(self):
        """Blocking everything would pass the test above and break every resume."""
        from src.enums import Severity
        from src.graph import _serializer

        serde = _serializer()
        restored = serde.loads_typed(serde.dumps_typed({"severity": Severity.HIGH}))
        assert restored["severity"] is Severity.HIGH

    def test_both_checkpointers_use_the_restricted_serialiser(self, tmp_path: Path):
        from src.graph import build_checkpointer, build_memory_checkpointer

        for saver in (build_memory_checkpointer(), build_checkpointer(tmp_path / "cp.sqlite")):
            serde = saver.serde
            restored = serde.loads_typed(serde.dumps_typed({"v": FakeCheckpointPayload(marker="x")}))
            assert not isinstance(restored.get("v"), FakeCheckpointPayload), (
                f"{type(saver).__name__} is using the permissive default serialiser"
            )

    def test_checkpoint_stack_is_at_or_above_the_fixed_versions(self):
        """The floors in requirements.txt are set by these advisories, not by taste."""
        from importlib.metadata import version

        for package, minimum in (
            ("langgraph", (1, 0, 10)),
            ("langgraph-checkpoint", (4, 1, 1)),
            ("langgraph-checkpoint-sqlite", (3, 1, 1)),
        ):
            installed = tuple(int(part) for part in version(package).split(".")[:3])
            assert installed >= minimum, (
                f"{package} {version(package)} is below the security floor {minimum}"
            )
