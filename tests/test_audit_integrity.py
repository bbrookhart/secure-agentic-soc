"""Audit signing, anchoring, rotation and retention.

The chain proves internal consistency. These cover what it cannot: that records
came from this deployment's key, that a rewrite has something off-host to
disagree with, and that bounding disk use does not quietly break verification.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from src.enums import AgentRole, AuditAction
from src.security.audit import AuditEvent, AuditLogger, verify_chain
from src.security.audit_sink import JsonlSink
from src.security.signing import (
    Ed25519Signer,
    NullSigner,
    public_key_fingerprint,
    verify_signature,
)


def _record(logger: AuditLogger, thread_id: str = "t1", summary: str = "event"):
    return logger.record(
        thread_id=thread_id,
        actor=AgentRole.SUPERVISOR,
        action=AuditAction.ROUTING_DECISION,
        summary=summary,
    )


@pytest.fixture
def signer(tmp_path: Path) -> Ed25519Signer:
    return Ed25519Signer(tmp_path / "signing-key.pem")


class TestSigningKey:
    def test_key_is_generated_owner_only(self, tmp_path: Path):
        """A signing key others can read is a signing key they hold."""
        signer = Ed25519Signer(tmp_path / "k.pem")
        assert signer.created
        mode = (tmp_path / "k.pem").stat().st_mode
        assert mode & 0o077 == 0, f"key is readable beyond its owner: {oct(mode)}"

    def test_key_is_reused_not_regenerated(self, tmp_path: Path):
        first = Ed25519Signer(tmp_path / "k.pem")
        second = Ed25519Signer(tmp_path / "k.pem")
        assert not second.created
        assert first.key_id == second.key_id

    def test_missing_key_can_be_required(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            Ed25519Signer(tmp_path / "absent.pem", create_if_missing=False)

    def test_fingerprint_identifies_the_key(self, signer: Ed25519Signer):
        assert signer.key_id.startswith("ed25519:")
        assert signer.key_id == public_key_fingerprint(signer.public_key_pem())


class TestSignedRecords:
    def test_events_are_signed_with_the_key_id_recorded(self, tmp_path: Path, signer):
        logger = AuditLogger(tmp_path / "a.jsonl", signer=signer)
        event = _record(logger)

        assert event.signature
        assert event.signing_key_id == signer.key_id
        assert verify_signature(
            event.event_hash.encode("ascii"), event.signature, signer.public_key_pem()
        )

    def test_verification_needs_only_the_public_key(self, tmp_path: Path, signer):
        """The property that makes a log worth showing to someone who distrusts you."""
        logger = AuditLogger(tmp_path / "a.jsonl", signer=signer)
        for index in range(4):
            _record(logger, summary=f"event {index}")

        ok, message = verify_chain(
            logger.read_events("t1"), public_key_pem=signer.public_key_pem()
        )
        assert ok, message
        assert "4 signatures valid" in message

    def test_a_recomputed_chain_still_fails_signature_verification(self, tmp_path: Path, signer):
        """The gap the threat model names, closed.

        An attacker with code execution can rewrite an event and recompute every
        hash after it, leaving a chain that verifies. Without the signing key
        they cannot re-sign, so the forgery surfaces.
        """
        path = tmp_path / "a.jsonl"
        logger = AuditLogger(path, signer=signer)
        for index in range(5):
            _record(logger, summary=f"event {index}")

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        rows[2]["summary"] = "fabricated"
        previous = rows[2]["prev_hash"]
        for row in rows[2:]:
            row["prev_hash"] = previous
            row["event_hash"] = AuditEvent.model_validate(row).compute_hash()
            previous = row["event_hash"]

        events = [AuditEvent.model_validate(row) for row in rows]

        chain_ok, _ = verify_chain(events)
        assert chain_ok, "the recomputed chain is internally consistent, as expected"

        signed_ok, message = verify_chain(events, public_key_pem=signer.public_key_pem())
        assert not signed_ok
        assert "signature invalid" in message

    def test_a_different_key_does_not_verify(self, tmp_path: Path, signer):
        logger = AuditLogger(tmp_path / "a.jsonl", signer=signer)
        _record(logger)

        other = Ed25519Signer(tmp_path / "other.pem")
        ok, _ = verify_chain(logger.read_events("t1"), public_key_pem=other.public_key_pem())
        assert not ok

    def test_unsigned_logging_still_works(self, tmp_path: Path):
        """Losing signatures must not cost the audit trail itself."""
        logger = AuditLogger(tmp_path / "a.jsonl", signer=NullSigner())
        event = _record(logger)
        assert event.signature == ""
        ok, _ = verify_chain(logger.read_events("t1"))
        assert ok


class TestAnchoring:
    def test_anchor_states_where_the_chain_stood(self, tmp_path: Path, signer):
        logger = AuditLogger(tmp_path / "a.jsonl", signer=signer)
        for _ in range(3):
            _record(logger)

        anchor = logger.anchor("t1")
        assert anchor is not None
        assert anchor.action is AuditAction.AUDIT_ANCHOR
        assert anchor.details["anchored_sequence"] == 2
        assert anchor.signature

    def test_no_anchor_without_signing(self, tmp_path: Path):
        """An unsigned anchor would assert integrity it cannot back."""
        logger = AuditLogger(tmp_path / "a.jsonl", signer=NullSigner())
        _record(logger)
        assert logger.anchor("t1") is None

    def test_no_anchor_for_a_run_with_no_events(self, tmp_path: Path, signer):
        logger = AuditLogger(tmp_path / "a.jsonl", signer=signer)
        assert logger.anchor("never-seen") is None

    def test_anchor_detects_a_rewritten_log(self, tmp_path: Path, signer):
        """The anchor is what survives off-host; compare it with what is left."""
        path = tmp_path / "a.jsonl"
        logger = AuditLogger(path, signer=signer)
        for index in range(4):
            _record(logger, summary=f"event {index}")
        anchor = logger.anchor("t1")
        assert anchor is not None
        forwarded_head = anchor.details["anchored_hash"]

        # Attacker truncates the log and recomputes a shorter, consistent chain.
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        path.write_text("\n".join(json.dumps(row) for row in rows[:2]) + "\n", encoding="utf-8")

        surviving = AuditLogger(path).read_events("t1")
        local_head = max(surviving, key=lambda e: e.sequence).event_hash
        assert local_head != forwarded_head, (
            "a truncated log must diverge from the anchor that already left the host"
        )


class TestRotationAndRetention:
    def test_rotation_creates_segments(self, tmp_path: Path):
        path = tmp_path / "a.jsonl"
        logger = AuditLogger(path, sink=JsonlSink(path, durable=False, max_bytes=800))
        for index in range(40):
            _record(logger, summary=f"event {index}")

        assert (tmp_path / "a.jsonl.1").exists(), "log never rotated"

    def test_the_chain_still_verifies_across_segments(self, tmp_path: Path, signer):
        """Rotation must not look like a truncated chain.

        Sized so rotation happens several times but retention discards nothing --
        the two behaviours are separable and this test is about the first.
        """
        path = tmp_path / "a.jsonl"
        logger = AuditLogger(
            path,
            sink=JsonlSink(path, durable=False, max_bytes=4000, max_segments=50),
            signer=signer,
        )
        for index in range(40):
            _record(logger, summary=f"event {index}")

        events = logger.read_events("t1")
        assert len(events) == 40, "events were lost across the rotation boundary"

        ok, message = verify_chain(events, public_key_pem=signer.public_key_pem())
        assert ok, message

    def test_retention_drops_the_oldest_segment(self, tmp_path: Path):
        path = tmp_path / "a.jsonl"
        logger = AuditLogger(
            path, sink=JsonlSink(path, durable=False, max_bytes=400, max_segments=2)
        )
        for index in range(60):
            _record(logger, summary=f"event {index}")

        segments = sorted(p.name for p in tmp_path.glob("a.jsonl*"))
        assert segments == ["a.jsonl", "a.jsonl.1", "a.jsonl.2"]
        # Retention deletes evidence: fewer events survive than were written.
        assert len(logger.read_events("t1")) < 60


class TestCaseRetention:
    def test_prune_removes_old_runs(self, tmp_path: Path):
        from src.memory import CaseStore, prune, set_case_store
        from tests.test_memory import _alert, _completed_run

        store = CaseStore(tmp_path / "cases.sqlite")
        set_case_store(store)
        try:
            store.record_run(_completed_run(_alert("A-1"), thread_id="run-1"))
            assert prune(store, older_than=timedelta(days=365)) == 0
            assert prune(store, older_than=timedelta(seconds=0)) == 1
            assert store.related_runs(_alert("A-2")) == []
        finally:
            set_case_store(None)
            store.close()
