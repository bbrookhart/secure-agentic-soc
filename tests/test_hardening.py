"""Tests for the production-hardening controls: sinks, approval identity, ingestion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.enums import AgentRole, AuditAction
from src.ingest import AlertIngestError, DirectorySource, parse_alert
from src.ingest.base import MAX_ALERT_BYTES
from src.ingest.siem import ElasticSource, SplunkSource, _map_severity
from src.security.approval_identity import (
    UnauthenticatedApproval,
    require_identity,
    resolve_identity,
)
from src.security.audit import AuditLogger, verify_chain
from src.security.audit_sink import FanOutSink, JsonlSink


class _CountingSink:
    """A sink that records what it received."""

    def __init__(self, *, fail: bool = False) -> None:
        self.events: list[str] = []
        self.fail = fail
        self.failures = 0
        self.last_error = ""

    def write(self, event) -> None:
        if self.fail:
            self.failures += 1
            self.last_error = "collector unreachable"
            raise RuntimeError("collector unreachable")
        self.events.append(event.event_id)

    def close(self) -> None:
        return None


def _record(logger: AuditLogger, thread_id: str = "t1"):
    return logger.record(
        thread_id=thread_id,
        actor=AgentRole.SUPERVISOR,
        action=AuditAction.ROUTING_DECISION,
        summary="test event",
    )


class TestAuditSinks:
    def test_events_reach_every_sink(self, tmp_path: Path):
        forwarder = _CountingSink()
        sink = FanOutSink(JsonlSink(tmp_path / "a.jsonl", durable=False), forwarder)
        logger = AuditLogger(tmp_path / "a.jsonl", sink=sink)

        event = _record(logger)
        assert forwarder.events == [event.event_id]
        assert (tmp_path / "a.jsonl").read_text(encoding="utf-8").strip()

    def test_a_failing_forwarder_does_not_lose_the_local_write(self, tmp_path: Path):
        """Forwarding is best effort. The local record is not."""
        broken = _CountingSink(fail=True)
        sink = FanOutSink(JsonlSink(tmp_path / "a.jsonl", durable=False), broken)
        logger = AuditLogger(tmp_path / "a.jsonl", sink=sink)

        _record(logger)

        lines = [line for line in (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines() if line]
        assert len(lines) == 1
        assert json.loads(lines[0])["summary"] == "test event"

    def test_forwarding_failures_are_visible(self, tmp_path: Path):
        """Silent forwarding failure would fake a control that is not running."""
        broken = _CountingSink(fail=True)
        sink = FanOutSink(JsonlSink(tmp_path / "a.jsonl", durable=False), broken)
        logger = AuditLogger(tmp_path / "a.jsonl", sink=sink)

        _record(logger)

        health = logger.forwarding_health()
        assert health and health[0]["failures"] == 1

    def test_a_failing_local_sink_is_not_swallowed(self, tmp_path: Path):
        class Broken:
            def write(self, event) -> None:
                raise OSError("disk full")

            def close(self) -> None:
                return None

        logger = AuditLogger(tmp_path / "a.jsonl", sink=FanOutSink(Broken()))
        with pytest.raises(OSError, match="disk full"):
            _record(logger)

    def test_chain_still_verifies_through_a_sink(self, tmp_path: Path):
        logger = AuditLogger(
            tmp_path / "a.jsonl",
            sink=FanOutSink(JsonlSink(tmp_path / "a.jsonl", durable=False), _CountingSink()),
        )
        for _ in range(4):
            _record(logger)

        ok, message = verify_chain(logger.read_events("t1"))
        assert ok, message

    def test_durable_writes_land_on_disk_immediately(self, tmp_path: Path):
        """An audit line still sitting in a page cache is not evidence."""
        path = tmp_path / "a.jsonl"
        logger = AuditLogger(path, sink=JsonlSink(path, durable=True))
        _record(logger)
        assert len(path.read_text(encoding="utf-8").splitlines()) == 1


class TestApprovalIdentity:
    def test_identity_comes_from_the_configured_header(self):
        identity = resolve_identity({"X-Forwarded-User": "a.analyst", "X-Forwarded-Email": "a@x.io"})
        assert identity is not None
        assert identity.username == "a.analyst"
        assert identity.source == "proxy_header"

    def test_header_lookup_is_case_insensitive(self):
        """A control that fails on capitalisation is a control that silently does not run."""
        assert resolve_identity({"x-forwarded-user": "a.analyst"}) is not None

    def test_missing_header_yields_no_identity(self):
        assert resolve_identity({}) is None
        assert resolve_identity(None) is None
        assert resolve_identity({"X-Forwarded-User": "   "}) is None

    def test_approval_fails_closed_without_a_verified_identity(self, monkeypatch):
        monkeypatch.setenv("SOC_REQUIRE_AUTHENTICATED_APPROVAL", "true")
        from src.config import get_settings

        get_settings.cache_clear()
        with pytest.raises(UnauthenticatedApproval):
            require_identity({})

    def test_unauthenticated_mode_is_labelled_not_silent(self, monkeypatch):
        """Opting out must be visible in the trail, not indistinguishable from real auth."""
        monkeypatch.setenv("SOC_REQUIRE_AUTHENTICATED_APPROVAL", "false")
        from src.config import get_settings

        get_settings.cache_clear()
        identity = require_identity({})
        assert identity.source == "unauthenticated"

    def test_decision_records_how_the_identity_was_established(self):
        from src.state import ApprovalDecision

        decision = ApprovalDecision(approved=True, decided_by="a.analyst", identity_source="proxy_header")
        assert decision.identity_source == "proxy_header"
        # Default is the pessimistic one.
        assert ApprovalDecision(approved=True).identity_source == "unauthenticated"


class TestIngestionAdapters:
    def test_every_adapter_terminates_in_the_validator(self):
        """The trust boundary is one function; adapters must not build alerts by hand."""
        source = ElasticSource("https://elastic.invalid")
        payload = source._to_alert_payload(
            {
                "kibana.alert.uuid": "abc-123",
                "kibana.alert.rule.name": "Suspicious PowerShell",
                "kibana.alert.severity": "high",
                "@timestamp": "2026-02-01T10:00:00Z",
                "host": {"name": "WKS-1", "ip": "10.0.0.1"},
                "destination": {"ip": "203.0.113.5"},
            }
        )
        alert = parse_alert(payload)
        assert alert.alert_id == "abc-123"
        assert alert.reported_severity.value == "high"
        assert alert.assets[0].name == "WKS-1"

    def test_unknown_vendor_severity_does_not_default_downwards(self):
        """An unrecognised label is not evidence of harmlessness."""
        assert _map_severity("catastrophic", SplunkSource._SEVERITY) == "medium"
        assert _map_severity(None, SplunkSource._SEVERITY) == "medium"

    def test_malformed_vendor_record_is_rejected_not_repaired(self):
        source = SplunkSource("https://splunk.invalid")
        payload = source._to_alert_payload({"event_id": "", "search_name": ""})
        payload["alert_id"] = ""
        with pytest.raises(AlertIngestError):
            parse_alert(payload)

    def test_directory_source_emits_each_file_once(self, tmp_path: Path):
        alert = {
            "alert_id": "DIR-001",
            "source": "test",
            "title": "A test alert",
            "reported_severity": "low",
        }
        (tmp_path / "one.json").write_text(json.dumps(alert), encoding="utf-8")

        source = DirectorySource(tmp_path)
        assert [a.alert_id for a in source.poll()] == ["DIR-001"]
        assert list(source.poll()) == []

    def test_directory_source_skips_malformed_files(self, tmp_path: Path):
        """One bad alert must not stop the queue."""
        (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
        (tmp_path / "good.json").write_text(
            json.dumps({"alert_id": "DIR-002", "source": "test", "title": "ok"}), encoding="utf-8"
        )

        assert [a.alert_id for a in DirectorySource(tmp_path).poll()] == ["DIR-002"]

    def test_oversized_alert_is_refused_before_parsing(self, tmp_path: Path):
        from src.ingest import load_alert_file

        path = tmp_path / "huge.json"
        path.write_text("x" * (MAX_ALERT_BYTES + 1), encoding="utf-8")
        with pytest.raises(AlertIngestError, match="exceeding"):
            load_alert_file(path)
