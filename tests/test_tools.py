"""Tool contract tests: validation, authorisation, budgets, containment."""

from __future__ import annotations

import pytest

from src.enums import AgentRole
from src.tools import TOOL_REGISTRY

#: Modules that would give a tool the ability to reach outside the process.
NETWORK_MODULES = {"httpx", "requests", "urllib", "urllib.request", "socket", "http.client", "ftplib"}
EXECUTION_MODULES = {"subprocess", "os", "shutil", "ctypes", "multiprocessing", "pty", "commands"}
DANGEROUS_MODULES = NETWORK_MODULES | EXECUTION_MODULES


def imported_modules(path: str | object) -> set[str]:
    """Top-level modules a source file imports, via AST rather than text search.

    Text-searching the source is wrong here: these modules are named in
    docstrings precisely *because* they are deliberately absent, so a substring
    check reports failures on the comments explaining the control.
    """
    import ast
    from pathlib import Path

    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    modules: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
                modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
            modules.add(node.module.split(".")[0])

    return modules


class TestRegistryShape:
    def test_no_dangerous_tools_exist(self):
        """The absence of these is the design; assert it so it stays true."""
        forbidden = {"shell", "bash", "exec", "python", "http_request", "fetch_url",
                     "read_file", "write_file", "eval", "run_command"}
        assert forbidden & set(TOOL_REGISTRY) == set()

    def test_every_tool_has_a_schema_and_description(self):
        for name, tool in TOOL_REGISTRY.items():
            assert tool.input_model is not None, name
            assert len(tool.description) > 40, name

    def test_only_containment_tool_is_above_read_only(self):
        from src.enums import ActionRisk

        elevated = {n for n, t in TOOL_REGISTRY.items() if t.risk is not ActionRisk.READ_ONLY}
        assert elevated == {"draft_containment_proposal"}


class TestAuthorisation:
    def test_unauthorised_tool_is_denied(self, broker):
        result = broker.invoke(
            "enrich_ioc",
            {"indicator": "203.0.113.45", "indicator_type": "ipv4"},
            principal=AgentRole.TRIAGE,
            thread_id="t1",
        )
        assert not result.ok
        assert "not authorized" in result.error

    def test_denial_is_audited(self, broker, audit_logger):
        broker.invoke(
            "enrich_ioc", {"indicator": "203.0.113.45", "indicator_type": "ipv4"},
            principal=AgentRole.REPORTER, thread_id="t1",
        )
        actions = [e.action.value for e in audit_logger.read_events("t1")]
        assert "tool_denied" in actions

    def test_unknown_tool_is_denied(self, broker):
        result = broker.invoke("rm_rf", {}, principal=AgentRole.ENRICHMENT, thread_id="t1")
        assert not result.ok
        assert "unknown tool" in result.error

    def test_authorised_call_succeeds(self, broker):
        result = broker.invoke(
            "enrich_ioc", {"indicator": "203.0.113.45", "indicator_type": "ipv4"},
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        assert result.ok
        assert result.data["known_malicious"] is True


class TestInputValidation:
    @pytest.mark.parametrize(
        "indicator,indicator_type",
        [
            ("not-an-ip", "ipv4"),
            ("999.999.999.999", "ipv4"),
            ("deadbeef", "sha256"),
            ("nodomain", "domain"),
            ("ftp://example.com/x", "url"),
            ("not an email", "email"),
        ],
    )
    def test_malformed_indicators_rejected(self, broker, indicator, indicator_type):
        result = broker.invoke(
            "enrich_ioc", {"indicator": indicator, "indicator_type": indicator_type},
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        assert not result.ok
        assert "invalid arguments" in result.error

    def test_handler_never_runs_on_invalid_input(self, broker, audit_logger):
        broker.invoke(
            "enrich_ioc", {"indicator": "bad", "indicator_type": "ipv4"},
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        actions = [e.action.value for e in audit_logger.read_events("t1")]
        assert "tool_result" not in actions

    def test_limit_bounds_are_enforced(self, broker):
        result = broker.invoke(
            "query_vector_logs", {"query": "test query", "limit": 9999},
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        assert not result.ok

    def test_containment_target_rejects_metacharacters(self, broker):
        result = broker.invoke(
            "draft_containment_proposal",
            {
                "action_type": "isolate_host",
                "target": "SRV-01; rm -rf /",
                "justification": "attempting command injection through the target field",
            },
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        assert not result.ok

    def test_containment_action_type_is_closed(self, broker):
        result = broker.invoke(
            "draft_containment_proposal",
            {
                "action_type": "run_arbitrary_script",
                "target": "SRV-01",
                "justification": "trying to invent a new capability",
            },
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        assert not result.ok


class TestBudgetsAndLimits:
    def test_run_budget_is_enforced(self, audit_logger):
        from src.tools import build_broker

        broker = build_broker(audit=audit_logger, max_calls_per_run=3)
        for _ in range(3):
            broker.invoke(
                "lookup_mitre", {"query": "T1486"},
                principal=AgentRole.ENRICHMENT, thread_id="t1",
            )
        result = broker.invoke(
            "lookup_mitre", {"query": "T1486"},
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        assert not result.ok
        assert "budget exhausted" in result.error

    def test_budget_is_per_thread(self, audit_logger):
        from src.tools import build_broker

        broker = build_broker(audit=audit_logger, max_calls_per_run=2)
        for _ in range(2):
            broker.invoke("lookup_mitre", {"query": "T1486"},
                          principal=AgentRole.ENRICHMENT, thread_id="t1")
        # A different run has its own budget.
        result = broker.invoke("lookup_mitre", {"query": "T1486"},
                               principal=AgentRole.ENRICHMENT, thread_id="t2")
        assert result.ok


class TestUntrustedOutputContainment:
    def test_injected_log_content_is_flagged(self, broker):
        result = broker.invoke(
            "query_vector_logs",
            {"query": "ticket INC-88213 external submitter note", "limit": 5},
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        assert result.ok
        assert result.flagged
        assert "instruction_override" in result.injection_flags

    def test_flagging_is_audited(self, broker, audit_logger):
        broker.invoke(
            "query_vector_logs",
            {"query": "ticket INC-88213 external submitter note", "limit": 5},
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        actions = [e.action.value for e in audit_logger.read_events("t1")]
        assert "untrusted_content_flagged" in actions


class TestContainmentIsProposalOnly:
    def test_draft_is_never_executed(self, broker):
        result = broker.invoke(
            "draft_containment_proposal",
            {
                "action_type": "isolate_host",
                "target": "SRV-FILE-02",
                "justification": "Confirmed ransomware encryption on this host.",
            },
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        assert result.ok
        assert result.data["execution_mode"] == "proposal_only"
        assert result.data["executed"] is False
        assert result.data["requires_human_approval"] is True

    def test_response_module_has_no_execution_capability(self):
        """Static guarantee: nothing in the response tool can reach a system."""
        assert imported_modules("src/tools/response.py") & DANGEROUS_MODULES == set()


class TestClassifier:
    def test_ransomware_scores_critical(self, broker):
        result = broker.invoke(
            "classify_alert",
            {
                "alert_summary": (
                    "Ransomware encrypted 14211 files, vssadmin delete shadows, "
                    "defender disabled on critical production file server"
                ),
                "reported_severity": "critical",
            },
            principal=AgentRole.TRIAGE, thread_id="t1",
        )
        assert result.ok
        assert result.data["severity"] == "critical"
        assert result.data["category"] == "malware"

    def test_known_false_positive_is_downgraded(self, broker):
        result = broker.invoke(
            "classify_alert",
            {
                "alert_summary": (
                    "Impossible travel alert; both addresses are the known corporate vpn "
                    "egress pool, managed device, mfa satisfied, approved change window"
                ),
                "reported_severity": "low",
            },
            principal=AgentRole.TRIAGE, thread_id="t1",
        )
        assert result.ok
        assert result.data["category"] == "benign_or_false_positive"
        assert result.data["severity"] in {"info", "low"}


class TestMitreLookup:
    def test_exact_id_lookup(self, broker):
        result = broker.invoke("lookup_mitre", {"query": "T1486"},
                               principal=AgentRole.ENRICHMENT, thread_id="t1")
        assert result.data["match_type"] == "exact_id"
        assert result.data["results"][0]["name"] == "Data Encrypted for Impact"

    def test_unknown_id_reports_absence_honestly(self, broker):
        result = broker.invoke("lookup_mitre", {"query": "T9999"},
                               principal=AgentRole.ENRICHMENT, thread_id="t1")
        assert result.data["results"] == []
        assert "does not mean" in result.data["note"]

    def test_irrelevant_query_returns_nothing(self, broker):
        """A relevance floor prevents spurious ATT&CK mappings."""
        result = broker.invoke(
            "lookup_mitre", {"query": "quarterly budget spreadsheet review meeting"},
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        assert result.data["results"] == []


class TestIOCEnrichment:
    def test_unknown_indicator_is_unknown_not_benign(self, broker):
        result = broker.invoke(
            "enrich_ioc", {"indicator": "198.18.0.1", "indicator_type": "ipv4"},
            principal=AgentRole.ENRICHMENT, thread_id="t1",
        )
        assert result.ok
        assert result.data["found"] is False
        assert "UNKNOWN, not benign" in result.data["notes"]

    def test_ioc_module_makes_no_network_calls(self):
        assert imported_modules("src/tools/ioc.py") & NETWORK_MODULES == set()

    def test_no_tool_module_imports_a_dangerous_capability(self):
        """The whole tool package must stay free of execution and network primitives."""
        from pathlib import Path

        for path in sorted(Path("src/tools").glob("*.py")):
            offenders = imported_modules(path) & DANGEROUS_MODULES
            assert offenders == set(), f"{path.name} imports {offenders}"
