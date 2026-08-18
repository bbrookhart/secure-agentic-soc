"""The evidence bundle must be generated, not transcribed.

The point of these is that the bundle tracks the *system*, not a document. If
someone disables signing, the bundle says signing is disabled — whatever
docs/CONTROLS.md claims about AU-10. A bundle that could drift from reality
would be a third document agreeing with the other two.
"""

from __future__ import annotations

from pathlib import Path

from src.evidence import collect, render

ROOT = Path(__file__).resolve().parent.parent


class TestBundleIsReadFromLiveComponents:
    def test_agent_capabilities_come_from_the_identity_registry(self):
        from src.security.identity import capability_matrix

        assert collect()["agent_capabilities"] == capability_matrix()

    def test_approval_policy_comes_from_the_policy_engine(self):
        from src.security.policy import default_policy

        rules = {rule["rule_id"] for rule in collect()["approval_policy"]}
        assert rules == {rule["rule_id"] for rule in default_policy().describe()}

    def test_human_authority_comes_from_the_authz_matrix(self):
        from src.security.authz import authority_matrix

        assert collect()["human_authority"] == authority_matrix()

    def test_prompt_manifest_matches_the_registry(self):
        from src.prompts import manifest_hash

        assert collect()["prompts"]["manifest"] == manifest_hash()

    def test_the_tool_inventory_matches_the_registry(self):
        from src.tools import TOOL_REGISTRY

        assert {tool["name"] for tool in collect()["tools"]} == set(TOOL_REGISTRY)


class TestPostureTracksConfiguration:
    def test_disabling_signing_is_reported_as_disabled(self, monkeypatch):
        """The bundle must contradict the documentation when the deployment does."""
        monkeypatch.setenv("SOC_AUDIT_SIGNING_ENABLED", "false")
        from src.config import get_settings

        get_settings.cache_clear()
        try:
            assert collect()["posture"]["audit_signing_enabled"] is False
        finally:
            get_settings.cache_clear()

    def test_the_operating_mode_is_reported(self):
        from src.security.operating_mode import OperatingMode, clear_mode, set_mode

        set_mode(OperatingMode.REVIEW_ALL)
        try:
            assert collect()["posture"]["operating_mode"] == "review_all"
        finally:
            clear_mode()

    def test_encryption_at_rest_is_labelled_declarative(self):
        """An operator's assertion must not be reported as a verified fact."""
        text = render(collect())
        assert "declarative; this application cannot verify it" in text

    def test_relaxed_controls_are_visible(self, monkeypatch):
        monkeypatch.setenv("SOC_REQUIRE_SEPARATION_OF_DUTIES", "false")
        from src.config import get_settings

        get_settings.cache_clear()
        try:
            assert collect()["posture"]["require_separation_of_duties"] is False
        finally:
            get_settings.cache_clear()


class TestSupplyChainAndEvaluation:
    def test_lockfile_state_is_counted_not_asserted(self):
        supply = collect()["supply_chain"]
        assert supply["lockfile_present"]
        assert supply["packages_pinned"] > 50
        assert supply["hashes_recorded"] >= supply["packages_pinned"]

    def test_suppressions_are_listed(self):
        """Whatever coverage was given up must appear in the evidence."""
        from src.evidence import _supply_chain_state

        assert "suppressed_vulnerabilities" in _supply_chain_state()

    def test_a_stale_baseline_is_flagged(self, monkeypatch):
        """Numbers from different prompts describe a different system."""
        monkeypatch.setattr("src.prompts.manifest_hash", lambda: "something-else")
        monkeypatch.setattr("src.evidence.manifest_hash", lambda: "something-else", raising=False)

        from src.evidence import _load_baseline

        baseline = _load_baseline()
        if baseline.get("available"):
            assert baseline["current_for_these_prompts"] is False

    def test_the_baseline_is_current_for_the_committed_prompts(self):
        evaluation = collect()["evaluation"]
        assert evaluation["available"]
        assert evaluation["current_for_these_prompts"], (
            "prompts changed since the baseline; run `make eval` and update "
            "evals/baselines/offline.json"
        )


class TestRendering:
    def test_markdown_covers_every_section(self):
        text = render(collect())
        for heading in (
            "## Posture",
            "## Provenance of judgement",
            "## Least privilege",
            "## Approval authority",
            "## Capability surface",
            "## Approval policy",
            "## Readiness",
            "## Audit chain verification",
            "## Software supply chain",
            "## Evaluation",
        ):
            assert heading in text, f"missing section: {heading}"

    def test_it_points_at_the_control_mapping(self):
        assert "CONTROLS.md" in render(collect())

    def test_the_control_mapping_exists_and_is_honest(self):
        """A mapping that only lists wins is not a mapping."""
        text = (ROOT / "docs" / "CONTROLS.md").read_text(encoding="utf-8")
        assert "## What this mapping does not claim" in text
        # Every status vocabulary word is actually used.
        for status in ("Implemented", "Partial", "Inherited", "Not applicable"):
            assert status in text
