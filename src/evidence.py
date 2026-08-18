"""Generate a control-evidence bundle from the running system.

There is a difference between a control that is *claimed* and one that is
*demonstrated*, and it is most of what a security review is trying to
establish. A document asserting "least privilege is enforced" is a sentence
someone wrote. A table generated from the live capability matrix is the
enforcement itself, printed.

So nothing here is transcribed. Every value is read from the thing that
implements it: the capability matrix from the identity registry, the approval
rules from the policy engine, the authority matrix from the authorization
module, the posture from the settings actually loaded, the chain status from
verifying real audit records.

Two consequences worth stating:

* **The bundle can contradict the documentation, and that is the point.** If
  someone disables signing, the evidence says signing is disabled, no matter
  what `docs/CONTROLS.md` says about AU-10.
* **Declarative controls are labelled as declarative.** Encryption at rest is an
  operator assertion this application cannot verify, and the bundle says so
  rather than reporting a configured boolean as a fact.

Usage::

    python -m src.evidence                     # Markdown to stdout
    python -m src.evidence --json bundle.json  # machine-readable too
"""

from __future__ import annotations

import argparse
import json
import subprocess  # noqa: S404 - reads the commit for provenance, fixed argv
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _git_commit() -> str:
    """The commit this evidence describes, so it can be tied to a diff."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001 - provenance is best effort
        return "unknown"


def collect() -> dict[str, Any]:
    """Read every control's state from the component that implements it."""
    from src.config import get_settings
    from src.model_provenance import resolve_model_provenance
    from src.observability.health import run_checks
    from src.prompts import manifest_hash, prompt_manifest
    from src.security.audit import get_audit_logger, verify_chain
    from src.security.authz import authority_matrix
    from src.security.identity import capability_matrix
    from src.security.operating_mode import current_mode
    from src.security.policy import default_policy
    from src.tools import TOOL_REGISTRY

    settings = get_settings()
    logger = get_audit_logger()
    provenance = resolve_model_provenance()

    # --- Chain status, verified rather than asserted ----------------------
    chains: list[dict[str, Any]] = []
    events = logger.read_events()
    thread_ids = sorted({event.thread_id for event in events})[-10:]
    for thread_id in thread_ids:
        ok, message = verify_chain(
            logger.read_events(thread_id), public_key_pem=logger.public_key_pem()
        )
        chains.append({"thread_id": thread_id, "verified": ok, "detail": message})

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "commit": _git_commit(),
        "app_version": settings.app_version,
        # --- Provenance of judgement ---------------------------------------
        "model": {
            "name": provenance.name,
            "digest": provenance.short_digest,
            "pinned": provenance.pinned,
            "matches_pin": provenance.matches_pin,
            "available": provenance.available,
        },
        "prompts": {"manifest": manifest_hash(), "versions": prompt_manifest()},
        # --- Authorization: code and people --------------------------------
        "agent_capabilities": capability_matrix(),
        "human_authority": authority_matrix(),
        "tools": [
            {
                "name": name,
                "risk": tool.risk.value,
                "returns_untrusted": tool.returns_untrusted,
                "description": tool.description,
            }
            for name, tool in sorted(TOOL_REGISTRY.items())
        ],
        "approval_policy": default_policy().describe(),
        # --- Configured posture, read from live settings -------------------
        "posture": {
            "operating_mode": current_mode().value,
            "offline_mode": settings.offline_mode,
            "audit_signing_enabled": settings.audit_signing_enabled,
            "audit_signing_key_id": logger.key_id or "(none)",
            "audit_durable_writes": settings.audit_durable_writes,
            "audit_forwarding_configured": bool(
                settings.audit_forward_url or settings.audit_syslog_address
            ),
            "audit_retention_segments": settings.audit_max_segments,
            "case_retention_days": settings.case_retention_days,
            "require_authenticated_approval": settings.require_authenticated_approval,
            "require_separation_of_duties": settings.require_separation_of_duties,
            "require_two_person_approval": settings.require_two_person_approval,
            "hitl_severity_threshold": settings.hitl_severity_threshold.value,
            "max_tool_calls_per_run": settings.max_tool_calls_per_run,
            "telemetry_enabled": settings.telemetry_enabled,
            # Declarative: the application cannot verify this and must not
            # report an operator's assertion as a fact.
            "state_volume_encrypted_declared": settings.state_volume_encrypted,
        },
        "readiness": [
            {"name": check.name, "status": check.status, "detail": check.detail}
            for check in run_checks()
        ],
        "audit_chains": chains,
        "audit_forwarding_health": logger.forwarding_health(),
        "evaluation": _load_baseline(),
        "supply_chain": _supply_chain_state(),
    }


def _load_baseline() -> dict[str, Any]:
    """The recorded evaluation, with the provenance of what produced it."""
    path = Path(__file__).resolve().parent.parent / "evals" / "baselines" / "offline.json"
    if not path.exists():
        return {"available": False}

    from src.prompts import manifest_hash

    baseline = json.loads(path.read_text(encoding="utf-8"))
    return {
        "available": True,
        "recorded": baseline.get("recorded", "unknown"),
        "prompt_manifest": baseline.get("prompt_manifest", ""),
        # An auditor should not have to notice this themselves.
        "current_for_these_prompts": baseline.get("prompt_manifest") == manifest_hash(),
        "summary": baseline.get("summary", {}),
    }


def _supply_chain_state() -> dict[str, Any]:
    """What is pinned, and what is suppressed."""
    root = Path(__file__).resolve().parent.parent
    lockfile = root / "requirements.lock"
    ignore_file = root / ".pip-audit-ignore"

    suppressed: list[str] = []
    if ignore_file.exists():
        for raw in ignore_file.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                suppressed.append(line)

    locked = 0
    hashes = 0
    if lockfile.exists():
        text = lockfile.read_text(encoding="utf-8")
        locked = sum(1 for line in text.splitlines() if "==" in line and not line.startswith("#"))
        hashes = text.count("--hash=sha256:")

    return {
        "lockfile_present": lockfile.exists(),
        "packages_pinned": locked,
        "hashes_recorded": hashes,
        "suppressed_vulnerabilities": suppressed,
    }


# --- Rendering --------------------------------------------------------------
def _table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> list[str]:
    if not rows:
        return ["_none_", ""]
    lines = [
        "| " + " | ".join(label for _, label in columns) + " |",
        "|" + "|".join(":--" for _ in columns) + "|",
    ]
    for row in rows:
        cells = []
        for key, _ in columns:
            value = row.get(key, "")
            if isinstance(value, list):
                value = ", ".join(str(item) for item in value) or "—"
            elif isinstance(value, bool):
                value = "yes" if value else "no"
            cells.append(str(value))
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    return lines


def render(bundle: dict[str, Any]) -> str:
    """Auditor-readable Markdown."""
    posture = bundle["posture"]
    evaluation = bundle["evaluation"]
    supply = bundle["supply_chain"]

    lines: list[str] = [
        "# Control Evidence",
        "",
        f"Generated **{bundle['generated_at']}** from commit `{bundle['commit']}`.",
        "",
        "Every value below is read from the component that implements it — the capability",
        "matrix from the identity registry, the approval rules from the policy engine, the",
        "chain status from verifying real records. Nothing is transcribed, so this bundle can",
        "and should contradict the documentation when the deployment differs from it.",
        "",
        "---",
        "",
        "## Posture",
        "",
        "| Control | State |",
        "|:--|:--|",
    ]

    labels = {
        "operating_mode": "Operating mode",
        "audit_signing_enabled": "Audit signing (AU-10)",
        "audit_signing_key_id": "Signing key",
        "audit_durable_writes": "Durable audit writes",
        "audit_forwarding_configured": "Off-host forwarding (AU-9)",
        "audit_retention_segments": "Audit segments retained (AU-11)",
        "case_retention_days": "Case retention, days",
        "require_authenticated_approval": "Authenticated approval (IA-2)",
        "require_separation_of_duties": "Separation of duties (AC-5)",
        "require_two_person_approval": "Two-person integrity",
        "hitl_severity_threshold": "Approval severity threshold",
        "max_tool_calls_per_run": "Tool budget per run (SC-5)",
        "telemetry_enabled": "Telemetry export",
        "offline_mode": "Offline mode",
    }
    for key, label in labels.items():
        value = posture.get(key)
        rendered = "yes" if value is True else ("no" if value is False else str(value))
        lines.append(f"| {label} | {rendered} |")

    declared = posture["state_volume_encrypted_declared"]
    lines += [
        f"| Encryption at rest (SC-28) | {'declared by operator' if declared else 'not declared'} "
        "— *declarative; this application cannot verify it* |",
        "",
        "## Provenance of judgement",
        "",
        f"- **Model** `{bundle['model']['name']}` digest `{bundle['model']['digest'] or 'unknown'}`"
        + (" — **pinned**" if bundle["model"]["pinned"] else " — not pinned")
        + ("" if bundle["model"]["matches_pin"] else " — **DOES NOT MATCH THE PIN**"),
        f"- **Prompts** manifest `{bundle['prompts']['manifest']}`",
        "",
    ]
    lines += _table(
        [{"id": k, "version": v} for k, v in bundle["prompts"]["versions"].items()],
        [("id", "Prompt"), ("version", "Version + fingerprint")],
    )

    lines += ["## Least privilege — agents (AC-6)", ""]
    lines += _table(
        bundle["agent_capabilities"],
        [
            ("agent", "Principal"),
            ("tools", "Tools held"),
            ("max_action_risk", "Max risk"),
            ("max_tool_calls", "Call budget"),
        ],
    )

    lines += ["## Approval authority — people (AC-3, AC-6)", ""]
    lines += _table(
        bundle["human_authority"],
        [
            ("role", "Role"),
            ("may_approve", "May approve"),
            ("max_severity", "Severity ceiling"),
            ("max_action_risk", "Action ceiling"),
            ("may_approve_critical_asset", "Critical assets"),
        ],
    )

    lines += ["## Capability surface", ""]
    lines += _table(
        bundle["tools"],
        [("name", "Tool"), ("risk", "Risk"), ("returns_untrusted", "Output untrusted")],
    )

    lines += ["## Approval policy", ""]
    lines += _table(
        bundle["approval_policy"],
        [("rule_id", "Rule"), ("effect", "Effect"), ("reason", "Reason")],
    )

    lines += ["## Readiness", ""]
    lines += _table(
        bundle["readiness"], [("name", "Check"), ("status", "Status"), ("detail", "Detail")]
    )

    lines += ["## Audit chain verification (AU-9)", ""]
    if bundle["audit_chains"]:
        lines += _table(
            bundle["audit_chains"],
            [("thread_id", "Run"), ("verified", "Verified"), ("detail", "Detail")],
        )
    else:
        lines += ["_No audit records present._", ""]

    lines += [
        "## Software supply chain (SR-3, SR-11, SI-7)",
        "",
        f"- Lockfile present: **{'yes' if supply['lockfile_present'] else 'no'}**",
        f"- Packages pinned: **{supply['packages_pinned']}**, hashes recorded: "
        f"**{supply['hashes_recorded']}**",
        f"- Suppressed vulnerabilities: **{len(supply['suppressed_vulnerabilities'])}**"
        + (
            f" (`{', '.join(supply['suppressed_vulnerabilities'])}` — justified in "
            "docs/DEPENDENCY_EXCEPTIONS.md)"
            if supply["suppressed_vulnerabilities"]
            else " — none"
        ),
        "",
        "## Evaluation (SA-11)",
        "",
    ]

    if evaluation.get("available"):
        summary = evaluation["summary"]
        current = evaluation["current_for_these_prompts"]
        lines += [
            f"Baseline recorded **{evaluation['recorded']}** against prompt manifest "
            f"`{evaluation['prompt_manifest']}`.",
            "",
        ]
        if not current:
            lines += [
                "> **These numbers are stale.** The prompts have changed since this baseline",
                "> was recorded, so it describes a system that no longer exists. Re-run",
                "> `make eval` before citing them.",
                "",
            ]
        lines += [
            "| Metric | Value |",
            "|:--|--:|",
            f"| Cases | {summary.get('cases', 0)} |",
            f"| Security invariant breaches | {summary.get('violations', 0)} |",
            f"| Injection containment | {summary.get('injection_containment', 0):.0%} |",
            f"| Missed escalations | {summary.get('missed_escalations', 0)} |",
            f"| Severity in band | {summary.get('severity_in_band', 0):.0%} |",
            f"| Severity under-called | {summary.get('severity_under_called', 0):.0%} |",
            f"| Category accuracy | {summary.get('category_accuracy', 0):.0%} |",
            "",
        ]
    else:
        lines += ["_No baseline recorded. Run `make eval`._", ""]

    lines += [
        "---",
        "",
        "Control-by-control mapping: [docs/CONTROLS.md](CONTROLS.md). "
        "Residual risk: [docs/THREAT_MODEL.md](THREAT_MODEL.md).",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a control-evidence bundle.")
    parser.add_argument("--json", dest="json_path", help="Also write the raw bundle here.")
    parser.add_argument("--out", help="Write Markdown here instead of stdout.")
    args = parser.parse_args(argv)

    bundle = collect()
    markdown = render(bundle)

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")
    if args.out:
        Path(args.out).write_text(markdown + "\n", encoding="utf-8")
    else:
        print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
