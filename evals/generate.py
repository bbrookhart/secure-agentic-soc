"""Generate multi-host investigation scenarios for the eval corpus.

The hand-authored corpus tests *classification*: one alert, one host, one
correct answer. It cannot test whether the pipeline **investigates**, because
nothing in it rewards following a lead -- every case's answer is already inside
the alert it was given.

This generates the shape that does: an alert naming one host, log evidence
linking that host to a second, and the second to a third. A single-pass
pipeline sees only the first hop. Entity recall over these scenarios is what
makes the difference measurable rather than asserted.

Two deliberate isolation choices:

* Logs are written to ``data/logs/generated.jsonl``, never to the hand-authored
  corpus, so a bug here cannot damage cases that already pass.
* Scenarios are dated a **month after** the existing alerts. Log correlation is
  scoped to +/-72h of a detection, so generated logs are unreachable from the
  existing 38 cases by construction rather than by hoping the vocabulary does
  not collide. That hope has already failed once: planted records collided with
  unrelated alerts on words like "tool" and "access" and moved metrics on cases
  they had nothing to do with.

Usage::

    python -m evals.generate                 # write logs + cases
    python -m evals.generate --dry-run       # print what would be written
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

#: Generated scenarios live here, clear of the February alert cluster.
BASE_DATE = datetime(2026, 3, 10, 9, 0, 0)

#: Days between scenarios. Must exceed twice the correlation window
#: (``enrichment.LOG_WINDOW_HOURS``, 72h) or neighbouring scenarios fall inside
#: each other's reach and pivot into one another -- which happened at two days
#: apart, sending the no-pivot control case off into a different scenario's
#: hosts. Scenarios have to be independent for per-case scoring to mean
#: anything.
SCENARIO_SPACING_DAYS = 10

CORPUS_FILE = Path("evals/corpus/generated.json")
LOG_FILE = Path("data/logs/generated.jsonl")


@dataclass
class Hop:
    """One step in an intrusion chain: a host and what it did next."""

    host: str
    message: str
    source: str = "sysmon"
    #: Entity this hop reveals, which the next hop is about.
    reveals: str = ""


@dataclass
class Scenario:
    """An alert plus the log trail an analyst should be able to follow."""

    case_id: str
    title: str
    description: str
    category: str
    severity_band: list[str]
    entry_host: str
    hops: list[Hop]
    reported_severity: str = "medium"
    should_escalate: bool = True
    criticality: str = "high"
    notes: str = ""
    indicators: list[dict[str, str]] = field(default_factory=list)

    @property
    def expected_entities(self) -> list[str]:
        """Entities beyond the alert's own that the investigation should reach."""
        return [hop.reveals.lower() for hop in self.hops if hop.reveals]


def _scenarios() -> list[Scenario]:
    """The generated corpus.

    Kept explicit rather than randomised: a corpus that changes shape every run
    cannot be used for paired comparison, which is the only thing that resolves
    a difference at this sample size.
    """
    return [
        Scenario(
            case_id="GEN-001-two-hop-lateral",
            title="Suspicious service creation on HR-WKS-31",
            description=(
                "A service was created by a non-administrative account outside any "
                "change window, and the binary was written to disk minutes earlier by "
                "a process with no software-distribution parent. The account then "
                "authenticated off-box. No change ticket references this host."
            ),
            category="lateral_movement",
            severity_band=["medium", "high"],
            entry_host="HR-WKS-31",
            hops=[
                Hop(
                    host="HR-WKS-31",
                    message=(
                        "Service create: svc_update.exe installed by CORP\\d.moreau then "
                        "authenticated outbound to GEN-SRV-APP-12 over SMB"
                    ),
                    reveals="GEN-SRV-APP-12",
                ),
                Hop(
                    host="GEN-SRV-APP-12",
                    message=(
                        "Logon type 3 from HR-WKS-31 followed by credential material access "
                        "and an outbound session to GEN-SRV-DB-09"
                    ),
                    source="edr-telemetry",
                    reveals="GEN-SRV-DB-09",
                ),
                Hop(
                    host="GEN-SRV-DB-09",
                    message=(
                        "Bulk table export initiated by the account that arrived from "
                        "GEN-SRV-APP-12; 41GB staged to a local archive"
                    ),
                    source="db-audit",
                ),
            ],
            notes=(
                "Single-pass triage sees a service creation on one workstation. The "
                "database export two hops away is the actual incident, and is only "
                "reachable by following the evidence."
            ),
        ),
        Scenario(
            case_id="GEN-002-c2-fanout",
            title="Beaconing detected from GEN-WKS-88",
            description=(
                "Periodic outbound connections with low jitter were observed from a "
                "single workstation. The destination is not on any vendor allowlist."
            ),
            category="command_and_control",
            severity_band=["high", "critical"],
            entry_host="GEN-WKS-88",
            indicators=[{"indicator_type": "ipv4", "value": "203.0.113.45",
                         "context": "beacon destination"}],
            hops=[
                Hop(
                    host="GEN-WKS-88",
                    message=(
                        "Outbound tcp to 203.0.113.45:443 at fixed 60s interval; same "
                        "destination contacted by GEN-WKS-91"
                    ),
                    source="firewall",
                    reveals="GEN-WKS-91",
                ),
                Hop(
                    host="GEN-WKS-91",
                    message=(
                        "Outbound tcp to 203.0.113.45:443 matching the GEN-WKS-88 pattern; "
                        "parent process launched from GEN-SRV-FILE-14 share"
                    ),
                    source="firewall",
                    reveals="GEN-SRV-FILE-14",
                ),
                Hop(
                    host="GEN-SRV-FILE-14",
                    message=(
                        "Executable written to a public share and read by two workstations "
                        "within four minutes"
                    ),
                    source="file-audit",
                ),
            ],
            notes=(
                "A shared C2 destination is the pivot. The file server distributing the "
                "payload is the root cause and is two hops from the alert."
            ),
        ),
        Scenario(
            case_id="GEN-003-single-host-no-pivot",
            title="Failed logon burst on GEN-WKS-52",
            description=(
                "Twelve failed interactive logons for one account followed by a success, "
                "all from the console of a single managed workstation."
            ),
            category="credential_access",
            severity_band=["low", "medium"],
            entry_host="GEN-WKS-52",
            should_escalate=False,
            criticality="standard",
            reported_severity="low",
            hops=[
                Hop(
                    host="GEN-WKS-52",
                    message=(
                        "Repeated 4625 for CORP\\p.iversen from the local console, then 4624 "
                        "success; no network logon and no other host involved"
                    ),
                    source="windows-security",
                ),
            ],
            notes=(
                "The control case. Evidence is genuinely confined to one host, so the "
                "frontier must come back empty and the run must stay single-round. "
                "Without this, a loop that always pivots would score perfectly."
            ),
        ),
    ]


def _log_records(scenarios: list[Scenario]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, scenario in enumerate(scenarios):
        start = BASE_DATE + timedelta(days=index * SCENARIO_SPACING_DAYS)
        for step, hop in enumerate(scenario.hops):
            # Minutes apart, so the whole chain sits inside the correlation
            # window and the hops stay in causal order.
            moment = start + timedelta(minutes=step * 7)
            records.append(
                {
                    "log_id": f"GEN-{scenario.case_id[4:7]}-{step:02d}",
                    "timestamp": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "host": hop.host,
                    "source": hop.source,
                    "message": hop.message,
                }
            )
    return records


def _cases(scenarios: list[Scenario]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for index, scenario in enumerate(scenarios):
        detected = BASE_DATE + timedelta(days=index * SCENARIO_SPACING_DAYS, minutes=20)
        cases.append(
            {
                "case_id": scenario.case_id,
                "expected": {
                    "severity_band": scenario.severity_band,
                    "category": scenario.category,
                    "should_escalate": scenario.should_escalate,
                    "expected_entities": scenario.expected_entities,
                    "notes": scenario.notes,
                },
                "alert": {
                    "alert_id": f"EVAL-{scenario.case_id}",
                    "source": "EDR",
                    "title": scenario.title,
                    "description": scenario.description,
                    "detected_at": detected.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "reported_severity": scenario.reported_severity,
                    "assets": [
                        {
                            "name": scenario.entry_host,
                            "asset_type": "host",
                            "criticality": scenario.criticality,
                            "owner": "IT",
                        }
                    ],
                    "indicators": scenario.indicators,
                    "raw_event": {"detection_rule": f"GEN-RULE-{index:03d}"},
                },
            }
        )
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Print instead of writing.")
    args = parser.parse_args()

    scenarios = _scenarios()
    records = _log_records(scenarios)
    cases = _cases(scenarios)

    log_text = "\n".join(json.dumps(r) for r in records) + "\n"
    case_text = json.dumps(cases, indent=2) + "\n"

    if args.dry_run:
        print(f"{len(records)} log record(s), {len(cases)} case(s)")
        for scenario in scenarios:
            print(f"  {scenario.case_id:<32} pivots -> {scenario.expected_entities or '(none)'}")
        return 0

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CORPUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text(log_text, encoding="utf-8")
    CORPUS_FILE.write_text(case_text, encoding="utf-8")
    print(f"  wrote {len(records)} log record(s) to {LOG_FILE}")
    print(f"  wrote {len(cases)} case(s) to {CORPUS_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
