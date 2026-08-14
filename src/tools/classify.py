"""``classify_alert`` -- deterministic rule-based alert classification.

This tool exists so that triage has a **non-LLM backstop**.  The LLM produces a
richer narrative, but the numbers it is graded against come from a transparent,
inspectable rule set that an analyst can read, argue with and tune.  When the
model is unavailable or returns nonsense, this is what the pipeline falls back
to -- so the system degrades to "deterministic and explainable" rather than to
"broken".

Scores are intentionally simple keyword-weight sums.  A real deployment would
back this with detection-engineering content; the structure would be identical.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from src.enums import ActionRisk, AlertCategory, Severity
from src.tools.base import SOCTool

# Weighted signal keywords per category.  Weight reflects how strongly the term
# implies that category, not how bad it is.
_CATEGORY_SIGNALS: dict[AlertCategory, dict[str, float]] = {
    AlertCategory.MALWARE: {
        "ransomware": 4.0, "encrypt": 2.5, "simlock": 3.0, "ransom note": 3.0,
        "malware": 3.0, "payload": 1.5, "dropper": 2.5, "trojan": 3.0,
        "unsigned": 1.0, "quarantine": 1.5, "shadow copy": 2.0, "vssadmin": 2.5,
    },
    AlertCategory.PHISHING: {
        "phishing": 4.0, "spearphishing": 4.0, "email": 1.5, "spf": 2.0,
        "dkim": 2.0, "dmarc": 2.0, "attachment": 1.5, "credential harvest": 3.0,
        "typosquat": 2.5, "login page": 2.0, "mailbox rule": 2.0, "lure": 2.0,
    },
    AlertCategory.CREDENTIAL_ACCESS: {
        "brute force": 4.0, "password spray": 4.0, "failed login": 2.5,
        "authentication failure": 2.5, "lsass": 3.5, "mimikatz": 4.0,
        "credential dump": 4.0, "4625": 2.0, "stolen password": 2.5, "ntds": 3.0,
    },
    AlertCategory.LATERAL_MOVEMENT: {
        "lateral movement": 4.0, "rdp": 2.5, "psexec": 3.0, "smb": 2.0,
        "admin$": 2.5, "logon type 3": 2.0, "logon type 10": 2.0, "pivot": 2.0,
        "remote desktop": 2.5,
    },
    AlertCategory.DATA_EXFILTRATION: {
        "exfiltration": 4.0, "exfil": 3.5, "large transfer": 3.0, "upload": 2.0,
        "outbound transfer": 3.0, "data transfer": 2.0, "7z": 1.5,
        "archive": 1.5, "cloud storage": 2.0, "gb": 1.0, "dlp": 2.0,
    },
    AlertCategory.COMMAND_AND_CONTROL: {
        "command and control": 4.0, "c2": 4.0, "beacon": 3.5, "cobalt strike": 4.0,
        "callback": 2.0, "dns tunnel": 3.5, "jitter": 2.5, "periodic": 1.5,
    },
    AlertCategory.PRIVILEGE_ESCALATION: {
        "privilege escalation": 4.0, "elevated": 2.0, "administrators group": 3.0,
        "4732": 2.5, "uac bypass": 3.0, "token": 1.5, "sudo": 2.0,
    },
    AlertCategory.PERSISTENCE: {
        "persistence": 4.0, "scheduled task": 3.0, "run key": 3.0, "registry run": 3.0,
        "autostart": 2.5, "startup folder": 2.5, "4720": 2.0, "account created": 2.0,
        "service created": 2.0,
    },
    AlertCategory.RECONNAISSANCE: {
        "reconnaissance": 4.0, "port scan": 3.0, "net view": 2.5, "enumerate": 2.0,
        "discovery": 2.5, "nmap": 3.0, "ping sweep": 3.0, "scan": 1.5,
    },
    AlertCategory.POLICY_VIOLATION: {
        "policy violation": 4.0, "unauthorized software": 2.5, "pua": 2.5,
        "keygen": 2.5, "crack": 2.5, "usb": 1.5, "unsanctioned": 2.0,
    },
    AlertCategory.BENIGN_OR_FALSE_POSITIVE: {
        "false positive": 4.0, "benign": 3.5, "known vpn": 3.0, "expected": 2.0,
        "approved change": 3.0, "sanctioned": 2.5, "asset inventory": 2.0,
        "change window": 2.5, "managed device": 1.5, "signed_script": 2.0,
        "corporate vpn": 3.0, "blocked": 1.5, "quarantined": 2.0,
    },
}

# Terms that raise severity regardless of category.
_SEVERITY_SIGNALS: dict[str, float] = {
    "ransomware": 5.0, "encrypt": 3.0, "mass file": 3.5, "shadow copy": 3.0,
    "exfiltration": 4.0, "domain admin": 4.0, "credential dump": 4.0,
    "lsass": 3.0, "c2": 3.0, "beacon": 2.5, "critical": 2.5, "production": 2.0,
    "defender": 2.0, "disabled": 2.0, "spray": 2.5, "8.4 gb": 3.0,
    "privilege escalation": 3.0, "lateral movement": 3.0,
}

# Terms that lower severity -- evidence of containment or benign explanation.
_MITIGATING_SIGNALS: dict[str, float] = {
    "blocked": 3.0, "quarantined": 3.0, "denied": 2.5, "prevented": 3.0,
    "false positive": 5.0, "known vpn": 4.0, "corporate vpn": 4.0,
    "approved change": 4.0, "sanctioned": 3.0, "change window": 3.0,
    "no execution": 3.0, "mfa satisfied": 2.0, "managed device": 1.5,
}

# Category -> candidate ATT&CK techniques for the hunter to verify.
_CATEGORY_TECHNIQUES: dict[AlertCategory, tuple[str, ...]] = {
    AlertCategory.MALWARE: ("T1486", "T1490", "T1059.001"),
    AlertCategory.PHISHING: ("T1566", "T1566.002", "T1078"),
    AlertCategory.CREDENTIAL_ACCESS: ("T1110", "T1110.003", "T1003.001"),
    AlertCategory.LATERAL_MOVEMENT: ("T1021.001", "T1021.002", "T1078"),
    AlertCategory.DATA_EXFILTRATION: ("T1041", "T1567.002"),
    AlertCategory.COMMAND_AND_CONTROL: ("T1071.001", "T1071.004", "T1105"),
    AlertCategory.PRIVILEGE_ESCALATION: ("T1078", "T1098"),
    AlertCategory.PERSISTENCE: ("T1547.001", "T1053.005", "T1136.001"),
    AlertCategory.RECONNAISSANCE: ("T1018", "T1087"),
    AlertCategory.POLICY_VIOLATION: (),
    AlertCategory.BENIGN_OR_FALSE_POSITIVE: (),
    AlertCategory.UNKNOWN: (),
}


class ClassifyAlertInput(BaseModel):
    """Input schema for ``classify_alert``."""

    alert_summary: str = Field(
        min_length=8,
        max_length=8000,
        description="Alert title, description and salient raw fields, concatenated.",
    )
    reported_severity: Severity = Field(
        default=Severity.MEDIUM,
        description="Severity claimed by the detection source, used as a prior.",
    )

    @field_validator("alert_summary")
    @classmethod
    def _must_have_substance(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("alert_summary must not be blank")
        return value


def _score(text: str, signals: dict[str, float]) -> tuple[float, list[str]]:
    total = 0.0
    matched: list[str] = []
    for term, weight in signals.items():
        if term in text:
            total += weight
            matched.append(term)
    return total, matched


def classify_alert(payload: ClassifyAlertInput) -> dict[str, Any]:
    """Classify an alert into severity, category and confidence."""
    text = payload.alert_summary.lower()

    # --- Category ---------------------------------------------------------
    category_scores: dict[AlertCategory, float] = {}
    category_matches: dict[AlertCategory, list[str]] = {}
    for category, signals in _CATEGORY_SIGNALS.items():
        score, matched = _score(text, signals)
        if score > 0:
            category_scores[category] = score
            category_matches[category] = matched

    if category_scores:
        best_category = max(category_scores, key=lambda c: category_scores[c])
        best_score = category_scores[best_category]
        runner_up = sorted(category_scores.values(), reverse=True)
        margin = best_score - (runner_up[1] if len(runner_up) > 1 else 0.0)
    else:
        best_category, best_score, margin = AlertCategory.UNKNOWN, 0.0, 0.0

    # --- Severity ---------------------------------------------------------
    aggravating, aggravating_terms = _score(text, _SEVERITY_SIGNALS)
    mitigating, mitigating_terms = _score(text, _MITIGATING_SIGNALS)

    # Start from the reporter's severity, then move it on evidence.
    base = float(payload.reported_severity.rank)
    adjustment = (aggravating / 6.0) - (mitigating / 6.0)
    severity_value = base + adjustment

    if best_category is AlertCategory.BENIGN_OR_FALSE_POSITIVE and mitigating > aggravating:
        severity_value = min(severity_value, 1.0)

    severity_rank = max(0, min(4, round(severity_value)))
    severity = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL][severity_rank]

    # --- Confidence -------------------------------------------------------
    # High when one category clearly dominates and there is decisive evidence
    # either way; low when signals are sparse or contradictory.
    evidence = best_score + aggravating + mitigating
    confidence = 0.30 + min(0.40, evidence / 30.0) + min(0.20, margin / 10.0)
    if best_category is AlertCategory.UNKNOWN:
        confidence = min(confidence, 0.35)
    if aggravating > 0 and mitigating > 0 and abs(aggravating - mitigating) < 2.0:
        confidence -= 0.15  # genuinely ambiguous
    confidence = round(max(0.05, min(0.95, confidence)), 2)

    observations: list[str] = []
    if category_matches.get(best_category):
        observations.append(
            f"Category signals matched: {', '.join(sorted(category_matches[best_category])[:6])}."
        )
    if aggravating_terms:
        observations.append(f"Aggravating factors: {', '.join(sorted(aggravating_terms)[:6])}.")
    if mitigating_terms:
        observations.append(f"Mitigating factors: {', '.join(sorted(mitigating_terms)[:6])}.")
    if not observations:
        observations.append("No known signal keywords matched; classification is low confidence.")

    return {
        "severity": severity.value,
        "category": best_category.value,
        "confidence": confidence,
        "rationale": (
            f"Rule-based classifier scored '{best_category.value}' highest ({best_score:.1f} points, "
            f"margin {margin:.1f}). Reported severity '{payload.reported_severity.value}' adjusted by "
            f"{adjustment:+.2f} from {aggravating:.1f} aggravating and {mitigating:.1f} mitigating "
            f"points, giving '{severity.value}'."
        ),
        "key_observations": observations,
        "suggested_techniques": list(_CATEGORY_TECHNIQUES.get(best_category, ())),
        "scores": {
            "category_scores": {c.value: round(s, 2) for c, s in sorted(
                category_scores.items(), key=lambda kv: kv[1], reverse=True
            )[:5]},
            "aggravating": round(aggravating, 2),
            "mitigating": round(mitigating, 2),
        },
    }


CLASSIFY_ALERT_TOOL = SOCTool(
    name="classify_alert",
    description=(
        "Classify an alert summary into severity, category, confidence and candidate "
        "ATT&CK techniques using a deterministic rule set. Read-only; no side effects."
    ),
    input_model=ClassifyAlertInput,
    handler=classify_alert,
    risk=ActionRisk.READ_ONLY,
    # Output is derived from our own rule set, but the alert text it echoes
    # back into rationale/observations is attacker-influenced.
    returns_untrusted=True,
)
