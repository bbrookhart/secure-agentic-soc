<div align="center">

# Control Mapping

**NIST SP 800-53 controls, how this system implements them, and where the evidence lives.**

[← Back to README](../README.md) · [Threat Model](THREAT_MODEL.md) · [Runbooks](RUNBOOKS.md)

</div>

---

## How to read this

Three columns matter, and the third is the one that makes this document worth anything:
**where the evidence is**. A mapping whose evidence column says "see the design document" is
two documents agreeing with each other.

```bash
make evidence          # generates the bundle this table points at
```

`python -m src.evidence` reads every value from the component that implements it — the
capability matrix from the identity registry, the approval rules from the policy engine, chain
status from verifying real records. **It can contradict this table**, and when it does, the
bundle is right: it describes the deployment, this describes the intent.

Status is stated honestly:

| | |
|:--|:--|
| **Implemented** | The control operates in code and the bundle demonstrates it. |
| **Partial** | Implemented with a stated limit; read the notes. |
| **Inherited** | Delegated to the deployment — proxy, volume, platform. This system provides the seam and refuses to pretend otherwise. |
| **Not applicable** | Out of scope for a single-node analysis tool, said plainly rather than omitted. |

> [!IMPORTANT]
> This is a **control mapping, not an authorization package**. It is the engineering half of
> what an assessor needs. Policy, personnel, physical and organisational controls are the
> deployment's responsibility and are not represented here.

---

## Access Control (AC)

| Control | Status | Implementation | Evidence |
|:--|:--|:--|:--|
| **AC-2** Account Management | Inherited | Identities and group membership come from the authenticating proxy; this system consumes them and maps groups to roles. It creates no accounts. | `src/security/approval_identity.py`, `authz.GROUP_ROLE_MAP` |
| **AC-3** Access Enforcement | Implemented | Two enforcement points: the tool broker authorises every agent capability call, and the approval gate authorises every human decision. Neither is advisory. | Bundle → *Least privilege*, *Approval authority*; `tools/base.py`, `security/authz.py` |
| **AC-4** Information Flow | Implemented | Untrusted content is sanitised, labelled and flagged at every boundary; policy inputs carry no free text so injected prose cannot reach a decision. | `security/sanitizer.py`, `PolicyInput`, `ApprovalContext` |
| **AC-5** Separation of Duties | Partial | Whoever initiates a run may not approve it (`AUTHZ-003`). **A single-operator deployment cannot satisfy this** and must disable it deliberately — that is a real reduction in control, not a formality. | `tests/test_authz.py::TestSeparationOfDuties`; bundle → posture |
| **AC-6** Least Privilege | Implemented | Statically declared capability sets per agent — the supervisor and reporter hold **none** — and severity/risk ceilings per human role. | Bundle → *Least privilege*, *Approval authority* |
| **AC-7** Unsuccessful Attempts | Partial | Authorization refusals are recorded and bounded (the gate halts after repeated refusals) but there is no account lockout; that belongs to the proxy. | `AuditAction.AUTHORIZATION_DENIED`, `MAX_AUTHORIZATION_DENIALS` |

---

## Audit and Accountability (AU)

| Control | Status | Implementation | Evidence |
|:--|:--|:--|:--|
| **AU-2** Event Logging | Implemented | A closed action vocabulary covering every routing decision, policy evaluation, tool call, model call, approval and refusal. Agents cannot write to the log, so *"do not log this"* is not an available action. | `src/enums.py::AuditAction` |
| **AU-3** Content of Records | Implemented | Typed records: actor, action, timestamp, duration, outcome, structured details. Emitted as JSONL for direct SIEM ingest. | `security/audit.py::AuditEvent` |
| **AU-6** Review and Reporting | Implemented | Metrics for the signals worth alerting on — injection rate, policy decisions by rule, authorization denials, approval queue age. | `observability/metrics.py` |
| **AU-8** Time Stamps | Implemented | UTC throughout, hashed into the chain so a timestamp cannot be edited independently. | `AuditEvent.payload_for_hash` |
| **AU-9** Protection of Audit Information | Partial | SHA-256 hash chain, Ed25519 signatures, optional off-host forwarding, secret redaction on the way in. **An attacker holding the signing key can still forge.** Use a KMS/HSM; `AuditSigner` is the seam. | Bundle → *Audit chain verification*; `tests/test_audit_integrity.py` |
| **AU-10** Non-repudiation | Implemented | Records are signed, so a verifier holding only the public key can attribute them. A recomputed chain passes structural verification and fails signature verification — demonstrated by test. | `test_a_recomputed_chain_still_fails_signature_verification` |
| **AU-11** Retention | Implemented | Size-based rotation with a segment cap; case history pruned by age. Verification reads across segments, so rotation does not resemble truncation. | Bundle → posture; `security/audit_sink.py` |
| **AU-12** Audit Generation | Implemented | Emitted by the broker and graph nodes, not by agents — the components with authority, not the ones with reasoning. | `tools/base.py`, `graph.py` |

---

## Configuration Management (CM)

| Control | Status | Implementation | Evidence |
|:--|:--|:--|:--|
| **CM-2** Baseline Configuration | Implemented | Settings are read in exactly one module; the effective posture is emitted in the bundle rather than described. | `src/config.py`; bundle → posture |
| **CM-3** Change Control | Implemented | Prompts are versioned and hashed; the evaluation baseline records the prompt manifest and model digest that produced it, and CI flags a stale comparison before any metric is read. | `src/prompts/`, `evals/baselines/`, `evals/summary.py` |
| **CM-5** Access Restrictions for Change | Implemented | CODEOWNERS requires security review on the control plane, the capability surface, the prompts, and the corpus. | `.github/CODEOWNERS` |
| **CM-7** Least Functionality | Implemented | No shell, subprocess, arbitrary HTTP or file-write capability exists in the tool layer, asserted by an AST-level test. | `tests/test_tools.py` |
| **CM-14** Signed Components | Implemented | Container images are Sigstore-signed with SLSA provenance and an SBOM attestation. | `.github/workflows/release.yml` |

---

## Contingency Planning (CP)

| Control | Status | Implementation | Evidence |
|:--|:--|:--|:--|
| **CP-9** Backup | Implemented | Archives audit log, signing key, checkpoints and case history. The key is included because a restored log nobody can verify is not evidence — **which makes the backup forgeable material**; encrypt it and store it apart. | `scripts/backup.sh`, [RUNBOOKS §7](RUNBOOKS.md) |
| **CP-10** Recovery | Implemented | Runs resume from checkpoints across processes; restore refuses to overwrite live state, since merging two histories produces a chain nobody can reason about. | `graph.py::build_checkpointer` |

---

## Identification and Authentication (IA)

| Control | Status | Implementation | Evidence |
|:--|:--|:--|:--|
| **IA-2** Identification and Authentication | Inherited | Approver identity comes from an authenticating proxy; the gate fails closed without it. **Only as strong as the deployment**: the proxy must strip the header inbound and the app must be reachable only through it. | `security/approval_identity.py` |
| **IA-8** Non-organisational Users | Not applicable | No external user interface exists. | — |

---

## Incident Response (IR)

| Control | Status | Implementation | Evidence |
|:--|:--|:--|:--|
| **IR-4** Incident Handling | Implemented | Runbooks for when this system is the problem, and an operating-mode kill switch that withdraws autonomy in seconds without a redeploy. | [RUNBOOKS.md](RUNBOOKS.md), `security/operating_mode.py` |
| **IR-5** Incident Monitoring | Implemented | Security-specific metrics, including approval queue age — a gate nobody answers is a failed control that looks identical to a working one. | `observability/metrics.py` |

---

## Risk Assessment (RA)

| Control | Status | Implementation | Evidence |
|:--|:--|:--|:--|
| **RA-3** Risk Assessment | Implemented | Threat model with residual risk stated per threat, including what the controls do *not* cover. | [THREAT_MODEL.md](THREAT_MODEL.md) |
| **RA-5** Vulnerability Monitoring | Implemented | Dependency CVEs, secret scanning, SAST and container scanning in CI. Suppressions require a written reachability argument or the audit refuses to run. | `scripts/audit_deps.py`, [DEPENDENCY_EXCEPTIONS.md](DEPENDENCY_EXCEPTIONS.md) |

---

## System and Services Acquisition (SA)

| Control | Status | Implementation | Evidence |
|:--|:--|:--|:--|
| **SA-11** Developer Testing | Implemented | 294 tests, a 35-case labelled evaluation whose **security invariants gate the build** while quality metrics are reported and never enforced, plus scheduled red-teaming. | Bundle → *Evaluation*; `.github/workflows/` |
| **SA-15** Development Process | Implemented | NIST SSDF practices in CI — see the mapping below. | `.github/workflows/ci.yml` |

---

## System and Communications Protection (SC)

| Control | Status | Implementation | Evidence |
|:--|:--|:--|:--|
| **SC-5** Denial of Service | Implemented | Per-principal rate limits, per-run tool budgets, supervisor turn caps, a model circuit breaker, and container resource limits. | Bundle → posture; `security/ratelimit.py` |
| **SC-7** Boundary Protection | Implemented | Tools make no network calls at all; the only outbound code is the ingestion adapters, which run before the pipeline and are unreachable from any agent. | `src/ingest/siem.py`, `tests/test_tools.py` |
| **SC-12/13** Cryptography | Implemented | Ed25519 for audit signing, SHA-256 for chaining and fingerprints. Key generated `0600` via `O_EXCL`. | `security/signing.py` |
| **SC-28** Protection at Rest | Inherited | Deliberately **not** implemented in the application: app-level encryption would put the keys in the process holding the data. Volume-level is the deployment's job; the bundle reports the operator's assertion **as an assertion**. | Bundle → posture |

---

## System and Information Integrity (SI)

| Control | Status | Implementation | Evidence |
|:--|:--|:--|:--|
| **SI-4** System Monitoring | Implemented | Golden signals plus security signals; readiness checks split critical from degraded so a missing model does not become an outage. | `observability/health.py` |
| **SI-7** Software and Information Integrity | Implemented | Hash-pinned dependencies installed with `--require-hashes`, model digest recorded and optionally pinned, prompts hashed, immutable fingerprinted alerts, validated phase transitions. | Bundle → *Provenance*, *Supply chain* |
| **SI-10** Input Validation | Implemented | Every alert enters through one strict validator; every tool argument is schema-checked; every model output is Pydantic-validated before becoming state. | `ingest/base.py::parse_alert`, `tools/base.py` |
| **SI-12** Information Management | Implemented | Retention for both audit and case history, with the trade-off stated: correlation cannot see past its window. | Bundle → posture |

---

## NIST SSDF (SP 800-218)

| Practice | Implementation |
|:--|:--|
| **PS.1** Protect code | Branch protection with CODEOWNERS review on the control plane. |
| **PS.2** Verify integrity | Sigstore signing and SLSA provenance on release artefacts. |
| **PS.3** Archive and protect releases | SBOM generated and attested per release, retained 365 days. |
| **PW.4** Reuse secure software | Hash-pinned lockfile; every dependency CVE triaged with a reachability argument. |
| **PW.7** Review code | Required review on security-relevant paths; SAST on every pull request. |
| **PW.8** Test executable code | Unit, integration, and adversarial evaluation; invariants gate the build. |
| **RV.1** Identify vulnerabilities | `pip-audit`, `gitleaks`, `semgrep`, `trivy` in CI; scheduled red-team run. |
| **RV.2** Assess and remediate | Documented exception process with expiry; reachable findings are fixed, not suppressed. |

---

## What this mapping does not claim

- **No FIPS-validated cryptography.** `cryptography` is used in its default configuration.
- **No multi-tenancy.** State, checkpoints, audit and case history are single-tenant.
- **No continuous monitoring programme.** The signals exist; operating them is the deployment's.
- **AC-5 is conditional.** Single-operator deployments must disable it.
- **AU-9 has a stated ceiling.** An attacker holding the signing key can forge; a KMS moves
  that ceiling and this system provides the seam but not the KMS.
