<div align="center">

# Dependency Exceptions

**Every suppressed vulnerability, why it is suppressed, and when that reasoning expires.**

[← Back to README](../README.md) · [Threat Model](THREAT_MODEL.md)

</div>

---

## Current status

**No active exceptions.** `pip-audit` reports zero known vulnerabilities against
[`requirements.lock`](../requirements.lock), with nothing suppressed. Verified 2026-08-18.

That is the state worth defending. Every entry in
[`.pip-audit-ignore`](../.pip-audit-ignore) is a small piece of scanner coverage given up, so
the list should stay empty unless there is a reason it cannot.

---

## How this works

`pip-audit` runs in CI against the lockfile and fails the build on any known vulnerability.
Suppressions live in [`.pip-audit-ignore`](../.pip-audit-ignore) and **every one must appear
here with a reachability argument** — not a severity opinion.

The distinction matters. *"Low severity"* is someone else's judgement about someone else's
deployment. *"There is no call site"* is a fact about this one, and it can be re-checked with a
grep. Only the second kind is accepted.

[`scripts/audit_deps.py`](../scripts/audit_deps.py) is the only entry point — `make audit-deps`
and CI both go through it — and it refuses to run if any suppressed ID lacks a written
justification here. The list and the reasoning cannot drift apart.

> [!IMPORTANT]
> Suppressing a finding because the fix is inconvenient is how a scanner becomes decoration.
> A reachable vulnerability is fixed, or it is accepted as risk by a named owner with
> compensating controls and a date — never quietly ignored.

### Adding an exception

1. Establish that there is **no reachable call site**, and record the grep that shows it.
2. Add the ID to [`.pip-audit-ignore`](../.pip-audit-ignore) with a one-line reason.
3. Add a row here, with a review date no more than 90 days out.
4. If the vulnerability **is** reachable, do not add it. Fix it, or record it as accepted risk
   with an owner, compensating controls, and a plan.

---

## Resolved — 2026-08-18

The first CI run of the supply-chain job reported **12 known vulnerabilities across 5 packages**
in the pinned LangGraph / LangChain stack. All are now resolved by upgrade. Recorded here
because the reasoning is worth keeping, particularly the part that turned out to matter.

### The one that was reachable

`PYSEC-2026-1527`, `PYSEC-2026-2573`, `PYSEC-2026-83` — `JsonPlusSerializer` reconstructed
arbitrary Python objects when loading a checkpoint. An attacker able to write checkpoint bytes
could execute code at load time.

This system was squarely in scope. It persists checkpoints with `SqliteSaver`
([`graph.py`](../src/graph.py)) and reloads them **in a different process every time an analyst
answers the approval gate** — that is the mechanism the human-in-the-loop design is built on,
not an incidental behaviour.

Two things were verified directly rather than inferred from the advisories, because the
advisories cover version ranges and the details differed in ours:

| Claim | Result on the old pins (`langgraph-checkpoint` 2.1.2) |
|:--|:--|
| Constructor revival from written bytes | **Confirmed reachable.** `loads_typed(("json", …))` on a `{"lc": 2, "type": "constructor", "id": [...]}` payload reconstructed the named object. Demonstrated with a benign `datetime.date`; the advisory's own PoC uses `["os", "system"]`. |
| Reachable from hostile alert content alone | **No.** The advisory's PoC triggers the JSON fallback with a lone Unicode surrogate in state; in 2.1.2 `dumps_typed` raised `TypeError: string contains surrogates` instead of falling back. A hostile alert could not by itself get a constructor payload into a checkpoint. |

**Why it mattered more than the CVSS score suggested.** The threat model
([THREAT_MODEL.md](THREAT_MODEL.md)) reasons in places from *"an attacker with file write access
**and** code execution"* — that conjunction is why the audit chain is described as
tamper-evident rather than tamper-proof. On the state volume this vulnerability collapsed it:
**file write became code execution.** The checkpoint store is therefore integrity-sensitive
storage at the same level as the audit log, and is now documented as such.

### The other nine

No reachable call site, each checked against the code: prompt-loading path traversal
(no `load_prompt` call), `ChatOpenAI` SSRF (local Ollama only, no vision), `pickle` fallback in
the node-caching layer (no `CachePolicy`), `langgraph-sdk` URL path injection (transitive, the
graph runs in-process), `BaseStore` namespace confusion (no store), and SQL injection via
checkpoint-search metadata keys (search is never called; thread ids are internally generated).

These were suppressed with justification at the time. The upgrade removed them, so the
suppressions were deleted rather than left to rot.

### The fix

| Package | Was | Now | Floor set by |
|:--|:--|:--|:--|
| `langgraph` | 0.2.76 | 1.2.11 | `PYSEC-2026-83` (≥ 1.0.10) |
| `langgraph-checkpoint` | 2.1.2 | 4.2.0 | `PYSEC-2026-1527`, `PYSEC-2026-2573` (≥ 4.1.1) |
| `langgraph-checkpoint-sqlite` | 2.0.11 | 3.1.1 | `PYSEC-2026-3636`, `CVE-2025-67644` |
| `langchain-core` | 0.3.86 | 1.5.6 | `PYSEC-2026-2193`, `PYSEC-2026-2562` |
| `langchain-ollama` | 0.2.3 | 1.1.0 | compatibility with the above |

The old ranges (`langgraph>=0.2.60,<0.3`) pinned the project *below* every fixed version, so the
constraint itself was the blocker — relocking could not have helped. The floors in
[`requirements.txt`](../requirements.txt) are annotated with the advisory that sets each one.

**Upgrading alone was not the whole fix.** It closes the JSON constructor path — a payload
naming `os.system` now comes back as an inert dict — but msgpack deserialization defaults to
*warn-and-allow*, reconstructing any type and printing a deprecation notice. So
[`graph.py`](../src/graph.py) passes an explicit `allowed_msgpack_modules` allowlist derived
from this project's own state vocabulary (`src.state`, `src.enums`, `src.security.audit`, 28
types). Both checkpointers use it, so tests exercise the configuration that ships, and it is
passed explicitly rather than via `LANGGRAPH_STRICT_MSGPACK` so the control does not depend on
an environment variable someone forgot to set.

Both halves are pinned by tests in
[`tests/test_supply_chain.py`](../tests/test_supply_chain.py): execution primitives must not
revive, this project's own types must still round-trip, the allowlist must not widen beyond
those three modules, and the installed versions must stay at or above the security floors.
