<div align="center">

# Dependency Exceptions

**Every suppressed vulnerability, why it is suppressed, and when that reasoning expires.**

[← Back to README](../README.md) · [Threat Model](THREAT_MODEL.md)

</div>

---

## How to read this file

`pip-audit` runs in CI against `requirements.lock` and fails the build on any known
vulnerability. Suppressions live in [`.pip-audit-ignore`](../.pip-audit-ignore) and **every one
of them must appear here with a reachability argument** — not a severity opinion.

The distinction matters. "Low severity" is someone else's judgement about someone else's
deployment. "There is no call site" is a fact about this one, and it can be re-checked with a
grep. Only the second kind of argument is accepted here.

A suppression is not permanent. Each carries a review date. When the date passes, the
suppression is re-argued or removed — an exception nobody revisits is an exception that
outlives its reasoning.

> [!IMPORTANT]
> Suppressing a finding because the fix is inconvenient is how a scanner becomes decoration.
> If a vulnerability is reachable, it is not suppressed here — it is fixed, or it is accepted
> as risk by an owner and recorded in [§ Accepted risk](#accepted-risk) with compensating
> controls.

---

## Suppressed — not reachable

Verified against the codebase on **2026-08-18**. Each row's claim is checkable by the grep in
its rationale.

| ID | Package | Why it is not reachable here | Review by |
|:--|:--|:--|:--|
| `PYSEC-2026-2193` | `langchain-core` | Path traversal in `langchain_core.prompts.loading`. Requires `load_prompt()` / `load_prompt_from_config()` with a caller-influenced config. This project has no such call — prompts are inline module constants, moving to versioned files in `src/prompts/`. `grep -rn "load_prompt\|prompts.loading" src/` returns nothing. | 2026-11-18 |
| `PYSEC-2026-2562` | `langchain-core` | SSRF in `ChatOpenAI.get_num_tokens_from_messages()` fetching `image_url`. Requires `ChatOpenAI` and vision input. Inference is local-only through `langchain-ollama`; there is no OpenAI client and no image path anywhere. `grep -rn "ChatOpenAI\|image_url\|get_num_tokens" src/` returns nothing. | 2026-11-18 |
| `PYSEC-2026-2574` | `langgraph-checkpoint` | RCE via `pickle` fallback in the node-caching layer. Requires a `BaseCache` backend and nodes opted in with `CachePolicy`. No node caching is configured. `grep -rn "CachePolicy\|BaseCache" src/` returns nothing. | 2026-11-18 |
| `PYSEC-2026-2194` | `langgraph`, `langgraph-sdk` | URL path injection in the SDK's request construction. Requires using `langgraph-sdk` to call a LangGraph API server. The SDK is a transitive dependency with no call site; this system runs the graph in-process. `grep -rn "langgraph_sdk" src/` returns nothing. | 2026-11-18 |
| `PYSEC-2026-2575` | `langgraph-sdk` | Same SDK path-construction issue, same reasoning. | 2026-11-18 |
| `PYSEC-2026-3636` | `langgraph-checkpoint-sqlite` | Namespace prefix confusion in `BaseStore` — scoped `search` / `list_namespaces` matching sibling namespaces via `LIKE`. This affects the *store*, not the *checkpointer*. No store is used. `grep -rn "BaseStore\|list_namespaces" src/` returns nothing. | 2026-11-18 |
| `CVE-2025-67644` | `langgraph-checkpoint-sqlite` | SQL injection through untrusted checkpoint-search **metadata filter keys**. Checkpoint search is never called; thread ids are the only checkpoint identifiers used and they are generated internally (`run-<uuid4>`), never taken from alert content. | 2026-11-18 |

---

## Accepted risk

### Checkpoint deserialization — `PYSEC-2026-1527`, `PYSEC-2026-2573`, `PYSEC-2026-83`

**These are reachable. They are not suppressed, and CI fails on them until a decision is
recorded here by an owner.**

`langgraph-checkpoint`'s `JsonPlusSerializer` reconstructs Python objects when loading a
checkpoint. An attacker who can write to the checkpoint store can craft a payload that executes
code at load time.

This system uses `SqliteSaver` with the default serializer
([`graph.py:450`](../src/graph.py#L450)) and persists checkpoints to
`state/checkpoints.sqlite`. Reloading them in a *different process* is not incidental — it is
the mechanism the human-in-the-loop gate is built on. An analyst approving hours later, from
the CLI or the console, is a checkpoint load by definition.

**Verified against the pinned versions, 2026-08-18.** Two things were checked directly rather
than inferred from the advisory text, because the advisories describe a range of versions and
the details differ in ours:

- **Constructor revival from written bytes: CONFIRMED reachable.** Calling
  `JsonPlusSerializer().loads_typed(("json", ...))` on a payload shaped
  `{"lc": 2, "type": "constructor", "id": [...], "kwargs": {...}}` reconstructs the named
  object. Demonstrated with a benign target (`datetime.date`); the advisory's own proof of
  concept uses `["os", "system"]`. With `langgraph-checkpoint` 2.1.2 there is no
  `allowed_msgpack_modules` attribute, so the allowlist hardening the advisory recommends is
  not available without upgrading.
- **Reaching it from alert content alone: NOT reachable in this version.** The advisory's PoC
  triggers the JSON fallback with a lone Unicode surrogate in state. In 2.1.2 `dumps_typed`
  raises `TypeError: string contains surrogates` instead of falling back, and normal payloads
  serialize as `msgpack`. So a hostile alert cannot by itself get a constructor payload into a
  checkpoint. Recorded here so the question is not re-opened from the advisory text alone.

**Why this still matters more than the CVSS score suggests.** The threat model
([THREAT_MODEL.md](THREAT_MODEL.md)) reasons in places from *"an attacker with file write
access **and** code execution"* — for instance when explaining why the audit chain is
tamper-evident rather than tamper-proof. This vulnerability collapses that conjunction: on the
state volume, **file write becomes code execution**, and that is now demonstrated rather than
assumed. Any argument in the threat model that treats those as separate capabilities needs
re-reading in that light. The checkpoint store has to be treated as integrity-sensitive
storage, at the same level as the audit log.

**Fix:** upgrade `langgraph-checkpoint` to ≥ 4.1.1, which entails `langgraph` ≥ 1.0.10,
`langchain-core` ≥ 1.2.22 and `langgraph-checkpoint-sqlite` ≥ 3.1.1. The current ranges in
`requirements.txt` (`langgraph>=0.2.60,<0.3`) pin the project *below* every fixed version, so
the constraint itself is the blocker — this cannot be resolved by relocking.

**Compensating controls, pending upgrade** — mitigating, not sufficient:

- The container runs as an unprivileged user with `/app/state` as the only writable path, and
  the application tree mounted read-only ([`Dockerfile`](../Dockerfile),
  [`docker-compose.yml`](../docker-compose.yml)).
- Restrict filesystem access to the state volume to the service account alone.
- Volume-level encryption at rest.
- The audit log is forwarded off-host, so tampering that follows a compromise is still
  detectable even though this vulnerability precedes it.

**Status:** open — awaiting an upgrade decision. No expiry is set, because an accepted risk with
no owner and no date is an ignored one.

---

## Adding an exception

1. Establish that there is **no reachable call site**, and record the grep that shows it.
2. Add the ID to [`.pip-audit-ignore`](../.pip-audit-ignore) with a one-line reason.
3. Add a row above, including a review date no more than 90 days out.
4. If the vulnerability *is* reachable, do not add it here. Fix it, or record it under
   [§ Accepted risk](#accepted-risk) with an owner, compensating controls, and a plan.
