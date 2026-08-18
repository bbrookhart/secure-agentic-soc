<div align="center">

# Runbooks

**What to do when this system is the problem.**

[← Back to README](../README.md) · [Threat Model](THREAT_MODEL.md)

</div>

---

Most incident runbooks describe responding to an attack *with* your tools. These describe
responding to a problem *in* one — an agentic system whose analysis may be wrong, manipulated,
or unattributable. That is a different question, and it needs answering before it is asked.

The first entry is the one to read now rather than during an incident.

---

## 1 · Stop autonomous completion

**When:** a prompt-injection campaign is underway, a model was swapped, analysis has started
looking wrong, or you simply do not trust today's verdicts.

```bash
python -m src.run_cli --mode review_all --reason "suspected injection campaign, ticket INC-1234"
```

Every run now reaches a human regardless of policy (`HITL-000-autonomy-suspended`). The system
keeps triaging, enriching and reporting — it just stops concluding anything on its own.

Escalate if that is not enough:

| Mode | Effect |
|:--|:--|
| `review_all` | Everything gates. Analysis continues. |
| `drain` | In-flight runs finish; no new runs accepted. |
| `halt` | No new runs; in-flight runs stop at their next supervisor turn. |

The mode lives in `state/operating_mode` and is read on every routing decision, so it takes
effect immediately — **no redeploy, no restart**. Returning to `normal` is audited too; that
is the change a reviewer will ask about.

```bash
python -m src.run_cli --mode              # what is it now?
python -m src.run_cli --mode normal --reason "campaign contained, ticket INC-1234"
```

---

## 2 · Audit chain verification failed

```
Status : TAMPERING DETECTED
Detail : content tampered at sequence 54: hash mismatch
```

**Do not restart anything.** A restart writes new events and complicates the picture.

1. **Narrow the claim.** Which failed — the hash chain, or the signature?

   ```bash
   python -m src.run_cli --verify-audit <thread-id>
   ```

   *Hash mismatch* means the file was edited. *Signature invalid* means it was edited by
   someone without the signing key — a recomputed chain. *Sequence gap* can also mean a
   rotation segment was deleted, which is the benign explanation worth ruling out first.

2. **Compare with what left the host.** If forwarding is configured, the external copy is the
   authority. Anchors (`audit_anchor` events) state where the chain stood at a point in time
   and cannot be retracted once forwarded. A local log that disagrees with an anchor is the
   finding.

3. **If they disagree, treat the host as compromised.** An attacker who can rewrite the audit
   log had file write, and — per the checkpoint deserialisation entry in
   [DEPENDENCY_EXCEPTIONS.md](DEPENDENCY_EXCEPTIONS.md) — file write on the state volume has
   historically meant code execution. Assume both.

4. **Rotate the signing key** after any suspected host compromise. A key that may have been
   read can no longer attribute anything.

---

## 3 · Audit forwarding is failing

Readiness reports `audit_forwarding: DEGRADED`, or `soc.audit.forward.failures` is climbing.

Forwarding that fails silently is worse than none, because it looks like a control that is
running. While it is down, the local chain is **tamper-evident but not anchored**: an attacker
with code execution could rewrite it and there would be nothing off-host to disagree.

1. Confirm the collector is reachable and accepting writes.
2. Decide explicitly whether to keep running. Investigations continue during an outage by
   design — the local write never depends on the forwarder — but the window is one where audit
   integrity rests on the signing key alone.
3. After recovery, no backfill happens. Note the gap; it is a real hole in coverage.

---

## 4 · The approval queue is not being answered

`soc.approval.wait` is climbing, or runs are sitting in `AWAITING_APPROVAL`.

**A gate nobody answers is a failed control that looks exactly like a working one.** The
system is behaving correctly and the incident is entirely organisational.

1. Find them: runs in `awaiting_approval` with old `approval_requested` events.
2. Check whether it is an authorization problem rather than an attention problem — repeated
   `authorization_denied` events mean people are trying and being refused, most often because
   the incident needs a `senior_analyst` and only analysts are on shift.
3. If nobody with the authority is available, that is the finding. Escalate to whoever can
   grant it; do not widen the role matrix during an incident.

---

## 5 · A second instance will not start

```
error: another instance is already using this state directory (pid=1234)
```

Working as intended. Two instances against one state directory would silently multiply the
tool rate limit and can corrupt the audit chain for a resumed run.

- If the other instance is legitimate, use a different `SOC_STATE_DIR`.
- If it is a stale process, stop it. The lock is released when the process exits for any
  reason, including a crash, so there is no stuck lock to clear by hand.

---

## 6 · The model is unavailable or misbehaving

Readiness reports `model: DEGRADED`.

The pipeline continues on deterministic fallbacks: triage still classifies, enrichment still
gathers evidence, the gate still gates, the report is still produced and labelled rule-based.
**Quality drops; controls do not.** Expect category accuracy near the corpus floor (~49%) and
more escalations from low confidence — which is the safe direction.

The circuit breaker opens after three consecutive failures and holds for a minute, so a server
that accepts connections but fails every request costs one timeout rather than one per node.

If the model is *available but wrong* — the more dangerous case — go to runbook 1 and check the
digest:

```bash
python -m src.run_cli --health      # reports the serving model
```

A digest that differs from the evaluated one means the weights changed. Pin it
(`SOC_OLLAMA_MODEL_DIGEST`) so the next mismatch is refused rather than reported.

---

## 7 · Restore from backup

```bash
scripts/backup.sh create              # to backups/
scripts/backup.sh verify  backups/soc-state-<stamp>.tar.gz
scripts/backup.sh restore backups/soc-state-<stamp>.tar.gz
```

Restore refuses to write over live state: merging two histories into one chain would produce a
log that fails verification and cannot be reasoned about. Move the existing directory aside
first.

The archive contains the audit signing key, because a restored log nobody can verify is not
evidence. That makes the backup itself sensitive — **anyone holding it can forge audit
records**. Encrypt it at rest and store it separately from the log it signs.

After restoring, verify the chains. `restore` runs the readiness checks for you; a backup
nobody has restored is a hypothesis, not a backup.

---

## 8 · Suspected compromise of the agent pipeline

The general case, in order:

1. `--mode halt`. Stop everything before investigating.
2. Preserve state: copy the volume before anything else writes to it.
3. Verify the audit chain **and its signatures**, and compare against the forwarded copy.
4. Check `authorization_denied` and `untrusted_content_flagged` events for the shape of what
   was attempted.
5. Check the model digest and the prompt manifest on recent runs (`Model` and `Prompts` in the
   run summary). Either changing without a corresponding commit is a finding.
6. Rotate the audit signing key and any forwarding credentials.
7. Re-run the evaluation corpus before returning to `normal`: `make eval`. If the security
   invariants do not hold, the system does not go back into service.
