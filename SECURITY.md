# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately. Do not open a public issue.

Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, or contact the maintainer directly.

Please include: what you found, how to reproduce it, and what an attacker gains. A working
proof of concept is welcome but not required — a clear description of the control that fails is
enough.

Expect an acknowledgement within 3 working days and an assessment within 10.

## What this project treats as a vulnerability

This is a security tool, so the bar is specific. The following are vulnerabilities:

- **Any path that reaches `COMPLETE` past an approval the policy engine required.** The
  human-in-the-loop gate is the control everything else exists to protect.
- **Any way for model output, alert content, tool output or case history to change a routing or
  policy decision.** The model reasons; code decides. A model that can talk the router or the
  policy engine into anything is the whole threat model failing.
- **Any capability reachable by an agent that its identity does not grant**, or any way to reach
  a tool handler without passing the broker in [`src/tools/base.py`](src/tools/base.py).
- **Any execution primitive** — shell, subprocess, arbitrary HTTP, file write, `eval` — reachable
  from the tool layer. There is a test asserting none exists; a way around it is a finding.
- **Any way to write, alter or remove audit events without breaking chain verification.**
- **Secret disclosure** through prompts, reports, tool output or the audit log.
- **Approval taken without a verified identity**, or by a principal not authorised for it.

## What is not a vulnerability

Stated plainly, because a security policy that implies more coverage than exists is itself
misleading:

- **A prompt-injection payload the heuristics do not detect.** The detector is pattern-based and
  known to miss other languages, mixed-script look-alikes, and manipulation containing no
  instruction-shaped text. The eval corpus carries three such cases on purpose
  (`INJ-006`, `INJ-007`, `INJ-008`). A miss is expected and degrades to least privilege and the
  policy gate. **A miss that also escapes containment is a vulnerability** — that is the
  distinction worth reporting.
- **Weak analysis quality from a small model.** The deterministic controls hold regardless.
- **Anything requiring pre-existing code execution on the host.** An attacker at that level can
  recompute the local audit chain; this is documented in
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and mitigated by off-host forwarding, not by
  the chain alone.
- **The unauthenticated local mode.** `make ui` and the compose stack opt out of approval
  authentication explicitly and record decisions as `unauthenticated`. Deploying that way is a
  configuration choice, documented as one.

## Supported versions

The `main` branch is the supported version. This project has not cut a release.

## Security controls in this repository

- Every pull request runs the security-invariant gate (`python -m evals.runner`), which fails
  the build on approval bypass, non-proposal-only actions, audit chain failure, or configuration
  disclosure.
- Dependency scanning, secret scanning, SAST and container scanning run in CI.
- Changes under `src/security/`, `src/tools/` and `evals/corpus/` require security review — see
  [`CODEOWNERS`](.github/CODEOWNERS).

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full threat model and
[`docs/CONTROLS.md`](docs/CONTROLS.md) for the control mapping.
