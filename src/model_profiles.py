"""Per-agent model configuration.

One global model served every agent: the same weights, temperature, context and
reasoning budget for deciding a routing hop as for writing an incident
narrative. Those are not the same job, and on constrained hardware the
difference is the whole cost of the run.

Measured on this deployment (`qwen3:8b`, M2, 8GB) for one structured call:

    reasoning off    16.5s    severity "high"
    reasoning on     92.3s    severity "critical"

Both parsed. The slower answer was the better one -- shadow-copy-deleting
ransomware on a critical file server *is* critical -- but paying 92 seconds to
decide "triage should run next", a decision the deterministic router makes
anyway and only records the model's opinion of, is waste.

So a profile per role: model, temperature, context, and whether the model may
think. Reasoning is spent where judgement is genuinely wanted -- the hunt
narrative and the report -- and withheld where the answer is advisory or nearly
mechanical.

**Every profile defaults to the same model.** Two resident models would make
Ollama evict and reload between agents, and on 8GB that costs far more than the
split saves. The per-role *fields* are there so better hardware can run a small
fast model for routing and a large one for analysis by changing configuration,
not code. Set ``SOC_MODEL_<ROLE>`` to opt in.

**Why the default is ``llama3.2`` and not ``qwen3:8b``.** It was briefly the
latter, on the strength of the reasoning-mode result above. Three things
measured since say otherwise:

* Reasoning is **off** by default, and ``profile_for`` gates every role's
  reasoning behind ``settings.llm_reasoning``. So the default configuration
  bought qwen3's cost without the one thing that had been measured as better.
* ``qwen3:8b`` is 6.6GB resident against 8GB of RAM. The host drops to tens of
  megabytes of free pages and thrashes: a single evaluation case ran 35 minutes
  without completing, which puts a 35-case corpus around twenty hours. A default
  whose quality cannot be measured on the hardware that runs it is the wrong
  default, whatever its ceiling.
* On the same shadow-copy ransomware scenario, ``llama3.2`` returned
  ``critical`` in **6.7s on the first attempt** -- matching qwen3's
  reasoning-*on* answer at a fourteenth of the latency, and beating its
  reasoning-off answer of ``high``.

Both quality observations are single samples and neither settles the general
question. That is what ``evals/paired.py`` is for: record a baseline per model
and let the corpus answer. ``qwen3:8b`` stays one ``SOC_OLLAMA_MODEL`` away for
hosts that can hold it.

**Verdict authority is earned, not assumed.**

The same argument, applied to the thing that actually matters. Triage proposes a
severity and a category, and those drive the approval gate -- so the question of
whether the *model* or the *rules* should decide them is exactly the kind of
question the corpus can answer, and it has:

    paired, 38 cases, llama3.2 against the deterministic floor

        category correct      39%  vs  68%   p=0.035
        severity in band      79%  vs  93%   p=0.039
        escalation correct    74%  vs  97%   p=0.004
        missed escalations     4   vs   2    (two of them real attacks)

Every difference is resolved, and every one favours the rules. The model
under-calls severity to "medium", so ``HITL-001`` never fires and a genuine
incident completes without a human. So ``verdict_authority`` defaults to
**False**: the model's proposal is recorded, the disagreement is audited, and
the classifier's answer stands -- the same shape routing has always had.

To promote a model, measure it rather than trusting it::

    make baseline-llm NAME=<model>
    make eval-paired A=evals/baselines/offline.json B=evals/baselines/llm-<model>.json

Grant ``SOC_MODEL_VERDICT_AUTHORITY=true`` only if that model *beats* the floor
on category and severity, and does not add missed escalations. A model that
merely ties has not earned the authority: the rules are cheaper, reproducible,
and cannot be talked into anything.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.enums import AgentRole


@dataclass(frozen=True)
class ModelProfile:
    """How one agent talks to a model."""

    role: AgentRole
    model: str
    temperature: float
    num_ctx: int
    reasoning: bool
    #: Whether this role's model may decide the verdict, or merely propose one.
    verdict_authority: bool
    rationale: str

    def as_details(self) -> dict[str, object]:
        return {
            "role": self.role.value,
            "model": self.model,
            "temperature": self.temperature,
            "num_ctx": self.num_ctx,
            "reasoning": self.reasoning,
            "verdict_authority": self.verdict_authority,
        }


#: Whether each role's work justifies the cost of a reasoning pass, and why.
#: Read this as a latency budget: on this hardware, reasoning is roughly a 5x
#: multiplier per call.
_REASONING_BY_ROLE: dict[AgentRole, tuple[bool, str]] = {
    AgentRole.SUPERVISOR: (
        False,
        "Routing is decided by the deterministic router; the model's opinion is advisory "
        "and logged. Paying a reasoning pass for a recorded disagreement is waste.",
    ),
    AgentRole.TRIAGE: (
        True,
        "Severity and category drive the approval gate, so the model's proposal is worth "
        "a reasoning pass -- but it is a proposal: the deterministic classifier decides "
        "unless a model has been measured to beat it (see verdict_authority).",
    ),
    AgentRole.ENRICHMENT: (
        True,
        "Connecting indicators to log lines across a timeline is the analytical work; "
        "it is where a stronger model earns its latency.",
    ),
    AgentRole.REPORTER: (
        False,
        "Synthesis over facts already validated and copied from state. The structural "
        "content is not the model's to change, so reasoning adds cost without authority.",
    ),
    AgentRole.BASELINE: (
        False,
        "The comparison agent. Kept cheap so the contrast measures architecture rather "
        "than inference budget.",
    ),
}


def profile_for(role: AgentRole) -> ModelProfile:
    """Resolve one role's profile from settings, falling back to the defaults."""
    from src.config import get_settings

    settings = get_settings()
    default_reasoning, rationale = _REASONING_BY_ROLE.get(
        role, (False, "No profile declared; defaults to the global model without reasoning.")
    )

    override = settings.model_overrides().get(role.value, {})
    model = override.get("model")

    return ModelProfile(
        role=role,
        model=str(model) if model else settings.ollama_model,
        temperature=settings.llm_temperature,
        num_ctx=settings.llm_num_ctx,
        # Reasoning is opt-in overall: enabling it globally would make a full
        # investigation take minutes on modest hardware, so the per-role
        # defaults only apply once the operator has asked for reasoning at all.
        reasoning=default_reasoning and settings.llm_reasoning,
        # Only triage holds a verdict to begin with; the other roles produce
        # narrative or advice, so there is nothing here for them to be granted.
        verdict_authority=(role is AgentRole.TRIAGE and settings.model_verdict_authority),
        rationale=rationale,
    )


def profile_matrix() -> list[dict[str, object]]:
    """Every role's resolved profile, for docs and the evidence bundle."""
    rows: list[dict[str, object]] = []
    for role in (
        AgentRole.SUPERVISOR,
        AgentRole.TRIAGE,
        AgentRole.ENRICHMENT,
        AgentRole.REPORTER,
        AgentRole.BASELINE,
    ):
        profile = profile_for(role)
        rows.append({**profile.as_details(), "rationale": profile.rationale})
    return rows


def distinct_models() -> set[str]:
    """Models a full run would need resident.

    More than one means Ollama will evict and reload between agents, which on
    memory-constrained hosts costs more than any per-role tuning saves.
    """
    return {str(row["model"]) for row in profile_matrix()}
