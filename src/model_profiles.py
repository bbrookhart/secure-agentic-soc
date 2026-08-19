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
    rationale: str

    def as_details(self) -> dict[str, object]:
        return {
            "role": self.role.value,
            "model": self.model,
            "temperature": self.temperature,
            "num_ctx": self.num_ctx,
            "reasoning": self.reasoning,
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
        "Severity and category drive the approval gate. This is the judgement call most "
        "worth spending on, and the measured difference was a correct escalation.",
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
