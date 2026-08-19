"""Central configuration.

Security note: configuration values are read from the environment exactly once
here.  Nothing in this module is ever interpolated into an LLM prompt -- the
prompt builders in ``src/agents`` receive only explicitly whitelisted fields.
Any value marked ``SecretStr`` is additionally registered with the redaction
engine so that it is scrubbed from audit logs and tool output.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.enums import Severity

# Repository root -- resolved from this file so paths work identically whether
# the app runs from the host, a container, or pytest.
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Application settings, populated from environment variables / .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="SOC_",
        extra="ignore",
    )

    # --- LLM -------------------------------------------------------------
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL of the Ollama server.",
    )
    ollama_model: str = Field(
        default="llama3.2",
        description=(
            "Default chat model for every agent. Must support tool/structured output. "
            "Per-role overrides via SOC_MODEL_<ROLE>; see src/model_profiles.py."
        ),
    )
    # Reasoning models answer better and cost roughly 5x the latency per call
    # on modest hardware. Off by default so a full investigation stays
    # minutes rather than tens of minutes; when on, only the roles that
    # benefit use it (triage and enrichment).
    llm_reasoning: bool = Field(default=False)
    #: Whether the model's severity and category may *decide* the verdict.
    #:
    #: Off by default because the corpus says so, not on principle. Paired
    #: against the deterministic floor, llama3.2 scores 39% category against
    #: 68% and 79% severity-in-band against 93%, and causes four missed
    #: escalations against two -- all resolved at p<0.05. A model that beats
    #: the floor can be promoted; see src/model_profiles.py for the procedure.
    model_verdict_authority: bool = Field(default=False)
    # A model tag is mutable: "llama3.2" re-pulled can be different weights
    # with different judgement, and nothing would notice. Pin the digest and
    # a mismatch is refused; leave it unset and the observed digest is still
    # audited, which is what makes pinning possible later.
    ollama_model_digest: str | None = Field(
        default=None,
        description="Expected model digest (prefix match). Unset observes without enforcing.",
    )
    llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    llm_timeout_seconds: int = Field(default=120, ge=5, le=600)
    llm_num_ctx: int = Field(default=8192, ge=2048)
    # Per-role overrides, e.g. SOC_MODEL_TRIAGE=qwen3:8b,
    # SOC_MODEL_SUPERVISOR=llama3.2. Only worth setting when the host can
    # hold several models resident at once.
    model_supervisor: str | None = Field(default=None)
    model_triage: str | None = Field(default=None)
    model_enrichment: str | None = Field(default=None)
    model_reporter: str | None = Field(default=None)
    model_baseline: str | None = Field(default=None)

    # When True, agents skip the LLM entirely and use their deterministic
    # rule-based fallbacks.  Makes the pipeline runnable (and testable) with no
    # model server present, and gives a reproducible demo path.
    offline_mode: bool = Field(default=False)

    # --- Embeddings ------------------------------------------------------
    # 'tfidf' is a dependency-free deterministic lexical vectoriser that works
    # with no model download; 'ollama' uses a real embedding model when one has
    # been pulled.  See docs/ARCHITECTURE.md for the trade-off.
    embedding_backend: str = Field(default="tfidf", pattern="^(tfidf|ollama)$")
    ollama_embedding_model: str = Field(default="nomic-embed-text")

    # --- Storage ---------------------------------------------------------
    data_dir: Path = Field(default=PROJECT_ROOT / "data")
    state_dir: Path = Field(default=PROJECT_ROOT / "state")
    checkpoint_db: Path = Field(default=PROJECT_ROOT / "state" / "checkpoints.sqlite")
    audit_log_path: Path = Field(default=PROJECT_ROOT / "state" / "audit" / "audit.jsonl")
    chroma_dir: Path = Field(default=PROJECT_ROOT / "state" / "chroma")
    case_store_db: Path = Field(
        default=PROJECT_ROOT / "state" / "cases.sqlite",
        description="Cross-run case history: what was seen before, and what a human decided.",
    )

    # --- Security policy -------------------------------------------------
    hitl_severity_threshold: Severity = Field(
        default=Severity.HIGH,
        description="Triage severity at or above which human approval is required.",
    )
    max_tool_calls_per_run: int = Field(default=40, ge=1, le=500)
    tool_rate_limit_per_minute: int = Field(default=30, ge=1, le=1000)
    max_untrusted_chars: int = Field(
        default=4000,
        ge=200,
        description="Hard truncation limit applied to any tool/RAG output before it reaches a prompt.",
    )

    # --- Audit durability and forwarding ---------------------------------
    # The local hash chain is tamper-evident but rewritable by anyone holding
    # code execution on this host.  Forwarding each event to storage under
    # different credentials is what makes a later rewrite detectable, because
    # the two copies then disagree.  See src/security/audit_sink.py.
    audit_durable_writes: bool = Field(
        default=True,
        description="fsync every audit record. An unflushed audit line is not evidence.",
    )
    audit_forward_url: str | None = Field(
        default=None,
        description="HTTP collector receiving every audit event as it is written.",
    )
    audit_forward_token: SecretStr | None = Field(default=None)
    # Signing gives non-repudiation to a verifier holding only the public key
    # (AU-10) -- verification stops requiring the power to forge. It does not
    # stop an attacker who holds the key; see src/security/signing.py.
    # Retention (AU-11). Rotation caps disk use; anything past the last
    # segment is deleted, which is why forwarding matters -- off-host
    # retention is not bounded by this volume.
    audit_max_segment_bytes: int = Field(
        default=64 * 1024 * 1024,
        ge=0,
        description="Roll to a new audit segment past this size. 0 disables rotation.",
    )
    audit_max_segments: int = Field(default=10, ge=1)
    # Encryption at rest (SC-28) is a volume-level deployment concern, not an
    # application one: app-level encryption would put the keys in the same
    # process as the data it protects. This flag records that the operator has
    # provided it, so the evidence bundle states a fact rather than a hope.
    state_volume_encrypted: bool = Field(
        default=False,
        description=(
            "Set true when the state volume is encrypted at rest. Purely declarative: "
            "the application cannot verify it, and says so."
        ),
    )
    case_retention_days: int = Field(
        default=365,
        ge=1,
        description="Prune case history older than this. Correlation cannot see past it.",
    )
    audit_signing_enabled: bool = Field(default=True)
    audit_signing_key_path: Path = Field(
        default=PROJECT_ROOT / "state" / "audit" / "signing-key.pem",
        description="Ed25519 private key. Production should use a KMS or HSM instead.",
    )
    audit_anchor_interval: int = Field(
        default=25,
        ge=1,
        description=(
            "Emit a signed chain-head anchor every N events. Anchors that have "
            "left the host cannot be retracted, so a later local rewrite diverges "
            "from them."
        ),
    )
    audit_syslog_address: str | None = Field(
        default=None,
        description="Syslog target, e.g. '/dev/log' or 'collector.internal:514'.",
    )

    # --- Approval console authentication ---------------------------------
    # The approval gate is the most security-critical control in the system and
    # the UI has no authentication of its own.  Front it with an authenticating
    # proxy and name the header it sets; the console then refuses to record a
    # decision without a verified identity.
    approval_identity_header: str = Field(
        default="X-Forwarded-User",
        description="Request header carrying the proxy-verified analyst identity.",
    )
    require_authenticated_approval: bool = Field(
        default=True,
        description="Refuse to record approvals when no verified identity is present.",
    )
    approval_roles_header: str = Field(
        default="X-Forwarded-Groups",
        description="Header carrying proxy-verified group membership; maps to approval roles.",
    )
    require_separation_of_duties: bool = Field(
        default=True,
        description=(
            "Refuse approvals from whoever initiated the run (NIST 800-53 AC-5). "
            "A single-operator deployment cannot satisfy this and must set it false "
            "deliberately -- the CLI initiator and approver are the same person by "
            "construction."
        ),
    )
    require_two_person_approval: bool = Field(
        default=False,
        description=(
            "Require two distinct approvers for disruptive proposals on critical assets. "
            "Off by default: it doubles the cost of every such approval, which is correct "
            "in some environments and pure friction in others."
        ),
    )

    # --- Operating mode --------------------------------------------------
    # The default when no runtime override file is present. The file in
    # state/operating_mode takes precedence, because during an incident a
    # control that needs a redeploy is a control that does not exist.
    operating_mode: str = Field(
        default="normal",
        pattern="^(normal|review_all|drain|halt)$",
        description="normal | review_all | drain | halt. See src/security/operating_mode.py.",
    )

    # --- Observability ---------------------------------------------------
    # Off by default. Telemetry is an egress path and the data here is
    # incident data, so switching it on is a decision -- see
    # src/observability/telemetry.py for the label discipline that keeps
    # alert content out of it.
    telemetry_enabled: bool = Field(default=False)
    telemetry_endpoint: str | None = Field(
        default=None,
        description="OTLP/gRPC collector. Unset records in-process without exporting.",
    )
    app_version: str = Field(default="0.1.0")

    # --- Optional secrets (never placed in prompts) ----------------------
    # Present to demonstrate correct secret handling; the shipped tools are all
    # offline and do not require credentials.
    threat_intel_api_key: SecretStr | None = Field(default=None)

    @field_validator("data_dir", "state_dir", "chroma_dir")
    @classmethod
    def _resolve_dir(cls, value: Path) -> Path:
        return value.expanduser().resolve()

    # --- Derived paths ---------------------------------------------------
    @property
    def sample_alerts_dir(self) -> Path:
        return self.data_dir / "sample_alerts"

    @property
    def mitre_path(self) -> Path:
        return self.data_dir / "mitre" / "attack_knowledge.json"

    @property
    def intel_path(self) -> Path:
        return self.data_dir / "intel" / "threat_intel.json"

    @property
    def log_corpus_path(self) -> Path:
        return self.data_dir / "logs" / "corpus.jsonl"

    @property
    def generated_log_corpus_path(self) -> Path:
        """Scenario logs written by ``evals.generate``.

        Kept out of the hand-authored corpus so a generator run can never
        perturb the cases that already depend on it.
        """
        return self.data_dir / "logs" / "generated.jsonl"

    @property
    def change_records_path(self) -> Path:
        return self.data_dir / "changes" / "change_records.json"

    def ensure_dirs(self) -> None:
        """Create writable directories on first use (idempotent)."""
        for path in (
            self.state_dir,
            self.chroma_dir,
            self.checkpoint_db.parent,
            self.audit_log_path.parent,
            self.case_store_db.parent,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def model_overrides(self) -> dict[str, dict[str, object]]:
        """Per-role model overrides, keyed by AgentRole value."""
        mapping = {
            "supervisor": self.model_supervisor,
            "triage": self.model_triage,
            "enrichment": self.model_enrichment,
            "reporter": self.model_reporter,
            "baseline": self.model_baseline,
        }
        return {role: {"model": model} for role, model in mapping.items() if model}

    def secret_values(self) -> list[str]:
        """Every configured secret, for registration with the redactor."""
        values: list[str] = []
        for candidate in (self.threat_intel_api_key, self.audit_forward_token):
            if candidate is not None:
                secret = candidate.get_secret_value()
                if secret:
                    values.append(secret)
        return values


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return Settings()
