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
        description="Chat model used by every agent. Must support tool/structured output.",
    )
    llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    llm_timeout_seconds: int = Field(default=120, ge=5, le=600)
    llm_num_ctx: int = Field(default=8192, ge=2048)

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

    # --- Security policy -------------------------------------------------
    hitl_severity_threshold: Severity = Field(
        default=Severity.HIGH,
        description="Triage severity at or above which human approval is required.",
    )
    hitl_min_confidence: float = Field(
        default=0.55,
        ge=0.0,
        le=1.0,
        description="Below this triage confidence, escalate to a human even for low severity.",
    )
    max_tool_calls_per_run: int = Field(default=40, ge=1, le=500)
    tool_rate_limit_per_minute: int = Field(default=30, ge=1, le=1000)
    max_untrusted_chars: int = Field(
        default=4000,
        ge=200,
        description="Hard truncation limit applied to any tool/RAG output before it reaches a prompt.",
    )

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

    def ensure_dirs(self) -> None:
        """Create writable directories on first use (idempotent)."""
        for path in (
            self.state_dir,
            self.chroma_dir,
            self.checkpoint_db.parent,
            self.audit_log_path.parent,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def secret_values(self) -> list[str]:
        """Every configured secret, for registration with the redactor."""
        values: list[str] = []
        if self.threat_intel_api_key is not None:
            secret = self.threat_intel_api_key.get_secret_value()
            if secret:
                values.append(secret)
        return values


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return Settings()
