"""Which model actually produced a verdict, and whether it is the expected one.

``SOC_OLLAMA_MODEL`` names a tag, and a tag is mutable. ``llama3.2`` today and
``llama3.2`` after someone re-pulls it can be different weights with different
judgement, and nothing in the system would notice: every severity call, every
narrative, every routing opinion would shift with no diff, no audit entry and no
change to any test.

That is the same class of problem as an unpinned dependency, and it gets the
same treatment:

* **Observe.** The digest of the model actually serving requests is read at
  startup and recorded on the run, so *"which weights produced this report"* is
  answerable months later.
* **Pin, optionally.** Set ``SOC_OLLAMA_MODEL_DIGEST`` and a mismatch is
  refused rather than reported. Unpinned deployments still get the digest in the
  audit trail, which is what makes pinning possible later.

Fails open when the model server cannot be reached: refusing to start because a
digest could not be *read* would take the system down for a reason unrelated to
integrity, and the deterministic floor is designed to carry that case.
"""

from __future__ import annotations

from dataclasses import dataclass


class ModelIntegrityError(RuntimeError):
    """Raised when the serving model is not the pinned one."""


@dataclass(frozen=True)
class ModelProvenance:
    """What is actually serving requests."""

    name: str
    digest: str = ""
    parameter_size: str = ""
    quantization: str = ""
    available: bool = False
    pinned: bool = False
    matches_pin: bool = True

    @property
    def short_digest(self) -> str:
        return self.digest[:16] if self.digest else ""

    @property
    def label(self) -> str:
        """Compact identifier recorded on the run, beside the prompt manifest."""
        if not self.digest:
            return f"{self.name}@unknown"
        return f"{self.name}@{self.short_digest}"

    def as_details(self) -> dict[str, object]:
        return {
            "model": self.name,
            "digest": self.short_digest,
            "parameter_size": self.parameter_size,
            "quantization": self.quantization,
            "available": self.available,
            "pinned": self.pinned,
            "matches_pin": self.matches_pin,
        }


def resolve_model_provenance() -> ModelProvenance:
    """Read the serving model's digest and compare it against any pin."""
    from src.config import get_settings

    settings = get_settings()
    expected = (settings.ollama_model_digest or "").strip().lower()
    name = settings.ollama_model

    if settings.offline_mode:
        return ModelProvenance(name=name, available=False, pinned=bool(expected))

    digest = ""
    parameter_size = ""
    quantization = ""
    available = False
    try:
        import httpx

        response = httpx.get(f"{settings.ollama_base_url.rstrip('/')}/api/tags", timeout=3.0)
        response.raise_for_status()
        for entry in response.json().get("models", []):
            entry_name = str(entry.get("name", ""))
            # A configured "llama3.2" is served as "llama3.2:latest".
            if entry_name == name or entry_name.split(":")[0] == name.split(":")[0]:
                digest = str(entry.get("digest", "")).lower()
                details = entry.get("details", {}) or {}
                parameter_size = str(details.get("parameter_size", ""))
                quantization = str(details.get("quantization_level", ""))
                available = True
                break
    except Exception:  # noqa: BLE001 - unreachable server is not an integrity failure
        return ModelProvenance(name=name, available=False, pinned=bool(expected))

    matches = True
    if expected and digest:
        # Prefix comparison, so a short pin is usable without pasting 64 hex
        # characters into configuration.
        matches = digest.startswith(expected) or expected.startswith(digest)

    return ModelProvenance(
        name=name,
        digest=digest,
        parameter_size=parameter_size,
        quantization=quantization,
        available=available,
        pinned=bool(expected),
        matches_pin=matches,
    )


def verify_model(*, audit: object = None, thread_id: str = "startup") -> ModelProvenance:
    """Resolve provenance, audit it, and refuse a mismatch against a pin.

    Raises :class:`ModelIntegrityError` only when a digest is pinned and the
    serving model is demonstrably different. An unreachable server is not a
    mismatch -- there is nothing to compare -- and is left to the readiness
    checks to report as degraded.
    """
    from src.enums import AgentRole, AuditAction

    provenance = resolve_model_provenance()

    if audit is not None:
        record = getattr(audit, "record", None)
        if callable(record):
            record(
                thread_id=thread_id,
                actor=AgentRole.SUPERVISOR,
                action=AuditAction.MODEL_VERIFIED,
                summary=(
                    f"model {provenance.label}"
                    + ("" if provenance.matches_pin else " DOES NOT MATCH the pinned digest")
                ),
                details=provenance.as_details(),
                success=provenance.matches_pin,
            )

    if provenance.pinned and provenance.available and not provenance.matches_pin:
        from src.config import get_settings

        raise ModelIntegrityError(
            f"model '{provenance.name}' has digest {provenance.short_digest}, "
            f"but SOC_OLLAMA_MODEL_DIGEST pins "
            f"{(get_settings().ollama_model_digest or '')[:16]}. The weights serving this "
            "deployment are not the ones that were evaluated; refusing to start."
        )

    return provenance
