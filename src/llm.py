"""Local LLM access (Ollama) with structured output and deterministic fallback.

Design decisions worth stating:

* **Local-first.** Alert content is sensitive. Ollama runs on the host or in a
  sibling container; no prompt ever leaves the machine. A cloud model would be
  a configuration change *and* a data-egress decision, so it is not the default.
* **Structured output or nothing.** Agents ask for a Pydantic schema. Free-form
  model prose never becomes state -- it is either parsed and validated, or the
  agent falls back to its deterministic path.
* **Every prompt is redacted on the way out.** The final chokepoint before any
  text reaches the model runs the secret redactor, so a credential that leaked
  into a log line cannot be memorialised in model context.
* **Failure is expected, not exceptional.** Small local models routinely emit
  malformed JSON. That is handled with bounded retries and a documented
  fallback, not by pretending it will not happen.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, TypeVar

from pydantic import BaseModel

from src.enums import AgentRole, AuditAction
from src.security.audit import AuditEvent, AuditLogger
from src.security.redaction import redact_text

T = TypeVar("T", bound=BaseModel)

#: Cached availability probe result: (checked_at_monotonic, is_available).
_availability_cache: tuple[float, bool] | None = None
_AVAILABILITY_TTL_SECONDS = 30.0


class LLMUnavailable(RuntimeError):
    """Raised when the local model server cannot be reached."""


def is_available(*, force: bool = False) -> bool:
    """Probe the Ollama server, caching the answer briefly.

    Used to decide whether to attempt an LLM call at all, so an offline host
    degrades immediately to the deterministic path instead of waiting for a
    connection timeout on every node.
    """
    global _availability_cache
    from src.config import get_settings

    settings = get_settings()
    if settings.offline_mode:
        return False

    now = time.monotonic()
    if not force and _availability_cache is not None:
        checked_at, available = _availability_cache
        if now - checked_at < _AVAILABILITY_TTL_SECONDS:
            return available

    available = False
    try:
        import httpx

        response = httpx.get(f"{settings.ollama_base_url.rstrip('/')}/api/tags", timeout=3.0)
        available = response.status_code == 200
    except Exception:  # noqa: BLE001 - any failure means "not available"
        available = False

    _availability_cache = (now, available)
    return available


def reset_availability_cache() -> None:
    """Test hook."""
    global _availability_cache
    _availability_cache = None


def get_chat_model(temperature: float | None = None, *, json_mode: bool = False) -> Any:
    """Build a ChatOllama client bound to the configured model."""
    from langchain_ollama import ChatOllama

    from src.config import get_settings

    settings = get_settings()
    kwargs: dict[str, Any] = {
        "model": settings.ollama_model,
        "base_url": settings.ollama_base_url,
        "temperature": settings.llm_temperature if temperature is None else temperature,
        "num_ctx": settings.llm_num_ctx,
        "client_kwargs": {"timeout": settings.llm_timeout_seconds},
    }
    if json_mode:
        # Constrained decoding: the server will only emit syntactically valid
        # JSON, which removes the most common small-model failure mode.
        kwargs["format"] = "json"
    return ChatOllama(**kwargs)


def _extract_json(text: str) -> str:
    """Pull a JSON object out of a model response that may be fenced or padded."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return cleaned[start : end + 1]
    return cleaned


def _describe_fields(schema: type[BaseModel]) -> str:
    """Render a schema as a compact field list for a small model.

    Deliberately *not* the raw JSON Schema: given a schema document, small
    models frequently echo the document back instead of producing an instance
    of it.  A plain annotated field list, plus a worked skeleton, is far more
    reliable.
    """
    lines: list[str] = []
    for name, field in schema.model_fields.items():
        annotation = field.annotation
        type_name = getattr(annotation, "__name__", str(annotation))
        type_name = (
            type_name.replace("list[str]", "array of strings")
            .replace("str", "string")
            .replace("bool", "boolean")
            .replace("float", "number")
        )
        required = "required" if field.is_required() else "optional"
        description = (field.description or "").strip()
        lines.append(f'- "{name}" ({type_name}, {required}): {description}')
    return "\n".join(lines)


def _example_skeleton(schema: type[BaseModel]) -> str:
    """A filled-in example object showing the exact expected shape."""
    example: dict[str, Any] = {}
    for name, field in schema.model_fields.items():
        annotation = field.annotation
        origin = getattr(annotation, "__name__", str(annotation))
        if "list" in str(annotation):
            example[name] = ["..."]
        elif origin == "bool":
            example[name] = False
        elif origin == "float":
            example[name] = 0.5
        else:
            example[name] = "..."
    return json.dumps(example, indent=2)


def _json_mode_completion(
    schema: type[T],
    *,
    system_prompt: str,
    user_prompt: str,
    temperature: float | None,
) -> T:
    """Fallback strategy: ask for raw JSON and parse it.

    Small local models frequently fail the tool-calling path that
    ``with_structured_output`` relies on, returning ``None``.  Constrained JSON
    decoding plus an explicit field list succeeds far more often, and the
    result is still validated by Pydantic before it can become state.
    """
    instruction = (
        f"{user_prompt}\n\n"
        "Reply with ONE JSON object containing your answer. Fields:\n"
        f"{_describe_fields(schema)}\n\n"
        "Shape of the object you must return (replace every '...' with your actual "
        f"content):\n{_example_skeleton(schema)}\n\n"
        "Output the filled-in object only. Do not output a schema, do not add commentary, "
        "and do not wrap the JSON in markdown fences."
    )

    model = get_chat_model(temperature=temperature, json_mode=True)
    response = model.invoke([("system", system_prompt), ("human", instruction)])
    content = response.content if hasattr(response, "content") else str(response)
    if isinstance(content, list):  # some backends return content parts
        content = "".join(part if isinstance(part, str) else str(part.get("text", "")) for part in content)

    return schema.model_validate(json.loads(_extract_json(str(content))))


class StructuredCall(BaseModel):
    """Result of a structured LLM invocation."""

    model_config = {"arbitrary_types_allowed": True}

    parsed: Any = None
    ok: bool = False
    error: str | None = None
    attempts: int = 0
    duration_ms: float = 0.0
    audit_events: list[AuditEvent] = []


def structured_completion(
    schema: type[T],
    *,
    system_prompt: str,
    user_prompt: str,
    actor: AgentRole,
    thread_id: str,
    audit: AuditLogger,
    max_attempts: int = 2,
    temperature: float | None = None,
) -> StructuredCall:
    """Ask the local model for a validated instance of ``schema``.

    Returns a :class:`StructuredCall` whose ``ok`` flag tells the caller whether
    to use ``parsed`` or fall back.  This function never raises for an expected
    failure -- an unreachable model or an unparseable response is a normal,
    audited outcome.
    """
    events: list[AuditEvent] = []
    started = time.perf_counter()

    # Final redaction chokepoint: nothing reaches the model unscrubbed.
    safe_system = redact_text(system_prompt)
    safe_user = redact_text(user_prompt)

    if not is_available():
        events.append(
            audit.record(
                thread_id=thread_id,
                actor=actor,
                action=AuditAction.LLM_FALLBACK,
                summary="LLM unavailable or offline mode enabled; using deterministic fallback",
                details={"schema": schema.__name__},
                success=True,
            )
        )
        return StructuredCall(
            ok=False,
            error="llm_unavailable",
            duration_ms=(time.perf_counter() - started) * 1000,
            audit_events=events,
        )

    def _tool_calling_strategy() -> T:
        model = get_chat_model(temperature=temperature).with_structured_output(schema)
        result = model.invoke([("system", safe_system), ("human", safe_user)])
        if isinstance(result, dict):
            result = schema.model_validate(result)
        if not isinstance(result, schema):
            # `with_structured_output` yields None when the model fails to emit
            # a usable tool call -- the dominant failure mode for small models.
            raise TypeError(f"model returned {type(result).__name__}, expected {schema.__name__}")
        return result

    def _json_strategy() -> T:
        return _json_mode_completion(
            schema,
            system_prompt=safe_system,
            user_prompt=safe_user,
            temperature=temperature,
        )

    # Try tool-calling first (richer schema fidelity), then constrained JSON.
    strategies: list[tuple[str, Any]] = [("tool_calling", _tool_calling_strategy)] * max_attempts
    strategies.append(("json_mode", _json_strategy))

    last_error: str | None = None
    for attempt, (strategy_name, strategy) in enumerate(strategies, start=1):
        try:
            result = strategy()

            duration_ms = (time.perf_counter() - started) * 1000
            events.append(
                audit.record(
                    thread_id=thread_id,
                    actor=actor,
                    action=AuditAction.LLM_CALL,
                    summary=f"structured completion -> {schema.__name__} via {strategy_name}",
                    details={
                        "schema": schema.__name__,
                        "attempt": attempt,
                        "strategy": strategy_name,
                        "prompt_chars": len(safe_system) + len(safe_user),
                    },
                    duration_ms=duration_ms,
                )
            )
            return StructuredCall(
                parsed=result,
                ok=True,
                attempts=attempt,
                duration_ms=duration_ms,
                audit_events=events,
            )

        except Exception as exc:  # noqa: BLE001 - malformed output is routine here
            last_error = f"{type(exc).__name__}: {exc}"
            events.append(
                audit.record(
                    thread_id=thread_id,
                    actor=actor,
                    action=AuditAction.LLM_CALL,
                    summary=f"structured completion attempt {attempt} ({strategy_name}) failed",
                    details={"schema": schema.__name__, "strategy": strategy_name, "error": last_error[:500]},
                    success=False,
                )
            )

    events.append(
        audit.record(
            thread_id=thread_id,
            actor=actor,
            action=AuditAction.LLM_FALLBACK,
            summary=f"all {len(strategies)} LLM attempts failed; using deterministic fallback",
            details={"schema": schema.__name__, "last_error": (last_error or "")[:500]},
        )
    )
    return StructuredCall(
        ok=False,
        error=last_error,
        attempts=len(strategies),
        duration_ms=(time.perf_counter() - started) * 1000,
        audit_events=events,
    )
