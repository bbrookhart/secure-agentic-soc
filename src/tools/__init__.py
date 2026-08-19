"""Narrow, purpose-built tools and the guarded broker that fronts them.

Every tool in this registry is:

* **narrow** -- it answers one question or drafts one proposal;
* **schema-validated** -- arguments are parsed by a Pydantic model;
* **offline** -- no tool makes a network request, spawns a process, or
  evaluates code;
* **read-only or proposal-only** -- nothing here changes any real system.

There is intentionally no shell tool, no HTTP tool, no file-write tool and no
code-execution tool.  That absence is the design.
"""

from __future__ import annotations

from src.tools.authorisation import VERIFY_AUTHORISATION_TOOL
from src.tools.base import SOCTool, ToolBroker, ToolResult
from src.tools.case_history import QUERY_CASE_HISTORY_TOOL
from src.tools.classify import CLASSIFY_ALERT_TOOL
from src.tools.ioc import ENRICH_IOC_TOOL
from src.tools.log_search import QUERY_VECTOR_LOGS_TOOL
from src.tools.mitre import LOOKUP_MITRE_TOOL
from src.tools.response import DRAFT_CONTAINMENT_TOOL

#: The complete capability surface of the system.
TOOL_REGISTRY: dict[str, SOCTool] = {
    tool.name: tool
    for tool in (
        CLASSIFY_ALERT_TOOL,
        ENRICH_IOC_TOOL,
        LOOKUP_MITRE_TOOL,
        QUERY_VECTOR_LOGS_TOOL,
        QUERY_CASE_HISTORY_TOOL,
        DRAFT_CONTAINMENT_TOOL,
        VERIFY_AUTHORISATION_TOOL,
    )
}


def build_broker(**kwargs: object) -> ToolBroker:
    """Construct a broker over the full registry."""
    from src.config import get_settings

    settings = get_settings()
    kwargs.setdefault("max_calls_per_run", settings.max_tool_calls_per_run)
    return ToolBroker(registry=TOOL_REGISTRY, **kwargs)  # type: ignore[arg-type]


__all__ = [
    "CLASSIFY_ALERT_TOOL",
    "DRAFT_CONTAINMENT_TOOL",
    "ENRICH_IOC_TOOL",
    "LOOKUP_MITRE_TOOL",
    "QUERY_CASE_HISTORY_TOOL",
    "QUERY_VECTOR_LOGS_TOOL",
    "VERIFY_AUTHORISATION_TOOL",
    "TOOL_REGISTRY",
    "SOCTool",
    "ToolBroker",
    "ToolResult",
    "build_broker",
]
