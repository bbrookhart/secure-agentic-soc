"""Versioned, hashed prompts.

A prompt change is a behaviour change. Keeping them here -- under code
ownership, with versions and content hashes that travel into the audit log --
makes editing what the model is told as reviewable as editing the policy engine.
"""

from __future__ import annotations

from src.prompts.registry import (
    BASELINE,
    ENRICHMENT,
    PROMPTS,
    REPORTER,
    SECURITY_PREAMBLE,
    SUPERVISOR,
    TRIAGE,
    Prompt,
    manifest_hash,
    prompt_manifest,
    register,
    with_preamble,
)

__all__ = [
    "BASELINE",
    "ENRICHMENT",
    "PROMPTS",
    "REPORTER",
    "SECURITY_PREAMBLE",
    "SUPERVISOR",
    "TRIAGE",
    "Prompt",
    "manifest_hash",
    "prompt_manifest",
    "register",
    "with_preamble",
]
