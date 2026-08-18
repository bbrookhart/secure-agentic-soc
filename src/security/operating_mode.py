"""The control you reach for when the agent itself is the suspect.

Every other control in this system answers *"can this alert be handled
autonomously"*. This one answers a different question: *"should anything be
handled autonomously right now"* -- and it is the question an incident responder
asks first when a prompt-injection campaign is underway, a model has been
swapped, or the analysis has simply started looking wrong.

Four modes, in increasing severity:

* ``normal`` -- policy decides, as designed.
* ``review_all`` -- every run reaches a human, whatever the policy says. The
  system keeps working and keeps producing analysis; it just stops concluding
  anything on its own. This is the setting for "we are not sure the model is
  trustworthy today".
* ``drain`` -- finish what is in flight, accept nothing new. For planned
  shutdown, or to stop the bleeding without abandoning live investigations.
* ``halt`` -- accept nothing new and stop in-flight runs at their next
  supervisor turn. Nothing completes.

**The mode lives in a file, not only in configuration.** An incident responder
needs to stop autonomous completion in seconds, and a control that requires a
redeploy is a control that does not exist during an incident. The file is read
on each check so a change takes effect on the next routing decision.

Reading fails safe in the direction of *more* human involvement: an unreadable
or unrecognised mode file yields ``review_all`` rather than ``normal``, because
the failure mode of guessing wrong should be extra analyst work, not unattended
completion.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path


class OperatingMode(str, Enum):
    """How much autonomy the system currently has."""

    NORMAL = "normal"
    REVIEW_ALL = "review_all"
    DRAIN = "drain"
    HALT = "halt"

    @property
    def accepts_new_runs(self) -> bool:
        return self in (OperatingMode.NORMAL, OperatingMode.REVIEW_ALL)

    @property
    def forces_human_review(self) -> bool:
        """Whether every run must reach a human regardless of policy."""
        return self is not OperatingMode.NORMAL

    @property
    def stops_in_flight(self) -> bool:
        return self is OperatingMode.HALT

    @property
    def description(self) -> str:
        return {
            OperatingMode.NORMAL: "policy decides autonomy, as designed",
            OperatingMode.REVIEW_ALL: "every run reaches a human regardless of policy",
            OperatingMode.DRAIN: "in-flight runs finish; no new runs accepted",
            OperatingMode.HALT: "no new runs; in-flight runs stop at the next supervisor turn",
        }[self]


def mode_file() -> Path:
    """Where the runtime override lives."""
    from src.config import get_settings

    return get_settings().state_dir / "operating_mode"


def current_mode() -> OperatingMode:
    """The effective mode: the file if present, otherwise configuration.

    Read on every check rather than cached, so flipping the switch during an
    incident takes effect on the next routing decision instead of the next
    restart.
    """
    from src.config import get_settings

    path = mode_file()
    if path.exists():
        try:
            raw = path.read_text(encoding="utf-8").strip().lower()
        except OSError:
            # A mode file we cannot read is a mode file someone wrote for a
            # reason. Assume the cautious one.
            return OperatingMode.REVIEW_ALL
        if raw:
            try:
                return OperatingMode(raw)
            except ValueError:
                return OperatingMode.REVIEW_ALL

    try:
        return OperatingMode(get_settings().operating_mode)
    except ValueError:
        return OperatingMode.REVIEW_ALL


def set_mode(mode: OperatingMode, *, reason: str = "", audit: object = None) -> None:
    """Write the runtime override, and record who narrowed autonomy and why.

    Changing this is a security-relevant act in both directions -- widening
    autonomy back to ``normal`` especially -- so it is audited like one.
    """
    from src.config import get_settings

    settings = get_settings()
    settings.ensure_dirs()
    mode_file().write_text(mode.value + "\n", encoding="utf-8")

    if audit is not None:
        record = getattr(audit, "record", None)
        if callable(record):
            from src.enums import AgentRole, AuditAction

            record(
                thread_id="operations",
                actor=AgentRole.HUMAN_ANALYST,
                action=AuditAction.OPERATING_MODE_CHANGED,
                summary=f"operating mode set to '{mode.value}': {mode.description}",
                details={"mode": mode.value, "reason": reason[:500]},
                success=mode is OperatingMode.NORMAL,
            )


def clear_mode() -> None:
    """Remove the runtime override, falling back to configuration."""
    path = mode_file()
    if path.exists():
        path.unlink()
