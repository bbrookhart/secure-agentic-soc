"""One writer per state directory, enforced rather than assumed.

Single-node is a deliberate deployment choice, but three components quietly
depend on it and none of them would fail loudly if it stopped being true:

* the **SQLite checkpointer** has no cross-process locking around a resumed run,
  so two processes resuming the same thread can both write it;
* the **rate limiter** holds its token buckets in memory, so N replicas allow N
  times the configured rate -- a limit that silently stops limiting;
* the **audit chain** rehydrates per process, so two processes appending events
  for the same run would both claim the same sequence number and produce a log
  that fails verification on an honest run.

None of those are hypothetical once someone scales the deployment "just to see".
An assumption that is load-bearing and unchecked is a bug waiting for a
coincidence, so this makes it fail immediately and say why.

Uses ``flock`` on a lock file in the state directory. The lock is released when
the process exits for any reason, including a crash, so a killed process does
not leave the system unstartable -- which would be trading one outage for a
worse one.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


class InstanceLockError(RuntimeError):
    """Raised when another process already holds this state directory."""


class InstanceLock:
    """Advisory exclusive lock over one state directory."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._handle: Any = None

    def acquire(self) -> None:
        """Take the lock, or explain who has it.

        Windows has no ``flock``; there the lock degrades to a no-op rather than
        blocking startup, and the deployment story for this system is Linux
        containers anyway.
        """
        try:
            import fcntl
        except ImportError:  # pragma: no cover - non-POSIX
            return

        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.path, "a+", encoding="utf-8")  # noqa: SIM115 - held for process life
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.seek(0)
            holder = handle.read().strip() or "an unknown process"
            handle.close()
            raise InstanceLockError(
                f"another instance is already using this state directory ({holder}). "
                "Running two against the same state would silently multiply the tool rate "
                "limit and can corrupt the audit chain for a resumed run. Point this "
                "instance at a different SOC_STATE_DIR, or stop the other one."
            ) from exc

        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()}\n")
        handle.flush()
        self._handle = handle

    def release(self) -> None:
        if self._handle is None:
            return
        try:
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        except (ImportError, OSError):  # pragma: no cover
            pass
        finally:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> InstanceLock:
        self.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


def default_lock() -> InstanceLock:
    """Lock over the configured state directory."""
    from src.config import get_settings

    settings = get_settings()
    settings.ensure_dirs()
    return InstanceLock(settings.state_dir / ".instance.lock")
