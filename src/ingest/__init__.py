"""Alert ingestion -- the trust boundary of the whole system.

Everything downstream treats alert content as attacker-influenced, and this
package is where that content is first parsed and validated.  Whatever the
source -- a bundled sample, a watched directory, a SIEM query -- it converges on
:func:`~src.ingest.base.parse_alert`, so there is exactly one strict validator
to review.

``src.ingest.siem`` holds the only outbound network code in the project, and it
runs before the pipeline starts. No tool and no agent can reach it.
"""

from __future__ import annotations

from src.ingest.base import (
    MAX_ALERT_BYTES,
    AlertIngestError,
    AlertSource,
    SourceError,
    parse_alert,
)
from src.ingest.files import (
    DirectorySource,
    list_sample_alerts,
    load_alert_file,
    resolve_alert,
)

__all__ = [
    "MAX_ALERT_BYTES",
    "AlertIngestError",
    "AlertSource",
    "DirectorySource",
    "SourceError",
    "list_sample_alerts",
    "load_alert_file",
    "parse_alert",
    "resolve_alert",
]
