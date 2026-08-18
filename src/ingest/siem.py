"""Polling adapters for real detection sources.

Each adapter does exactly two things: fetch, and map vendor fields onto the
plain dict that :func:`~src.ingest.base.parse_alert` validates.  They contain no
judgement about severity, no enrichment, and no repair of malformed input --
all of that belongs downstream of the trust boundary, not in the code that
talks to the network.

The mappings are deliberately small and readable.  Real deployments will need
to extend them for local field conventions, and a mapping you cannot read in
one sitting is one you cannot review for what it lets through.

These adapters are the only code in the project that makes an outbound network
request, and they run *before* the agent pipeline starts. No tool, and no
agent, can reach them.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

from src.enums import Severity
from src.ingest.base import AlertSource, SourceError, parse_alert
from src.state import SecurityAlert


def _utc_now() -> datetime:
    return datetime.now(UTC)


class HttpPollingSource:
    """Base for sources that fetch JSON over HTTP.

    Holds the cursor and the request plumbing; subclasses supply the request
    shape and the field mapping.
    """

    name = "http"

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        lookback_minutes: int = 15,
        timeout: float = 15.0,
        verify_tls: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._headers = {"accept": "application/json"}
        if token:
            self._headers["authorization"] = f"Bearer {token}"
        self._cursor = _utc_now() - timedelta(minutes=lookback_minutes)
        self._seen_ids: set[str] = set()

    # --- Subclass contract ------------------------------------------------
    def _request(self, since: datetime, limit: int) -> tuple[str, dict[str, Any]]:
        """Return ``(url, json_body_or_params)`` for the fetch."""
        raise NotImplementedError

    def _records(self, payload: Any) -> list[dict[str, Any]]:
        """Pull the record list out of a vendor response envelope."""
        raise NotImplementedError

    def _to_alert_payload(self, record: dict[str, Any]) -> dict[str, Any]:
        """Map one vendor record onto the SecurityAlert field names."""
        raise NotImplementedError

    # --- Polling ----------------------------------------------------------
    def poll(self, *, limit: int = 50) -> Iterator[SecurityAlert]:
        import httpx

        url, body = self._request(self._cursor, limit)
        try:
            response = httpx.post(
                url,
                json=body,
                headers=self._headers,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed source error
            raise SourceError(f"{self.name}: fetch failed: {type(exc).__name__}: {exc}") from exc

        polled_at = _utc_now()
        for record in self._records(payload)[:limit]:
            try:
                alert_payload = self._to_alert_payload(record)
            except Exception as exc:  # noqa: BLE001 - one bad record must not stop the queue
                raise SourceError(f"{self.name}: could not map record: {exc}") from exc

            alert_id = str(alert_payload.get("alert_id", ""))
            if alert_id and alert_id in self._seen_ids:
                continue
            self._seen_ids.add(alert_id)

            # Validation is not optional and not overridable: the boundary is
            # one function, and every adapter goes through it.
            yield parse_alert(alert_payload)

        self._cursor = polled_at


def _map_severity(value: Any, mapping: dict[str, Severity]) -> str:
    """Coerce a vendor severity onto ours, defaulting to medium.

    Unknown values become 'medium' rather than 'info': a severity we do not
    recognise is not evidence of harmlessness, and defaulting downwards would
    let an unmapped vendor label quietly skip the triage the alert deserves.
    """
    key = str(value).strip().lower()
    return mapping.get(key, Severity.MEDIUM).value


class ElasticSource(HttpPollingSource):
    """Elasticsearch / Elastic Security detection alerts."""

    name = "elastic"

    _SEVERITY = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }

    def __init__(self, base_url: str, *, index: str = ".alerts-security.alerts-default", **kwargs: Any) -> None:
        super().__init__(base_url, **kwargs)
        self.index = index

    def _request(self, since: datetime, limit: int) -> tuple[str, dict[str, Any]]:
        return (
            f"{self.base_url}/{self.index}/_search",
            {
                "size": limit,
                "sort": [{"@timestamp": "asc"}],
                "query": {"range": {"@timestamp": {"gt": since.isoformat()}}},
            },
        )

    def _records(self, payload: Any) -> list[dict[str, Any]]:
        hits = (payload or {}).get("hits", {}).get("hits", [])
        return [hit.get("_source", {}) for hit in hits]

    def _to_alert_payload(self, record: dict[str, Any]) -> dict[str, Any]:
        rule = record.get("kibana.alert.rule.name") or record.get("rule", {}).get("name", "")
        host = record.get("host", {}).get("name", "")
        user = record.get("user", {}).get("name", "")

        assets = []
        if host:
            assets.append({"name": host, "asset_type": "host", "ip_address": record.get("host", {}).get("ip")})
        if user:
            assets.append({"name": user, "asset_type": "user"})

        indicators = []
        destination_ip = record.get("destination", {}).get("ip")
        if destination_ip:
            indicators.append(
                {"value": str(destination_ip), "indicator_type": "ipv4", "context": "destination"}
            )

        return {
            "alert_id": str(record.get("kibana.alert.uuid") or record.get("event", {}).get("id", "")),
            "source": "Elastic Security",
            "title": str(rule or "Elastic detection alert")[:512],
            "description": str(record.get("kibana.alert.reason") or record.get("message", ""))[:8192],
            "detected_at": record.get("@timestamp"),
            "reported_severity": _map_severity(
                record.get("kibana.alert.severity") or record.get("event", {}).get("severity"),
                self._SEVERITY,
            ),
            "assets": assets,
            "indicators": indicators,
            "raw_event": {"detection_rule": rule},
        }


class SplunkSource(HttpPollingSource):
    """Splunk notable events via the search REST API."""

    name = "splunk"

    _SEVERITY = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFO,
    }

    def __init__(self, base_url: str, *, search: str = "search `notable`", **kwargs: Any) -> None:
        super().__init__(base_url, **kwargs)
        self.search = search

    def _request(self, since: datetime, limit: int) -> tuple[str, dict[str, Any]]:
        return (
            f"{self.base_url}/services/search/jobs/export",
            {
                "search": self.search,
                "earliest_time": since.isoformat(),
                "output_mode": "json",
                "count": limit,
            },
        )

    def _records(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [entry.get("result", entry) for entry in payload]
        return [entry.get("result", entry) for entry in (payload or {}).get("results", [])]

    def _to_alert_payload(self, record: dict[str, Any]) -> dict[str, Any]:
        host = record.get("host") or record.get("dest", "")
        return {
            "alert_id": str(record.get("event_id") or record.get("_cd", "")),
            "source": "Splunk",
            "title": str(record.get("rule_title") or record.get("search_name", "Splunk notable"))[:512],
            "description": str(record.get("rule_description") or record.get("_raw", ""))[:8192],
            "detected_at": record.get("_time"),
            "reported_severity": _map_severity(record.get("urgency") or record.get("severity"), self._SEVERITY),
            "assets": [{"name": str(host), "asset_type": "host"}] if host else [],
            "indicators": [],
            "raw_event": {"detection_rule": str(record.get("search_name", ""))},
        }


class SentinelSource(HttpPollingSource):
    """Microsoft Sentinel incidents via the Azure management API."""

    name = "sentinel"

    _SEVERITY = {
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFO,
    }

    def _request(self, since: datetime, limit: int) -> tuple[str, dict[str, Any]]:
        return (
            f"{self.base_url}/providers/Microsoft.SecurityInsights/incidents",
            {"$top": limit, "$filter": f"properties/createdTimeUtc gt {since.isoformat()}"},
        )

    def _records(self, payload: Any) -> list[dict[str, Any]]:
        return list((payload or {}).get("value", []))

    def _to_alert_payload(self, record: dict[str, Any]) -> dict[str, Any]:
        properties = record.get("properties", {})
        return {
            "alert_id": str(record.get("name", "")),
            "source": "Microsoft Sentinel",
            "title": str(properties.get("title", "Sentinel incident"))[:512],
            "description": str(properties.get("description", ""))[:8192],
            "detected_at": properties.get("createdTimeUtc"),
            "reported_severity": _map_severity(properties.get("severity"), self._SEVERITY),
            "assets": [],
            "indicators": [],
            "raw_event": {"detection_rule": str(properties.get("relatedAnalyticRuleIds", [""])[:1])},
        }


SOURCES: dict[str, type[AlertSource]] = {
    "elastic": ElasticSource,
    "splunk": SplunkSource,
    "sentinel": SentinelSource,
}
