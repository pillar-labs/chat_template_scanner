"""Thin wrapper around the Pillar prompt scanning API."""

from __future__ import annotations

import logging
import time
from typing import Iterable, List, Optional

import httpx

from .exceptions import PillarClientError
from .models import PillarFinding, ScannerConfig, Severity

logger = logging.getLogger("pillar_gguf_scanner.pillar_client")


def _map_severity(value: str) -> Severity:
    normalized = value.lower()
    if normalized == "critical":
        return Severity.CRITICAL
    if normalized in ("high",):
        return Severity.HIGH
    if normalized in ("medium", "moderate"):
        return Severity.MEDIUM
    if normalized in ("low", "warning"):
        return Severity.LOW
    return Severity.INFO


class PillarClient:
    """Client that communicates with the Pillar prompt scanning endpoint."""

    def __init__(
        self,
        api_key: str,
        *,
        endpoint: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        async_client: Optional[httpx.AsyncClient] = None,
        config: Optional[ScannerConfig] = None,
    ) -> None:
        self._api_key = api_key
        self._config = config or ScannerConfig()
        self._endpoint = endpoint or self._config.pillar_endpoint
        self._client = client
        self._async_client = async_client

    def _build_payload(self, template: str) -> dict:
        return {
            "message": template,
            "scanners": {
                "prompt_injection": True,
                "secrets": True,
                "pii": True,
            },
        }

    def _extract_findings(self, data: dict) -> List[PillarFinding]:
        findings: List[PillarFinding] = []
        raw_findings: Iterable[dict] = data.get("findings") or data.get("issues") or []
        for item in raw_findings:
            rule_id = item.get("rule_id") or item.get("id") or "pillar"
            severity = _map_severity(item.get("severity", "info"))
            message = item.get("message") or item.get("detail") or "Pillar reported issue"
            snippet = item.get("snippet") or item.get("example")
            metadata = {
                key: value
                for key, value in item.items()
                if key not in {"rule_id", "id", "severity", "message", "detail", "snippet", "example"}
            }
            findings.append(
                PillarFinding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    snippet=snippet,
                    metadata=dict(metadata),
                )
            )
        return findings

    def scan(self, template: str) -> List[PillarFinding]:
        if not self._api_key:
            raise PillarClientError("Pillar API key is required for remote scans")

        timeout = httpx.Timeout(self._config.request_timeout)
        close_client = False
        client = self._client
        if client is None:
            client = httpx.Client(timeout=timeout)
            close_client = True

        try:
            start = time.perf_counter()
            response = client.post(
                self._endpoint,
                json=self._build_payload(template),
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
            latency = time.perf_counter() - start
            logger.debug(
                "Pillar API response %s in %.3fs",
                response.status_code,
                latency,
            )
        except httpx.HTTPError as exc:
            raise PillarClientError(f"failed to call Pillar API: {exc}") from exc
        finally:
            if close_client:
                client.close()

        if response.status_code >= 400:
            raise PillarClientError(f"Pillar API returned HTTP {response.status_code}: {response.text}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise PillarClientError("Pillar API returned invalid JSON") from exc

        return self._extract_findings(payload)

    async def ascan(self, template: str) -> List[PillarFinding]:
        if not self._api_key:
            raise PillarClientError("Pillar API key is required for remote scans")

        timeout = httpx.Timeout(self._config.request_timeout)
        close_client = False
        client = self._async_client
        if client is None:
            client = httpx.AsyncClient(timeout=timeout)
            close_client = True

        try:
            start = time.perf_counter()
            response = await client.post(
                self._endpoint,
                json=self._build_payload(template),
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
            latency = time.perf_counter() - start
            logger.debug(
                "Pillar API response %s in %.3fs",
                response.status_code,
                latency,
            )
        except httpx.HTTPError as exc:
            raise PillarClientError(f"failed to call Pillar API: {exc}") from exc
        finally:
            if close_client:
                await client.aclose()

        if response.status_code >= 400:
            raise PillarClientError(f"Pillar API returned HTTP {response.status_code}: {response.text}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise PillarClientError("Pillar API returned invalid JSON") from exc

        return self._extract_findings(payload)
