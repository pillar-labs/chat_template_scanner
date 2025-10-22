from __future__ import annotations

import httpx
import pytest

from pillar_gguf_scanner.models import Severity
from pillar_gguf_scanner.pillar_client import PillarClient, PillarClientError


def test_scan_requires_api_key() -> None:
    client = PillarClient(api_key="")

    with pytest.raises(PillarClientError):
        client.scan("template")


def test_scan_returns_findings(http_response_factory, http_post_client_factory) -> None:
    payload = {
        "findings": [
            {
                "rule_id": "prompt_override",
                "severity": "critical",
                "message": "Critical override",
                "snippet": "danger",
                "extra": "value",
            },
            {
                "id": "secondary",
                "severity": "moderate",
                "detail": "Moderate issue",
            },
        ]
    }
    response = http_response_factory(status_code=200, payload=payload)
    http_client = http_post_client_factory(response)

    client = PillarClient(
        api_key="token",
        client=http_client,
    )

    findings = client.scan("payload")

    assert len(findings) == 2
    assert findings[0].rule_id == "prompt_override"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].metadata["extra"] == "value"
    assert findings[1].rule_id == "secondary"
    assert findings[1].severity == Severity.MEDIUM
    assert http_client.calls


def test_scan_handles_transport_errors(http_post_client_factory) -> None:
    http_client = http_post_client_factory(httpx.TimeoutException("timeout"))
    client = PillarClient(api_key="token", client=http_client)

    with pytest.raises(PillarClientError) as exc_info:
        client.scan("payload")

    assert "failed to call Pillar API" in str(exc_info.value)


def test_scan_handles_http_error_status(http_response_factory, http_post_client_factory) -> None:
    response = http_response_factory(status_code=500, payload={}, text="server error")
    http_client = http_post_client_factory(response)
    client = PillarClient(api_key="token", client=http_client)

    with pytest.raises(PillarClientError):
        client.scan("payload")


def test_scan_handles_invalid_json(http_response_factory, http_post_client_factory) -> None:
    response = http_response_factory(status_code=200, payload=ValueError("invalid"))
    http_client = http_post_client_factory(response)
    client = PillarClient(api_key="token", client=http_client)

    with pytest.raises(PillarClientError):
        client.scan("payload")


@pytest.mark.asyncio
async def test_ascan_mirrors_success(http_response_factory, http_async_post_client_factory) -> None:
    payload = {
        "issues": [
            {
                "id": "remote-alert",
                "severity": "warning",
                "detail": "Heads up",
            }
        ]
    }
    response = http_response_factory(status_code=200, payload=payload)
    async_client = http_async_post_client_factory(response)

    client = PillarClient(api_key="token", async_client=async_client)

    findings = await client.ascan("payload")

    assert len(findings) == 1
    assert findings[0].rule_id == "remote-alert"
    assert findings[0].severity == Severity.LOW
    assert async_client.calls
