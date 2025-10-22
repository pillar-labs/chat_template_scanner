from __future__ import annotations

from unittest import mock

import httpx
import pytest

from pillar_gguf_scanner import BufferUnderrunError, RemoteFetchError, ScannerConfig
from pillar_gguf_scanner.remote import (
    afetch_chat_templates_from_url,
    build_huggingface_url,
    fetch_chat_templates_from_url,
)


def test_fetch_chat_templates_from_url_success(
    monkeypatch,
    http_response_factory,
    http_get_client_factory,
) -> None:
    responses = [http_response_factory(status_code=200, content=b"template-bytes")]
    client = http_get_client_factory(responses)
    monkeypatch.setattr(
        "pillar_gguf_scanner.remote.parse_chat_templates_from_bytes",
        lambda payload: None,
    )

    payload = fetch_chat_templates_from_url(
        "https://example.com/model.gguf",
        client=client,
        config=ScannerConfig(initial_request_size=8, max_request_size=16),
    )

    assert payload == b"template-bytes"
    assert client.requests[0]["Range"] == "bytes=0-7"


def test_fetch_chat_templates_doubles_request_on_buffer(
    monkeypatch,
    http_response_factory,
    http_get_client_factory,
) -> None:
    responses = [
        http_response_factory(status_code=200, content=b"first"),
        http_response_factory(status_code=200, content=b"second payload"),
    ]
    client = http_get_client_factory(responses)

    calls = []

    def fake_parse(payload):
        calls.append(payload)
        if len(calls) == 1:
            raise BufferUnderrunError("need more data", required_bytes=12)

    monkeypatch.setattr("pillar_gguf_scanner.remote.parse_chat_templates_from_bytes", fake_parse)

    payload = fetch_chat_templates_from_url(
        "https://example.com/model.gguf",
        client=client,
        config=ScannerConfig(initial_request_size=5, max_request_size=20),
    )

    assert payload == b"firstsecond payload"
    assert [headers["Range"] for headers in client.requests] == ["bytes=0-4", "bytes=5-11"]


def test_fetch_chat_templates_raises_on_timeout(
    monkeypatch,
    http_get_client_factory,
) -> None:
    client = http_get_client_factory([httpx.TimeoutException("timeout")])
    monkeypatch.setattr(
        "pillar_gguf_scanner.remote.parse_chat_templates_from_bytes",
        lambda payload: None,
    )

    with pytest.raises(RemoteFetchError):
        fetch_chat_templates_from_url(
            "https://example.com/model.gguf",
            client=client,
            config=ScannerConfig(initial_request_size=4, max_request_size=8),
        )


def test_fetch_chat_templates_reports_declared_size(
    monkeypatch,
    http_response_factory,
    http_get_client_factory,
) -> None:
    responses = [http_response_factory(status_code=200, content=b"incomplete")]
    client = http_get_client_factory(responses)

    def fake_parse(payload):
        raise BufferUnderrunError("need more data", required_bytes=40)

    monkeypatch.setattr("pillar_gguf_scanner.remote.parse_chat_templates_from_bytes", fake_parse)

    with pytest.raises(RemoteFetchError) as exc_info:
        fetch_chat_templates_from_url(
            "https://example.com/model.gguf",
            client=client,
            config=ScannerConfig(initial_request_size=8, max_request_size=32),
        )

    assert "requires 40 bytes" in str(exc_info.value)


def test_fetch_creates_clients_with_redirects(monkeypatch, http_response_factory) -> None:
    response = http_response_factory(status_code=200, content=b"stub")
    client_instance = mock.create_autospec(httpx.Client, instance=True)
    client_instance.get.return_value = response
    client_instance.close = mock.Mock()

    factory = mock.Mock(return_value=client_instance)
    monkeypatch.setattr("pillar_gguf_scanner.remote.httpx.Client", factory)
    monkeypatch.setattr(
        "pillar_gguf_scanner.remote.parse_chat_templates_from_bytes",
        lambda payload: None,
    )

    fetch_chat_templates_from_url("https://example.com/model.gguf")

    factory.assert_called_once()
    _, kwargs = factory.call_args
    assert kwargs["follow_redirects"] is True
    client_instance.close.assert_called_once()


@pytest.mark.asyncio
async def test_afetch_creates_clients_with_redirects(monkeypatch, http_response_factory) -> None:
    response = http_response_factory(status_code=200, content=b"stub")
    async_client = mock.create_autospec(httpx.AsyncClient, instance=True)
    async_client.get = mock.AsyncMock(return_value=response)
    async_client.aclose = mock.AsyncMock()

    factory = mock.Mock(return_value=async_client)
    monkeypatch.setattr("pillar_gguf_scanner.remote.httpx.AsyncClient", factory)
    monkeypatch.setattr(
        "pillar_gguf_scanner.remote.parse_chat_templates_from_bytes",
        lambda payload: None,
    )

    await afetch_chat_templates_from_url("https://example.com/model.gguf")

    factory.assert_called_once()
    _, kwargs = factory.call_args
    assert kwargs["follow_redirects"] is True
    async_client.get.assert_awaited()
    async_client.aclose.assert_awaited_once()


def test_build_huggingface_url_validates_repo() -> None:
    with pytest.raises(RemoteFetchError):
        build_huggingface_url("invalid", "model.gguf")
