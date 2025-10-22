"""Shared pytest fixtures for the pillar_gguf_scanner library tests."""

from __future__ import annotations

import socket
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Dict, Optional
from unittest import mock

import gguf
import httpx
import pytest

from pillar_gguf_scanner.models import (
    ScanResult,
    TemplateScanEvidence,
    Verdict,
)


@pytest.fixture
def unused_tcp_port() -> int:
    """Provide an available TCP port for tests."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        port = sock.getsockname()[1]
    return port


@pytest.fixture
def gte_small_gguf_path() -> Path:
    """Path to the repository-provided GGUF file with an embedded chat template."""
    return Path(__file__).parent / "data" / "gte-small.Q2_K.gguf"


@pytest.fixture
def gte_small_template_text() -> str:
    """Expected chat template content embedded in the GGUF fixture."""
    return (
        "{% for message in messages %}\n"
        "{{ '[' ~ message['role'] ~ ']: ' ~ message['content'] ~ '\n' }}\n"
        "{% endfor %}{% if add_generation_prompt %}assistant: {% endif %}"
    )


@pytest.fixture
def gguf_template_factory(tmp_path: Path) -> Callable[..., Path]:
    """Create GGUF files with configurable chat templates for testing."""

    def factory(
        *,
        default_template: str = "{{ bos_token }} {{ system_message }}",
        named_templates: Optional[Dict[str, str]] = None,
        filename: str = "sample.gguf",
    ) -> Path:
        path = tmp_path / filename
        writer = gguf.GGUFWriter(str(path), arch="test-arch")

        if named_templates:
            entries = []
            if default_template is not None:
                entries.append({"name": "default", "template": default_template})
            for name, template in named_templates.items():
                entries.append({"name": name, "template": template})
            writer.add_chat_template(entries)
        else:
            writer.add_chat_template(default_template)

        writer.write_header_to_file()
        writer.write_kv_data_to_file()
        writer.write_tensors_to_file()
        writer.close()

        return path

    return factory


@pytest.fixture
def scan_result_factory():
    """Factory for building ScanResult objects with minimal boilerplate."""

    def factory(
        *,
        verdict: Verdict,
        findings=None,
        pillar_findings=None,
        errors=None,
        source: str = "sentinel.gguf",
    ) -> ScanResult:
        return ScanResult(
            verdict=verdict,
            evidence=TemplateScanEvidence(
                default_template=None,
                named_templates={},
                metadata_keys={},
                template_hashes={},
                template_lengths={},
            ),
            findings=list(findings or []),
            pillar_findings=list(pillar_findings or []),
            source=source,
            errors=list(errors or []),
        )

    return factory


@pytest.fixture
def http_response_factory():
    """Create an autospecced httpx.Response mock."""

    def factory(*, status_code: int = 200, payload=None, content: bytes = b"", text: str = ""):
        response = mock.create_autospec(httpx.Response, instance=True)
        response.status_code = status_code
        response.text = text
        response.content = content
        if payload is None:
            response.json.return_value = {}
        elif isinstance(payload, Exception):
            response.json.side_effect = payload
        else:
            response.json.return_value = payload
        return response

    return factory


@pytest.fixture
def http_post_client_factory():
    """Factory that produces autospecced httpx.Client mocks handling POST requests."""

    def factory(response):
        client = mock.create_autospec(httpx.Client, instance=True)
        calls = []

        def post(url, *, json, headers):
            calls.append((url, json, headers))
            if isinstance(response, Exception):
                raise response
            return response

        client.post.side_effect = post
        client.close = mock.Mock()
        client.calls = calls
        return client

    return factory


@pytest.fixture
def http_async_post_client_factory():
    """Factory that produces autospecced httpx.AsyncClient mocks handling POST requests."""

    def factory(response):
        client = mock.create_autospec(httpx.AsyncClient, instance=True)
        calls = []

        async def post(url, *, json, headers):
            calls.append((url, json, headers))
            if isinstance(response, Exception):
                raise response
            return response

        client.post = mock.AsyncMock(side_effect=post)
        client.aclose = mock.AsyncMock()
        client.calls = calls
        return client

    return factory


@pytest.fixture
def http_get_client_factory():
    """Factory that produces autospecced httpx.Client mocks handling sequential GET requests."""

    def factory(responses):
        iterator = iter(responses)
        client = mock.create_autospec(httpx.Client, instance=True)
        requests = []

        def get(url, *, headers):
            requests.append(headers)
            response = next(iterator)
            if isinstance(response, Exception):
                raise response
            return response

        client.get.side_effect = get
        client.close = mock.Mock()
        client.requests = requests
        return client

    return factory


@pytest.fixture
def http_async_get_client_factory():
    """Factory that produces autospecced httpx.AsyncClient mocks handling sequential GET requests."""

    def factory(responses):
        iterator = iter(responses)
        client = mock.create_autospec(httpx.AsyncClient, instance=True)
        requests = []

        async def get(url, *, headers):
            requests.append(headers)
            response = next(iterator)
            if isinstance(response, Exception):
                raise response
            return response

        client.get = mock.AsyncMock(side_effect=get)
        client.aclose = mock.AsyncMock()
        client.requests = requests
        return client

    return factory
