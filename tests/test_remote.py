from __future__ import annotations

from typing import Tuple

import pytest
from aiohttp import web

from pillar_gguf_scanner import (
    ScannerConfig,
    afetch_chat_templates_from_url,
    parse_chat_templates_from_bytes,
)


def _parse_range_header(header: str) -> Tuple[int, int | None]:
    unit, _, value = header.partition("=")
    if unit.strip().lower() != "bytes":
        raise ValueError("unsupported range unit")
    start_str, _, end_str = value.partition("-")
    start = int(start_str)
    end = int(end_str) if end_str else None
    return start, end


@pytest.mark.asyncio
async def test_fetch_chat_templates_from_url(gguf_template_factory, unused_tcp_port: int) -> None:
    path = gguf_template_factory(
        default_template="{{ custom_default }}",
        named_templates={"alt": "{{ alt_template }}"},
    )
    payload = path.read_bytes()

    async def handler(request: web.Request) -> web.StreamResponse:
        range_header = request.headers.get("Range")
        if range_header:
            start, end = _parse_range_header(range_header)
            end = end if end is not None else len(payload) - 1
            end = min(end, len(payload) - 1)
            body = payload[start : end + 1]
            headers = {
                "Content-Range": f"bytes {start}-{start + len(body) - 1}/{len(payload)}",
                "Accept-Ranges": "bytes",
            }
            return web.Response(status=206, body=body, headers=headers)
        return web.Response(body=payload)

    app = web.Application()
    app.router.add_get("/model.gguf", handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", unused_tcp_port)
    await site.start()

    try:
        payload = await afetch_chat_templates_from_url(
            f"http://127.0.0.1:{unused_tcp_port}/model.gguf",
            config=ScannerConfig(initial_request_size=32, max_request_size=1024),
        )
    finally:
        await runner.cleanup()

    extraction = parse_chat_templates_from_bytes(payload)
    assert extraction.default_template == "{{ custom_default }}"
    assert extraction.named_templates == {"alt": "{{ alt_template }}"}
