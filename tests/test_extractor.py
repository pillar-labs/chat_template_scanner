from __future__ import annotations

from pathlib import Path

import pytest

from pillar_gguf_scanner import (
    BufferUnderrunError,
    extract_chat_templates,
    parse_chat_templates_from_bytes,
    read_metadata_from_file,
)


def test_read_metadata_from_file_with_named_templates(gguf_template_factory) -> None:
    path = gguf_template_factory(
        named_templates={"chatml": "{{ message }}", "plain": "{{ user_input }}"},
        default_template="{{ bos_token }}",
    )

    extraction = read_metadata_from_file(path)

    assert extraction.has_template is True
    assert extraction.default_template == "{{ bos_token }}"
    assert set(extraction.template_names) == {"chatml", "plain"}
    assert extraction.named_templates["chatml"] == "{{ message }}"
    assert extraction.named_templates["plain"] == "{{ user_input }}"


def test_parse_chat_templates_requires_complete_header(gguf_template_factory) -> None:
    path = gguf_template_factory()
    data = path.read_bytes()
    truncated = data[:16]
    with pytest.raises(BufferUnderrunError):
        parse_chat_templates_from_bytes(truncated)


def test_extract_chat_templates_fallback_scan() -> None:
    metadata = {
        "tokenizer.chat_template": "{{ default }}",
        "tokenizer.chat_template.chatml": "{{ chatml }}",
    }

    extraction = extract_chat_templates(metadata)

    assert extraction.has_template is True
    assert extraction.default_template == "{{ default }}"
    assert extraction.named_templates == {"chatml": "{{ chatml }}"}
    assert extraction.template_names == ["chatml"]


def test_read_metadata_from_real_fixture(
    gte_small_gguf_path: Path,
    gte_small_template_text: str,
) -> None:
    extraction = read_metadata_from_file(gte_small_gguf_path)

    assert extraction.has_template is True
    assert extraction.default_template == gte_small_template_text
    assert extraction.named_templates == {}
    assert extraction.template_names == []
    assert extraction.metadata_keys["tokenizer.chat_template"] == gte_small_template_text
