"""Utilities for parsing GGUF headers and extracting templates."""

from __future__ import annotations

import struct
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from gguf import GGUF_MAGIC, GGUFValueType, Keys

from .exceptions import (
    BufferUnderrunError,
    ChatTemplateExtractionError,
    GGUFParseError,
    InvalidMagicError,
    UnsupportedValueTypeError,
)

_STRUCT_UINT32 = struct.Struct("<I")
_STRUCT_UINT64 = struct.Struct("<Q")
_STRUCT_INT8 = struct.Struct("<b")
_STRUCT_UINT8 = struct.Struct("<B")
_STRUCT_INT16 = struct.Struct("<h")
_STRUCT_UINT16 = struct.Struct("<H")
_STRUCT_INT32 = struct.Struct("<i")
_STRUCT_FLOAT32 = struct.Struct("<f")
_STRUCT_INT64 = struct.Struct("<q")
_STRUCT_FLOAT64 = struct.Struct("<d")


class _ByteReader:
    """Helper for reading structured data from bytes."""

    __slots__ = ("_view", "_offset")

    def __init__(self, buffer: bytes | bytearray | memoryview) -> None:
        self._view = memoryview(buffer)
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    def _require(self, size: int) -> None:
        if self._offset + size > len(self._view):
            required = self._offset + size
            raise BufferUnderrunError(
                f"not enough data to read {size} bytes at offset {self._offset}",
                required_bytes=required,
            )

    def read(self, size: int) -> memoryview:
        self._require(size)
        start = self._offset
        end = start + size
        self._offset = end
        return self._view[start:end]

    def read_uint32(self) -> int:
        return _STRUCT_UINT32.unpack_from(self.read(_STRUCT_UINT32.size))[0]

    def read_uint64(self) -> int:
        return _STRUCT_UINT64.unpack_from(self.read(_STRUCT_UINT64.size))[0]

    def read_int8(self) -> int:
        return _STRUCT_INT8.unpack_from(self.read(_STRUCT_INT8.size))[0]

    def read_uint8(self) -> int:
        return _STRUCT_UINT8.unpack_from(self.read(_STRUCT_UINT8.size))[0]

    def read_int16(self) -> int:
        return _STRUCT_INT16.unpack_from(self.read(_STRUCT_INT16.size))[0]

    def read_uint16(self) -> int:
        return _STRUCT_UINT16.unpack_from(self.read(_STRUCT_UINT16.size))[0]

    def read_int32(self) -> int:
        return _STRUCT_INT32.unpack_from(self.read(_STRUCT_INT32.size))[0]

    def read_float32(self) -> float:
        return _STRUCT_FLOAT32.unpack_from(self.read(_STRUCT_FLOAT32.size))[0]

    def read_int64(self) -> int:
        return _STRUCT_INT64.unpack_from(self.read(_STRUCT_INT64.size))[0]

    def read_uint64_as_int(self) -> int:
        return self.read_uint64()

    def read_float64(self) -> float:
        return _STRUCT_FLOAT64.unpack_from(self.read(_STRUCT_FLOAT64.size))[0]

    def read_bool(self) -> bool:
        return bool(self.read_uint8())


@dataclass(frozen=True)
class GGUFHeaderMetadata:
    """Representation of parsed GGUF metadata."""

    version: int
    tensor_count: int
    kv_count: int
    metadata: "OrderedDict[str, Any]"
    header_length: int


@dataclass(frozen=True)
class ChatTemplateExtraction:
    """Result of extracting chat templates from GGUF metadata.

    Contains the parsed chat template(s) and related metadata extracted from
    a GGUF file header.

    Attributes:
        has_template: True if any chat template was found in the metadata.
        default_template: The default chat template string, or None if not present.
        named_templates: Dictionary mapping template names to their content.
        template_names: List of all template names found.
        metadata_keys: All metadata key-value pairs from the GGUF header.
    """

    has_template: bool
    default_template: Optional[str]
    named_templates: Dict[str, str]
    template_names: Sequence[str]
    metadata_keys: Dict[str, Any]


def _read_string(reader: _ByteReader) -> str:
    length = reader.read_uint64_as_int()
    raw = reader.read(length)
    return raw.tobytes().decode("utf-8")


def _read_value(reader: _ByteReader, value_type: GGUFValueType) -> Any:
    if value_type == GGUFValueType.UINT8:
        return reader.read_uint8()
    if value_type == GGUFValueType.INT8:
        return reader.read_int8()
    if value_type == GGUFValueType.UINT16:
        return reader.read_uint16()
    if value_type == GGUFValueType.INT16:
        return reader.read_int16()
    if value_type == GGUFValueType.UINT32:
        return reader.read_uint32()
    if value_type == GGUFValueType.INT32:
        return reader.read_int32()
    if value_type == GGUFValueType.FLOAT32:
        return reader.read_float32()
    if value_type == GGUFValueType.BOOL:
        return reader.read_bool()
    if value_type == GGUFValueType.STRING:
        return _read_string(reader)
    if value_type == GGUFValueType.ARRAY:
        sub_type = GGUFValueType(reader.read_uint32())
        length = reader.read_uint64_as_int()
        entries: list[Any] = []
        for _ in range(length):
            entries.append(_read_value(reader, sub_type))
        return entries
    if value_type == GGUFValueType.UINT64:
        return reader.read_uint64()
    if value_type == GGUFValueType.INT64:
        return reader.read_int64()
    if value_type == GGUFValueType.FLOAT64:
        return reader.read_float64()

    raise UnsupportedValueTypeError(f"unsupported metadata value type: {value_type!r}")


def parse_metadata_section(buffer: bytes | bytearray | memoryview) -> GGUFHeaderMetadata:
    """Parse the metadata section of a GGUF header."""

    reader = _ByteReader(buffer)
    if reader.read_uint32() != GGUF_MAGIC:
        raise InvalidMagicError("buffer does not start with GGUF magic")

    version = reader.read_uint32()
    tensor_count = reader.read_uint64()
    kv_count = reader.read_uint64()
    metadata: "OrderedDict[str, Any]" = OrderedDict()

    for _ in range(kv_count):
        key_length = reader.read_uint64()
        key_bytes = reader.read(key_length)
        try:
            key = key_bytes.tobytes().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GGUFParseError(f"unable to decode metadata key: {exc}") from exc
        value_type = GGUFValueType(reader.read_uint32())
        metadata[key] = _read_value(reader, value_type)

    return GGUFHeaderMetadata(
        version=version,
        tensor_count=tensor_count,
        kv_count=kv_count,
        metadata=metadata,
        header_length=reader.offset,
    )


def extract_chat_templates(metadata: Mapping[str, Any]) -> ChatTemplateExtraction:
    """Extract chat templates from parsed GGUF metadata.

    Searches for tokenizer.chat_template and named template variants in the
    metadata dictionary and returns a structured representation.

    Args:
        metadata: Parsed GGUF metadata key-value pairs.

    Returns:
        ChatTemplateExtraction with parsed templates.

    Raises:
        ChatTemplateExtractionError: If template metadata is malformed.
    """

    default_template = metadata.get(Keys.Tokenizer.CHAT_TEMPLATE)
    if default_template is not None and not isinstance(default_template, str):
        raise ChatTemplateExtractionError(f"expected tokenizer.chat_template to be str, got {type(default_template)!r}")

    template_names_value = metadata.get(Keys.Tokenizer.CHAT_TEMPLATES, [])
    template_names: list[str] = []
    if isinstance(template_names_value, Sequence) and not isinstance(template_names_value, (str, bytes)):
        for entry in template_names_value:
            if isinstance(entry, str):
                template_names.append(entry)
    elif template_names_value:
        raise ChatTemplateExtractionError("tokenizer.chat_templates should be a sequence of strings")

    named_templates: dict[str, str] = {}
    prefix = "tokenizer.chat_template."

    for name in template_names:
        key = prefix + name
        value = metadata.get(key)
        if isinstance(value, str):
            named_templates[name] = value

    if not template_names:
        for key, value in metadata.items():
            if key.startswith(prefix) and isinstance(value, str):
                suffix = key[len(prefix) :]
                if suffix != "" and suffix not in named_templates:
                    named_templates[suffix] = value
                    template_names.append(suffix)

    metadata_keys: dict[str, Any] = {}
    if default_template is not None:
        metadata_keys[Keys.Tokenizer.CHAT_TEMPLATE] = default_template
    if template_names:
        metadata_keys[Keys.Tokenizer.CHAT_TEMPLATES] = list(template_names)
    for name, template in named_templates.items():
        metadata_keys[prefix + name] = template

    has_template = bool(default_template or named_templates)

    return ChatTemplateExtraction(
        has_template=has_template,
        default_template=default_template,
        named_templates=named_templates,
        template_names=list(template_names),
        metadata_keys=metadata_keys,
    )


def parse_chat_templates_from_bytes(data: bytes | bytearray | memoryview) -> ChatTemplateExtraction:
    """Parse chat templates from GGUF file bytes.

    Low-level function for extracting templates when you already have the
    GGUF file loaded into memory.

    Args:
        data: GGUF file data containing at least the complete header.

    Returns:
        ChatTemplateExtraction with parsed templates and metadata.

    Raises:
        GGUFParseError: If the GGUF header is invalid or corrupted.
        ChatTemplateExtractionError: If template metadata is malformed.

    Example:
        >>> with open("model.gguf", "rb") as f:
        ...     data = f.read(2_000_000)  # Read first 2MB
        >>> extraction = parse_chat_templates_from_bytes(data)
    """

    metadata = parse_metadata_section(data)
    return extract_chat_templates(metadata.metadata)


def read_metadata_from_file(
    path: Path,
    *,
    chunk_size: int = 1_048_576,
    max_bytes: int = 64_000_000,
) -> ChatTemplateExtraction:
    """Read chat templates from a local GGUF file with minimal I/O.

    Reads the file incrementally in chunks until the full metadata header is
    parsed, then stops. Much more efficient than loading the entire file.

    Args:
        path: Path to the .gguf file.
        chunk_size: Bytes to read per chunk. Default is 1MB.
        max_bytes: Maximum total bytes to read. Default is 64MB.

    Returns:
        ChatTemplateExtraction with parsed templates.

    Raises:
        GGUFParseError: If the file is not a valid GGUF file.
        ChatTemplateExtractionError: If template metadata is malformed.
        BufferUnderrunError: If the header is larger than max_bytes.
        OSError: If file cannot be read.

    Example:
        >>> from pathlib import Path
        >>> extraction = read_metadata_from_file(Path("model.gguf"))
        >>> print(extraction.default_template)
    """

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if max_bytes < chunk_size:
        raise ValueError("max_bytes must be >= chunk_size")

    accumulator = bytearray()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            accumulator.extend(chunk)
            try:
                return parse_chat_templates_from_bytes(accumulator)
            except BufferUnderrunError:
                if len(accumulator) >= max_bytes:
                    raise
                continue

    raise BufferUnderrunError(f"unable to parse header from {path}: file ended before header completed")
