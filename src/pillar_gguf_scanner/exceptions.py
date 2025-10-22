"""Custom exceptions used by the scanner library."""

from __future__ import annotations


class GGUFParseError(Exception):
    """Raised when GGUF file metadata cannot be parsed.

    Base exception for all GGUF parsing failures including invalid format,
    corrupted headers, or unsupported GGUF versions.
    """


class BufferUnderrunError(GGUFParseError):
    """Raised when an incomplete buffer is provided for GGUF parsing.

    Occurs when the provided data is truncated and doesn't contain enough
    bytes to parse the GGUF header completely. The required_bytes attribute
    indicates how many bytes are needed (if known).

    Attributes:
        required_bytes: Optional hint for how many total bytes are needed.
    """

    def __init__(self, message: str | None = None, *, required_bytes: int | None = None) -> None:
        super().__init__(message or "buffer underrun")
        self.required_bytes = required_bytes


class InvalidMagicError(GGUFParseError):
    """Raised when the GGUF header does not begin with the expected magic bytes.

    GGUF files must start with the magic bytes 'GGUF'. This error indicates
    the file is not a valid GGUF file or is corrupted.
    """


class UnsupportedValueTypeError(GGUFParseError):
    """Raised when an unknown GGUF metadata value type is encountered.

    GGUF files use typed key-value metadata. This error occurs when the
    scanner encounters a type identifier it doesn't recognize, possibly
    from a newer GGUF specification version.
    """


class ChatTemplateExtractionError(Exception):
    """Raised when chat template metadata is missing or malformed.

    Occurs when the GGUF file doesn't contain the expected chat template
    metadata keys, or when template values are in an unexpected format.
    """


class RemoteFetchError(Exception):
    """Raised when a remote GGUF file cannot be downloaded.

    Network errors, HTTP errors, timeouts, or other issues fetching GGUF
    files from URLs or Hugging Face repositories will raise this exception.
    """


class PillarClientError(Exception):
    """Raised when a Pillar API call fails.

    Indicates authentication failures, rate limiting, network errors, or
    invalid API responses from Pillar's remote scanning service.
    """
