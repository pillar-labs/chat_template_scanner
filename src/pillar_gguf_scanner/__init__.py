"""Public facing API and metadata for the `pillar_gguf_scanner` package."""

from .cli import main as cli_main  # noqa: F401
from .exceptions import (  # noqa: F401
    BufferUnderrunError,
    ChatTemplateExtractionError,
    GGUFParseError,
    InvalidMagicError,
    PillarClientError,
    RemoteFetchError,
    UnsupportedValueTypeError,
)
from .heuristics import DEFAULT_PATTERNS, merge_heuristics, run_heuristics  # noqa: F401
from .models import (  # noqa: F401
    ErrorDetail,
    HuggingFaceRepoRef,
    PatternRule,
    PillarFinding,
    ScannerConfig,
    ScanResult,
    Severity,
    TemplateFinding,
    TemplateScanEvidence,
    Verdict,
    build_template_hashes,
    build_template_lengths,
)
from .reader import (  # noqa: F401
    ChatTemplateExtraction,
    extract_chat_templates,
    parse_chat_templates_from_bytes,
    read_metadata_from_file,
)
from .remote import (  # noqa: F401
    afetch_chat_templates_from_huggingface,
    afetch_chat_templates_from_url,
    build_huggingface_url,
    fetch_chat_templates_from_huggingface,
    fetch_chat_templates_from_url,
)
from .scanner import GGUFTemplateScanner, ascanner_session, scanner_session  # noqa: F401

__all__ = [
    "__version__",
    "GGUFTemplateScanner",
    "ScanResult",
    "TemplateScanEvidence",
    "TemplateFinding",
    "PatternRule",
    "ErrorDetail",
    "PillarFinding",
    "ScannerConfig",
    "Severity",
    "Verdict",
    "HuggingFaceRepoRef",
    "ChatTemplateExtraction",
    "extract_chat_templates",
    "parse_chat_templates_from_bytes",
    "read_metadata_from_file",
    "fetch_chat_templates_from_url",
    "fetch_chat_templates_from_huggingface",
    "afetch_chat_templates_from_url",
    "afetch_chat_templates_from_huggingface",
    "build_huggingface_url",
    "BufferUnderrunError",
    "ChatTemplateExtractionError",
    "GGUFParseError",
    "InvalidMagicError",
    "PillarClientError",
    "RemoteFetchError",
    "UnsupportedValueTypeError",
    "build_template_hashes",
    "build_template_lengths",
    "cli_main",
    "scanner_session",
    "ascanner_session",
    "merge_heuristics",
    "DEFAULT_PATTERNS",
    "run_heuristics",
]

__version__ = "0.1.0"
