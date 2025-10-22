"""Data models and enums shared across the scanner package."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional


class Severity(Enum):
    """Severity level attached to a finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def score(self) -> int:
        """Return a numeric score for comparisons."""

        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Verdict(Enum):
    """Overall scan verdict."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"


@dataclass(frozen=True)
class TemplateFinding:
    """A heuristic finding raised for a specific template.

    Represents a potential security issue detected by local heuristic rules
    when scanning chat templates extracted from GGUF files.

    Attributes:
        rule_id: Unique identifier for the heuristic rule that triggered this finding.
        severity: Severity level (INFO, LOW, MEDIUM, HIGH, or CRITICAL).
        message: Human-readable description of what was detected.
        template_name: Name of the template where the issue was found (e.g., "default" or a named template).
        snippet: Optional excerpt from the template showing the problematic content.
        metadata: Additional structured data about the finding for custom processing.

    Example:
        >>> finding = TemplateFinding(
        ...     rule_id="url_in_template",
        ...     severity=Severity.MEDIUM,
        ...     message="Template contains URL",
        ...     template_name="default",
        ...     snippet="http://evil.com"
        ... )
    """

    rule_id: str
    severity: Severity
    message: str
    template_name: str
    snippet: Optional[str] = None
    metadata: MutableMapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PillarFinding:
    """Finding produced by the Pillar API.

    Represents a security issue detected by Pillar's remote scanning service,
    which uses advanced ML models and threat intelligence to identify prompt
    injection attacks and other malicious patterns.

    Attributes:
        rule_id: Unique identifier for the Pillar detection rule.
        severity: Severity level assigned by Pillar's analysis engine.
        message: Description of the security issue detected.
        snippet: Optional excerpt from the template showing the malicious content.
        metadata: Additional context from Pillar's analysis.

    Note:
        Pillar findings require a valid API key and use_pillar=True when scanning.
    """

    rule_id: str
    severity: Severity
    message: str
    snippet: Optional[str] = None
    metadata: MutableMapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TemplateScanEvidence:
    """Normalized evidence returned alongside a scan result.

    Contains the extracted chat templates and metadata from a GGUF file,
    along with computed hashes and lengths for verification and analysis.

    Attributes:
        default_template: The default chat template string, or None if not present.
        named_templates: Dictionary mapping template names to their content.
        metadata_keys: All metadata keys extracted from the GGUF header.
        template_hashes: SHA-256 hashes of templates, keyed by "default" or "named:<name>".
        template_lengths: Character lengths of templates, using the same naming convention.

    Example:
        >>> evidence.default_template
        '<|im_start|>system\\n{system_message}<|im_end|>'
        >>> evidence.template_hashes["default"]
        'a1b2c3d4...'
    """

    default_template: Optional[str]
    named_templates: Dict[str, str]
    metadata_keys: Dict[str, Any]
    template_hashes: Dict[str, str]
    template_lengths: Dict[str, int]


@dataclass(frozen=True)
class ErrorDetail:
    """Structured error information returned alongside scan results.

    Errors are non-fatal issues encountered during scanning, such as network
    failures, parse errors, or API timeouts. Scan results with errors will
    have a verdict of Verdict.ERROR.

    Attributes:
        code: Error code for programmatic handling (e.g., "REMOTE_FETCH_FAILED", "PARSE_ERROR").
        message: Human-readable error description.
        context: Additional structured information about the error (stack traces, URLs, etc.).

    Example:
        >>> error = ErrorDetail(
        ...     code="REMOTE_FETCH_FAILED",
        ...     message="Failed to fetch GGUF file",
        ...     context={"url": "https://example.com/model.gguf", "status_code": 404}
        ... )
    """

    code: str
    message: str
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanResult:
    """Canonical response returned from scans.

    The main result object containing the overall verdict, extracted templates,
    security findings from both local heuristics and Pillar API, and any errors.

    Attributes:
        verdict: Overall assessment (CLEAN, SUSPICIOUS, MALICIOUS, or ERROR).
        evidence: Extracted templates, metadata, and computed hashes.
        findings: List of issues detected by local heuristic rules.
        pillar_findings: List of issues detected by Pillar's remote scanning service.
        source: Original source identifier (file path, URL, or repo reference).
        errors: List of non-fatal errors encountered during scanning.

    Example:
        >>> result = scanner.scan("model.gguf")
        >>> if result.verdict == Verdict.MALICIOUS:
        ...     for finding in result.critical_findings:
        ...         print(f"CRITICAL: {finding.message}")
    """

    verdict: Verdict
    evidence: TemplateScanEvidence
    findings: List[TemplateFinding]
    pillar_findings: List[PillarFinding]
    source: str
    errors: List[ErrorDetail] = field(default_factory=list)

    @property
    def suspicious_findings(self) -> Iterable[TemplateFinding]:
        """Return medium or above severity findings from local heuristics.

        Returns:
            Generator of findings with severity >= MEDIUM.
        """

        return (finding for finding in self.findings if finding.severity.score() >= 2)

    @property
    def critical_findings(self) -> Iterable[TemplateFinding]:
        """Return high or critical severity findings from local heuristics.

        Returns:
            Generator of findings with severity >= HIGH.
        """

        threshold = Severity.HIGH.score()
        return (finding for finding in self.findings if finding.severity.score() >= threshold)


@dataclass(frozen=True)
class PatternRule:
    """Heuristic rule for pattern-based detection in chat templates.

    Defines a search pattern that will be matched against extracted templates
    to detect suspicious or malicious content.

    Attributes:
        rule_id: Unique identifier for this rule (e.g., "url_in_template").
        severity: Severity level to assign if this rule matches.
        message: Human-readable description of what this rule detects.
        search_terms: List of strings or patterns to search for in templates.
        case_sensitive: Whether to perform case-sensitive matching. Default is False.

    Example:
        >>> rule = PatternRule(
        ...     rule_id="forbidden_phrase",
        ...     severity=Severity.HIGH,
        ...     message="Template contains forbidden instruction",
        ...     search_terms=["ignore previous instructions", "disregard"],
        ...     case_sensitive=False
        ... )
    """

    rule_id: str
    severity: Severity
    message: str
    search_terms: Iterable[str]
    case_sensitive: bool = False


@dataclass(frozen=True)
class ScannerConfig:
    """Configuration options controlling how scans are executed.

    Attributes:
        request_timeout: Maximum seconds to wait for HTTP requests. Default is 30.0.
        initial_request_size: Initial bytes to fetch when streaming GGUF headers from remote sources.
            Default is 2MB. The scanner will automatically request more data if needed.
        max_request_size: Maximum total bytes to fetch from remote sources to prevent excessive
            memory usage. Default is 8GB.
        heuristic_rules: Custom pattern rules to apply during scanning, or None to use DEFAULT_PATTERNS.
            Use merge_heuristics() to combine custom rules with defaults.
        url_severity: Severity level assigned to findings when URLs are detected in templates.
            Default is MEDIUM.
        base64_severity: Severity level assigned to findings when base64-encoded content is detected.
            Default is MEDIUM.
        pillar_endpoint: API endpoint URL for Pillar's remote scanning service.
            Default is https://api.pillar.security/api/v1/scan/prompt.
        event_handler: Optional callback function for scan telemetry events. Receives event name (str)
            and payload (dict). Built-in events include 'heuristic_match', 'pillar_response',
            'pillar_scan_failed', and 'remote_fetch_failed'.

    Example:
        >>> config = ScannerConfig(
        ...     request_timeout=60.0,
        ...     url_severity=Severity.HIGH,
        ...     event_handler=lambda name, payload: print(f"{name}: {payload}")
        ... )
    """

    request_timeout: float = 30.0
    initial_request_size: int = 2 * 1024 * 1024
    max_request_size: int = 8 * 1024 * 1024 * 1024
    heuristic_rules: Optional[List[PatternRule]] = None
    url_severity: Severity = Severity.MEDIUM
    base64_severity: Severity = Severity.MEDIUM
    pillar_endpoint: str = "https://api.pillar.security/api/v1/scan/prompt"
    event_handler: Optional[Any] = None


@dataclass(frozen=True)
class HuggingFaceRepoRef:
    """Reference to a GGUF file stored on Hugging Face.

    Used to specify a model file in a Hugging Face repository for remote scanning.
    The scanner will fetch the file using Hugging Face's API with range requests
    to minimize bandwidth usage.

    Attributes:
        repo_id: Repository identifier in "owner/repo" format (e.g., "TheBloke/Llama-2-7B-GGUF").
        filename: Name of the GGUF file within the repository (e.g., "llama-2-7b.Q4_K_M.gguf").
        revision: Git revision (branch, tag, or commit hash). Default is "main".
        token: Optional Hugging Face API token for private repositories.

    Example:
        >>> ref = HuggingFaceRepoRef(
        ...     repo_id="TheBloke/Llama-2-7B-GGUF",
        ...     filename="llama-2-7b.Q4_K_M.gguf",
        ...     revision="main"
        ... )
        >>> result = scanner.scan(ref)
    """

    repo_id: str
    filename: str
    revision: str = "main"
    token: Optional[str] = None


def build_template_hashes(default_template: Optional[str], named_templates: Mapping[str, str]) -> Dict[str, str]:
    """Compute SHA-256 hashes for all extracted templates.

    Args:
        default_template: The default chat template string, or None.
        named_templates: Dictionary of named templates.

    Returns:
        Dictionary mapping template identifiers to their SHA-256 hex digests.
        Keys use the format "default" for the default template and "named:<name>"
        for named templates.

    Example:
        >>> hashes = build_template_hashes("<s>[INST]", {"custom": "{{bos_token}}"})
        >>> hashes["default"]
        'a1b2c3...'
        >>> hashes["named:custom"]
        'd4e5f6...'
    """

    hashes: Dict[str, str] = {}
    if default_template is not None:
        hashes["default"] = hashlib.sha256(default_template.encode("utf-8")).hexdigest()
    for name, template in named_templates.items():
        hashes[f"named:{name}"] = hashlib.sha256(template.encode("utf-8")).hexdigest()
    return hashes


def build_template_lengths(default_template: Optional[str], named_templates: Mapping[str, str]) -> Dict[str, int]:
    """Compute character lengths for all extracted templates.

    Args:
        default_template: The default chat template string, or None.
        named_templates: Dictionary of named templates.

    Returns:
        Dictionary mapping template identifiers to their character counts.
        Keys use the format "default" for the default template and "named:<name>"
        for named templates.

    Example:
        >>> lengths = build_template_lengths("hello", {"greet": "hi there"})
        >>> lengths["default"]
        5
        >>> lengths["named:greet"]
        8
    """

    lengths: Dict[str, int] = {}
    if default_template is not None:
        lengths["default"] = len(default_template)
    for name, template in named_templates.items():
        lengths[f"named:{name}"] = len(template)
    return lengths
