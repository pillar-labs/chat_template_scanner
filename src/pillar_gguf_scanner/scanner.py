"""High level scanner API that orchestrates template extraction and analysis."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import AsyncIterator, Iterator, List, Mapping, Optional, Type, Union
from urllib.parse import urlparse

import httpx

from .exceptions import (
    BufferUnderrunError,
    ChatTemplateExtractionError,
    GGUFParseError,
    RemoteFetchError,
)
from .heuristics import run_heuristics
from .models import (
    ErrorDetail,
    HuggingFaceRepoRef,
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
from .pillar_client import PillarClient
from .reader import ChatTemplateExtraction, parse_chat_templates_from_bytes, read_metadata_from_file
from .remote import (
    afetch_chat_templates_from_huggingface,
    afetch_chat_templates_from_url,
    fetch_chat_templates_from_huggingface,
    fetch_chat_templates_from_url,
)

PathLike = Union[str, Path]


logger = logging.getLogger("pillar_gguf_scanner.scanner")


def _error_detail(code: str, message: str, *, context: Optional[Mapping[str, object]] = None) -> ErrorDetail:
    ctx = dict(context or {})
    return ErrorDetail(code=code, message=message, context=ctx)


def _determine_verdict(
    findings: List[TemplateFinding],
    pillar_findings: List[PillarFinding],
    errors: List[ErrorDetail],
) -> Verdict:
    if errors:
        return Verdict.ERROR

    highest_score = 0
    for finding in findings:
        highest_score = max(highest_score, finding.severity.score())
    for pillar_finding in pillar_findings:
        highest_score = max(highest_score, pillar_finding.severity.score())

    if highest_score >= Severity.HIGH.score():
        return Verdict.MALICIOUS
    if highest_score >= Severity.MEDIUM.score():
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def _build_evidence(extraction: ChatTemplateExtraction) -> TemplateScanEvidence:
    hashes = build_template_hashes(extraction.default_template, extraction.named_templates)
    lengths = build_template_lengths(extraction.default_template, extraction.named_templates)
    return TemplateScanEvidence(
        default_template=extraction.default_template,
        named_templates=dict(extraction.named_templates),
        metadata_keys=dict(extraction.metadata_keys),
        template_hashes=hashes,
        template_lengths=lengths,
    )


@dataclass
class _ScanContext:
    source: str
    extraction: ChatTemplateExtraction
    evidence: TemplateScanEvidence


def _close_async_client(client: httpx.AsyncClient) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(client.aclose())
    else:  # pragma: no cover - depends on embedding environment
        loop.create_task(client.aclose())


class GGUFTemplateScanner:
    """Main entry point for scanning GGUF chat templates.

    Provides methods for scanning GGUF model files from local paths, URLs, or
    Hugging Face repositories. Extracts embedded chat templates and runs both
    local heuristics and optional remote Pillar API scanning.

    The scanner supports both synchronous and asynchronous operations, with
    automatic HTTP client management through context managers.

    Args:
        pillar_api_key: Optional API key for Pillar's remote scanning service.
            If provided, enables deep ML-based threat detection.
        config: Scanner configuration controlling timeouts, heuristic rules,
            and severity levels. Defaults to ScannerConfig() if not provided.
        http_client: Optional httpx.Client for synchronous HTTP requests.
            If not provided, internal clients will be created as needed.
        async_http_client: Optional httpx.AsyncClient for async operations.
            Use scanner_session() or ascanner_session() to share clients across scans.

    Example:
        >>> scanner = GGUFTemplateScanner()
        >>> result = scanner.scan("model.gguf")
        >>> print(result.verdict)
        Verdict.CLEAN

        >>> # With Pillar API for advanced detection
        >>> scanner = GGUFTemplateScanner(pillar_api_key="your-key")
        >>> result = scanner.scan("model.gguf", use_pillar=True)

        >>> # Scan from Hugging Face
        >>> from pillar_gguf_scanner import HuggingFaceRepoRef
        >>> ref = HuggingFaceRepoRef("TheBloke/Llama-2-7B-GGUF", "llama-2-7b.gguf")
        >>> result = scanner.scan(ref)
    """

    def __init__(
        self,
        *,
        pillar_api_key: Optional[str] = None,
        config: Optional[ScannerConfig] = None,
        http_client: Optional[httpx.Client] = None,
        async_http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self._config = config or ScannerConfig()
        self._http_client = http_client
        self._async_client = async_http_client
        self._pillar_client: Optional[PillarClient] = None
        if pillar_api_key:
            self._pillar_client = PillarClient(
                pillar_api_key,
                client=http_client,
                async_client=async_http_client,
                config=self._config,
            )

    def _empty_evidence(self) -> TemplateScanEvidence:
        return TemplateScanEvidence(
            default_template=None,
            named_templates={},
            metadata_keys={},
            template_hashes={},
            template_lengths={},
        )

    def _error_scan_result(
        self,
        *,
        source: str,
        code: str,
        message: str,
        context: Optional[Mapping[str, object]] = None,
        evidence: Optional[TemplateScanEvidence] = None,
    ) -> ScanResult:
        detail = _error_detail(code, message, context=context)
        return ScanResult(
            verdict=Verdict.ERROR,
            evidence=evidence or self._empty_evidence(),
            findings=[],
            pillar_findings=[],
            source=source,
            errors=[detail],
        )

    def _ensure_local_path(self, path: PathLike) -> Path:
        resolved = Path(path).expanduser().resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"file not found: {resolved}")
        if not resolved.is_file():
            raise IsADirectoryError(f"expected file path, got directory: {resolved}")
        if resolved.suffix.lower() != ".gguf":
            raise ValueError("path must end with .gguf")
        return resolved

    def _scan_extraction(
        self,
        *,
        source: str,
        extraction: ChatTemplateExtraction,
        use_pillar: Optional[bool],
    ) -> ScanResult:
        evidence = _build_evidence(extraction)

        findings = run_heuristics(
            default_template=evidence.default_template,
            named_templates=evidence.named_templates,
            config=self._config,
        )

        pillar_findings: List[PillarFinding] = []
        errors: List[ErrorDetail] = []

        if use_pillar is None:
            use_pillar = self._pillar_client is not None

        if use_pillar and self._pillar_client:
            templates_to_scan: List[str] = []
            if evidence.default_template:
                templates_to_scan.append(evidence.default_template)
            templates_to_scan.extend(evidence.named_templates.values())

            for template in templates_to_scan:
                try:
                    pillar_findings.extend(self._pillar_client.scan(template))
                except Exception as exc:  # pragma: no cover - network failures are rare in tests
                    detail = _error_detail(
                        "pillar_scan_failed",
                        f"Pillar scanning failed: {exc}",
                        context={"template_length": len(template)},
                    )
                    errors.append(detail)

        verdict = _determine_verdict(findings, pillar_findings, errors)

        return ScanResult(
            verdict=verdict,
            evidence=evidence,
            findings=findings,
            pillar_findings=pillar_findings,
            source=source,
            errors=errors,
        )

    def scan_path(
        self,
        path: PathLike,
        *,
        use_pillar: Optional[bool] = None,
        chunk_size: Optional[int] = None,
        max_bytes: Optional[int] = None,
    ) -> ScanResult:
        """Scan a local GGUF file from the filesystem.

        Args:
            path: Path to the .gguf file. Must exist and have a .gguf extension.
            use_pillar: Whether to invoke Pillar API for remote scanning. If None,
                uses Pillar only if an API key was provided at scanner initialization.
            chunk_size: Bytes to read per chunk when parsing the file. Defaults to
                config.initial_request_size (2MB).
            max_bytes: Maximum total bytes to read. Defaults to config.max_request_size (8GB).

        Returns:
            ScanResult containing verdict, findings, extracted templates, and any errors.

        Example:
            >>> scanner = GGUFTemplateScanner()
            >>> result = scanner.scan_path("models/llama-2-7b.gguf")
            >>> if result.verdict == Verdict.MALICIOUS:
            ...     print("Malicious template detected!")
        """

        try:
            resolved = self._ensure_local_path(path)
        except (FileNotFoundError, IsADirectoryError, ValueError) as exc:
            return self._error_scan_result(
                source=str(path),
                code="invalid_path",
                message=str(exc),
                context={"path": str(path)},
            )
        try:
            extraction = read_metadata_from_file(
                resolved,
                chunk_size=chunk_size or self._config.initial_request_size,
                max_bytes=max_bytes or self._config.max_request_size,
            )
        except (
            BufferUnderrunError,
            ChatTemplateExtractionError,
            ValueError,
            GGUFParseError,
        ) as exc:
            return self._error_scan_result(
                source=str(resolved),
                code="gguf_parse_error",
                message=str(exc),
                context={"path": str(resolved)},
            )
        except OSError as exc:
            return self._error_scan_result(
                source=str(resolved),
                code="io_error",
                message=str(exc),
                context={"path": str(resolved)},
            )
        return self._scan_extraction(
            source=str(resolved),
            extraction=extraction,
            use_pillar=use_pillar,
        )

    def scan(
        self,
        source: Union[PathLike, HuggingFaceRepoRef],
        *,
        use_pillar: Optional[bool] = None,
        chunk_size: Optional[int] = None,
        max_bytes: Optional[int] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> ScanResult:
        """Unified scan method that accepts paths, URLs, or Hugging Face references.

        Automatically detects the source type and dispatches to the appropriate
        specialized scan method (scan_path, scan_url, or scan_huggingface).

        Args:
            source: Can be:
                - Local file path (str or Path): "models/model.gguf"
                - HTTP/HTTPS URL: "https://example.com/model.gguf"
                - HuggingFaceRepoRef: Reference to a file in a Hugging Face repository
            use_pillar: Whether to use Pillar API. Defaults to True if API key provided.
            chunk_size: Bytes per chunk for local files (ignored for URLs).
            max_bytes: Maximum bytes to read (ignored for URLs).
            headers: Optional HTTP headers for URL requests (ignored for local paths).

        Returns:
            ScanResult with verdict, findings, and extracted templates.

        Raises:
            TypeError: If source is not a valid type.

        Example:
            >>> scanner = GGUFTemplateScanner()
            >>> # Local file
            >>> result = scanner.scan("model.gguf")
            >>> # URL
            >>> result = scanner.scan("https://example.com/model.gguf")
            >>> # Hugging Face
            >>> ref = HuggingFaceRepoRef("owner/repo", "model.gguf")
            >>> result = scanner.scan(ref)
        """

        if isinstance(source, HuggingFaceRepoRef):
            return self.scan_huggingface(
                source.repo_id,
                source.filename,
                revision=source.revision,
                token=source.token,
                use_pillar=use_pillar,
            )

        if isinstance(source, (str, Path)):
            parsed = urlparse(str(source))
            if parsed.scheme in {"http", "https"}:
                return self.scan_url(
                    str(source),
                    headers=headers,
                    use_pillar=use_pillar,
                )
            return self.scan_path(
                source,
                use_pillar=use_pillar,
                chunk_size=chunk_size,
                max_bytes=max_bytes,
            )

        raise TypeError("source must be a filesystem path, URL string, or HuggingFaceRepoRef")

    def scan_url(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        use_pillar: Optional[bool] = None,
    ) -> ScanResult:
        """Scan a GGUF file from a direct download URL.

        Uses HTTP range requests to fetch only the GGUF header containing
        chat template metadata, minimizing bandwidth usage.

        Args:
            url: Direct download URL for the GGUF file (must start with http:// or https://).
            headers: Optional HTTP headers to include in the request (e.g., authentication).
            use_pillar: Whether to use Pillar API. Defaults to True if API key provided.

        Returns:
            ScanResult with verdict, findings, and extracted templates.

        Example:
            >>> scanner = GGUFTemplateScanner()
            >>> result = scanner.scan_url("https://example.com/model.gguf")
        """

        try:
            payload = fetch_chat_templates_from_url(
                url,
                headers=headers,
                client=self._http_client,
                config=self._config,
            )
        except RemoteFetchError as exc:
            return self._error_scan_result(
                source=url,
                code="remote_fetch_error",
                message=str(exc),
                context={"url": url},
            )

        try:
            extraction = parse_chat_templates_from_bytes(payload)
        except GGUFParseError as exc:
            return self._error_scan_result(
                source=url,
                code="gguf_parse_error",
                message=str(exc),
                context={"url": url},
            )
        return self._scan_extraction(
            source=url,
            extraction=extraction,
            use_pillar=use_pillar,
        )

    def scan_huggingface(
        self,
        repo_id: str,
        filename: str,
        *,
        revision: str = "main",
        token: Optional[str] = None,
        use_pillar: Optional[bool] = None,
    ) -> ScanResult:
        """Scan a GGUF file from a Hugging Face repository.

        Uses Hugging Face's API with range requests to fetch only the necessary
        header data from the model file.

        Args:
            repo_id: Repository identifier in "owner/repo" format (e.g., "TheBloke/Llama-2-7B-GGUF").
            filename: Name of the GGUF file in the repository (e.g., "llama-2-7b.Q4_K_M.gguf").
            revision: Git revision (branch, tag, or commit hash). Defaults to "main".
            token: Optional Hugging Face API token for accessing private repositories.
            use_pillar: Whether to use Pillar API. Defaults to True if API key provided.

        Returns:
            ScanResult with verdict, findings, and extracted templates.

        Example:
            >>> scanner = GGUFTemplateScanner()
            >>> result = scanner.scan_huggingface(
            ...     "TheBloke/Llama-2-7B-GGUF",
            ...     "llama-2-7b.Q4_K_M.gguf"
            ... )
        """

        try:
            payload = fetch_chat_templates_from_huggingface(
                repo_id,
                filename,
                revision=revision,
                token=token,
                client=self._http_client,
                config=self._config,
            )
        except RemoteFetchError as exc:
            source = f"huggingface:{repo_id}/{filename}@{revision}"
            return self._error_scan_result(
                source=source,
                code="remote_fetch_error",
                message=str(exc),
                context={
                    "repo_id": repo_id,
                    "filename": filename,
                    "revision": revision,
                },
            )

        try:
            extraction = parse_chat_templates_from_bytes(payload)
        except GGUFParseError as exc:
            source = f"huggingface:{repo_id}/{filename}@{revision}"
            return self._error_scan_result(
                source=source,
                code="gguf_parse_error",
                message=str(exc),
                context={
                    "repo_id": repo_id,
                    "filename": filename,
                    "revision": revision,
                },
            )
        return self._scan_extraction(
            source=f"huggingface:{repo_id}/{filename}@{revision}",
            extraction=extraction,
            use_pillar=use_pillar,
        )

    async def ascan_url(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        use_pillar: Optional[bool] = None,
    ) -> ScanResult:
        """Asynchronous variant of scan_url.

        Args:
            url: Direct download URL for the GGUF file.
            headers: Optional HTTP headers.
            use_pillar: Whether to use Pillar API.

        Returns:
            ScanResult with verdict and findings.

        Example:
            >>> scanner = GGUFTemplateScanner()
            >>> result = await scanner.ascan_url("https://example.com/model.gguf")
        """

        try:
            payload = await afetch_chat_templates_from_url(
                url,
                headers=headers,
                client=self._async_client,
                config=self._config,
            )
        except RemoteFetchError as exc:
            return self._error_scan_result(
                source=url,
                code="remote_fetch_error",
                message=str(exc),
                context={"url": url},
            )

        try:
            extraction = parse_chat_templates_from_bytes(payload)
        except GGUFParseError as exc:
            return self._error_scan_result(
                source=url,
                code="gguf_parse_error",
                message=str(exc),
                context={"url": url},
            )
        return self._scan_extraction(
            source=url,
            extraction=extraction,
            use_pillar=use_pillar,
        )

    async def ascan_huggingface(
        self,
        repo_id: str,
        filename: str,
        *,
        revision: str = "main",
        token: Optional[str] = None,
        use_pillar: Optional[bool] = None,
    ) -> ScanResult:
        """Asynchronous variant of scan_huggingface.

        Args:
            repo_id: Repository identifier (e.g., "TheBloke/Llama-2-7B-GGUF").
            filename: GGUF filename in the repository.
            revision: Git revision. Defaults to "main".
            token: Optional Hugging Face API token.
            use_pillar: Whether to use Pillar API.

        Returns:
            ScanResult with verdict and findings.

        Example:
            >>> scanner = GGUFTemplateScanner()
            >>> result = await scanner.ascan_huggingface("owner/repo", "model.gguf")
        """

        try:
            payload = await afetch_chat_templates_from_huggingface(
                repo_id,
                filename,
                revision=revision,
                token=token,
                client=self._async_client,
                config=self._config,
            )
        except RemoteFetchError as exc:
            source = f"huggingface:{repo_id}/{filename}@{revision}"
            return self._error_scan_result(
                source=source,
                code="remote_fetch_error",
                message=str(exc),
                context={
                    "repo_id": repo_id,
                    "filename": filename,
                    "revision": revision,
                },
            )

        try:
            extraction = parse_chat_templates_from_bytes(payload)
        except GGUFParseError as exc:
            source = f"huggingface:{repo_id}/{filename}@{revision}"
            return self._error_scan_result(
                source=source,
                code="gguf_parse_error",
                message=str(exc),
                context={
                    "repo_id": repo_id,
                    "filename": filename,
                    "revision": revision,
                },
            )
        return self._scan_extraction(
            source=f"huggingface:{repo_id}/{filename}@{revision}",
            extraction=extraction,
            use_pillar=use_pillar,
        )

    async def ascan_path(
        self,
        path: PathLike,
        *,
        use_pillar: Optional[bool] = None,
        chunk_size: Optional[int] = None,
        max_bytes: Optional[int] = None,
    ) -> ScanResult:
        """Asynchronous variant of scan_path that offloads file I/O to a thread pool.

        Args:
            path: Path to the local .gguf file.
            use_pillar: Whether to use Pillar API.
            chunk_size: Bytes per read chunk. Defaults to config.initial_request_size.
            max_bytes: Maximum total bytes to read. Defaults to config.max_request_size.

        Returns:
            ScanResult with verdict and findings.

        Example:
            >>> scanner = GGUFTemplateScanner()
            >>> result = await scanner.ascan_path("model.gguf")
        """

        try:
            resolved = self._ensure_local_path(path)
        except (FileNotFoundError, IsADirectoryError, ValueError) as exc:
            return self._error_scan_result(
                source=str(path),
                code="invalid_path",
                message=str(exc),
                context={"path": str(path)},
            )

        loop = asyncio.get_running_loop()

        try:
            extraction = await loop.run_in_executor(
                None,
                lambda: read_metadata_from_file(
                    resolved,
                    chunk_size=chunk_size or self._config.initial_request_size,
                    max_bytes=max_bytes or self._config.max_request_size,
                ),
            )
        except (
            BufferUnderrunError,
            ChatTemplateExtractionError,
            ValueError,
            GGUFParseError,
        ) as exc:
            return self._error_scan_result(
                source=str(resolved),
                code="gguf_parse_error",
                message=str(exc),
                context={"path": str(resolved)},
            )
        except OSError as exc:
            return self._error_scan_result(
                source=str(resolved),
                code="io_error",
                message=str(exc),
                context={"path": str(resolved)},
            )
        return self._scan_extraction(
            source=str(resolved),
            extraction=extraction,
            use_pillar=use_pillar,
        )

    def close(self) -> None:
        """Close any internally managed HTTP clients.

        Note: Currently a no-op as the scanner doesn't create its own persistent clients.
        Use scanner_session() to automatically manage client lifecycle.
        """

        # Currently the scanner does not create persistent clients on its own, so this is a no-op.
        return

    async def aclose(self) -> None:
        """Async variant of close for managed HTTP clients.

        Note: Currently a no-op. Use ascanner_session() for automatic client management.
        """

        return

    def __enter__(self) -> "GGUFTemplateScanner":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> bool | None:  # noqa: D401 - context manager protocol
        self.close()
        return None

    async def __aenter__(self) -> "GGUFTemplateScanner":
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> bool | None:
        await self.aclose()
        return None


@contextmanager
def scanner_session(
    *,
    pillar_api_key: Optional[str] = None,
    config: Optional[ScannerConfig] = None,
) -> Iterator[GGUFTemplateScanner]:
    """Context manager that creates a scanner with shared HTTP clients for efficient batch scanning.

    Reuses HTTP connections across multiple scans, improving performance when
    scanning many files. Automatically closes clients on exit.

    Args:
        pillar_api_key: Optional API key for Pillar's remote scanning service.
        config: Scanner configuration. Defaults to ScannerConfig().

    Yields:
        GGUFTemplateScanner instance with managed HTTP clients.

    Example:
        >>> with scanner_session(pillar_api_key="your-key") as scanner:
        ...     for path in model_paths:
        ...         result = scanner.scan(path)
        ...         print(f"{path}: {result.verdict}")
    """

    cfg = config or ScannerConfig()
    timeout = httpx.Timeout(cfg.request_timeout)
    client = httpx.Client(timeout=timeout)
    async_client = httpx.AsyncClient(timeout=timeout)
    scanner = GGUFTemplateScanner(
        pillar_api_key=pillar_api_key,
        config=cfg,
        http_client=client,
        async_http_client=async_client,
    )
    try:
        yield scanner
    finally:
        client.close()
        _close_async_client(async_client)


@asynccontextmanager
async def ascanner_session(
    *,
    pillar_api_key: Optional[str] = None,
    config: Optional[ScannerConfig] = None,
) -> AsyncIterator[GGUFTemplateScanner]:
    """Async context manager for batch scanning with shared HTTP clients.

    Async variant of scanner_session() that properly manages async HTTP clients
    for concurrent scanning operations.

    Args:
        pillar_api_key: Optional API key for Pillar's remote scanning service.
        config: Scanner configuration. Defaults to ScannerConfig().

    Yields:
        GGUFTemplateScanner instance with managed HTTP clients.

    Example:
        >>> async with ascanner_session() as scanner:
        ...     tasks = [scanner.ascan_url(url) for url in urls]
        ...     results = await asyncio.gather(*tasks)
        ...     for result in results:
        ...         print(result.verdict)
    """

    cfg = config or ScannerConfig()
    timeout = httpx.Timeout(cfg.request_timeout)
    client = httpx.Client(timeout=timeout)
    async_client = httpx.AsyncClient(timeout=timeout)
    scanner = GGUFTemplateScanner(
        pillar_api_key=pillar_api_key,
        config=cfg,
        http_client=client,
        async_http_client=async_client,
    )
    try:
        yield scanner
    finally:
        client.close()
        await async_client.aclose()
