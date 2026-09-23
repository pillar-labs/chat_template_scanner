"""Remote GGUF header retrieval helpers built on httpx."""

from __future__ import annotations

import logging
from typing import List, Mapping, MutableMapping, Optional
from urllib.parse import quote

import httpx

from .exceptions import BufferUnderrunError, GGUFParseError, RemoteFetchError
from .models import ScannerConfig
from .reader import parse_chat_templates_from_bytes

HF_BASE_URL = "https://huggingface.co"
HF_API_BASE_URL = "https://huggingface.co/api/models"


logger = logging.getLogger("pillar_gguf_scanner.remote")


def build_huggingface_url(repo_id: str, filename: str, revision: str = "main") -> str:
    """Construct a download URL for a file in a Hugging Face repository.

    Args:
        repo_id: Repository identifier in "owner/repo" format.
        filename: Path to the file within the repository.
        revision: Git revision (branch, tag, or commit hash). Defaults to "main".

    Returns:
        Full HTTPS URL to download the file from Hugging Face's CDN.

    Raises:
        RemoteFetchError: If repo_id is not in "owner/repo" format.
    """

    if not repo_id or "/" not in repo_id:
        raise RemoteFetchError("repo_id must be in the format 'owner/repo'")

    owner, repo = repo_id.split("/", 1)
    owner_quoted = quote(owner, safe="-_.~")
    repo_quoted = quote(repo, safe="-_.~")
    revision_quoted = quote(revision, safe="-_.~")
    filename_quoted = "/".join(quote(part, safe="-_.~/") for part in filename.split("/"))
    return f"{HF_BASE_URL}/{owner_quoted}/{repo_quoted}/resolve/{revision_quoted}/{filename_quoted}"


def _build_headers(
    *,
    range_start: int,
    range_end: int,
    headers: Optional[Mapping[str, str]],
    user_agent: str = "pillar-gguf-scanner/0.1",
) -> MutableMapping[str, str]:
    request_headers: MutableMapping[str, str] = {
        "Range": f"bytes={range_start}-{range_end}",
        "User-Agent": user_agent,
        "Accept": "application/octet-stream",
    }
    if headers:
        request_headers.update(headers)
    return request_headers


def fetch_chat_templates_from_url(
    url: str,
    *,
    client: Optional[httpx.Client] = None,
    headers: Optional[Mapping[str, str]] = None,
    config: Optional[ScannerConfig] = None,
) -> bytes:
    """Fetch GGUF header bytes from a URL using HTTP range requests.

    Downloads only the minimum data needed to extract chat templates,
    using incremental range requests to avoid downloading the entire file.

    Args:
        url: Direct download URL for the GGUF file.
        client: Optional httpx.Client for connection reuse.
        headers: Optional HTTP headers (e.g., for authentication).
        config: Scanner configuration for timeouts and size limits.

    Returns:
        Raw bytes of the GGUF header containing metadata.

    Raises:
        RemoteFetchError: If the file cannot be fetched or doesn't support range requests.
    """

    scanner_config = config or ScannerConfig()
    request_size = scanner_config.initial_request_size
    max_bytes = scanner_config.max_request_size

    close_client = False
    if client is None:
        timeout = httpx.Timeout(scanner_config.request_timeout)
        client = httpx.Client(timeout=timeout, follow_redirects=True)
        close_client = True

    buffer = bytearray()
    range_start = 0

    try:
        while True:
            if range_start >= max_bytes:
                raise RemoteFetchError(f"GGUF header exceeds {max_bytes} bytes; cannot extract chat template")
            range_end = min(range_start + request_size - 1, max_bytes - 1)
            if range_end < range_start:
                raise RemoteFetchError(f"GGUF header exceeds {max_bytes} bytes; cannot extract chat template")
            request_headers = _build_headers(
                range_start=range_start,
                range_end=range_end,
                headers=headers,
            )
            try:
                response = client.get(url, headers=request_headers)
            except httpx.TimeoutException as exc:
                logger.debug("timeout while fetching %s", url)
                raise RemoteFetchError(f"timeout while fetching {url}") from exc
            except httpx.HTTPError as exc:
                logger.debug("transport error while fetching %s: %s", url, exc)
                raise RemoteFetchError(f"http error while fetching {url}: {exc}") from exc

            status_code = response.status_code
            if status_code in (404, 401, 403):
                raise RemoteFetchError(f"failed to fetch GGUF header: HTTP {status_code}")
            if status_code >= 400:
                raise RemoteFetchError(f"unexpected HTTP status {status_code} while fetching {url}")

            payload = response.content
            if not payload:
                raise RemoteFetchError("server returned empty response while fetching GGUF header")

            buffer.extend(payload)
            range_start = len(buffer)

            try:
                parse_chat_templates_from_bytes(buffer)
                return bytes(buffer)
            except BufferUnderrunError as exc:
                required = getattr(exc, "required_bytes", None)
                if required and required > max_bytes:
                    raise RemoteFetchError(
                        f"GGUF header requires {required} bytes; exceeds configured limit of {max_bytes}"
                    ) from exc
                if len(buffer) >= max_bytes:
                    raise RemoteFetchError(
                        f"GGUF header exceeds {max_bytes} bytes; cannot extract chat template"
                    ) from exc
                if required and required > len(buffer):
                    next_bytes = required - len(buffer)
                    request_size = max(request_size, next_bytes)
                else:
                    request_size = max(request_size * 2, request_size + 1)
                remaining = max_bytes - len(buffer)
                request_size = min(request_size, remaining)
                if request_size <= 0:
                    raise RemoteFetchError(
                        f"GGUF header exceeds {max_bytes} bytes; cannot extract chat template"
                    ) from exc
                continue
            except GGUFParseError as exc:
                raise RemoteFetchError(f"failed to parse GGUF header: {exc}") from exc
    finally:
        if close_client:
            client.close()


async def afetch_chat_templates_from_url(
    url: str,
    *,
    client: Optional[httpx.AsyncClient] = None,
    headers: Optional[Mapping[str, str]] = None,
    config: Optional[ScannerConfig] = None,
) -> bytes:
    """Fetch the GGUF header bytes asynchronously."""

    scanner_config = config or ScannerConfig()
    request_size = scanner_config.initial_request_size
    max_bytes = scanner_config.max_request_size

    close_client = False
    if client is None:
        timeout = httpx.Timeout(scanner_config.request_timeout)
        client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        close_client = True

    buffer = bytearray()
    range_start = 0

    try:
        while True:
            if range_start >= max_bytes:
                raise RemoteFetchError(f"GGUF header exceeds {max_bytes} bytes; cannot extract chat template")
            range_end = min(range_start + request_size - 1, max_bytes - 1)
            if range_end < range_start:
                raise RemoteFetchError(f"GGUF header exceeds {max_bytes} bytes; cannot extract chat template")
            request_headers = _build_headers(
                range_start=range_start,
                range_end=range_end,
                headers=headers,
            )
            try:
                response = await client.get(url, headers=request_headers)
            except httpx.TimeoutException as exc:
                logger.debug("timeout while fetching %s", url)
                raise RemoteFetchError(f"timeout while fetching {url}") from exc
            except httpx.HTTPError as exc:
                logger.debug("transport error while fetching %s: %s", url, exc)
                raise RemoteFetchError(f"http error while fetching {url}: {exc}") from exc

            status_code = response.status_code
            if status_code in (404, 401, 403):
                raise RemoteFetchError(f"failed to fetch GGUF header: HTTP {status_code}")
            if status_code >= 400:
                raise RemoteFetchError(f"unexpected HTTP status {status_code} while fetching {url}")

            payload = response.content
            if not payload:
                raise RemoteFetchError("server returned empty response while fetching GGUF header")

            buffer.extend(payload)
            range_start = len(buffer)

            try:
                parse_chat_templates_from_bytes(buffer)
                return bytes(buffer)
            except BufferUnderrunError as exc:
                required = getattr(exc, "required_bytes", None)
                if required and required > max_bytes:
                    raise RemoteFetchError(
                        f"GGUF header requires {required} bytes; exceeds configured limit of {max_bytes}"
                    ) from exc
                if len(buffer) >= max_bytes:
                    raise RemoteFetchError(
                        f"GGUF header exceeds {max_bytes} bytes; cannot extract chat template"
                    ) from exc
                if required and required > len(buffer):
                    next_bytes = required - len(buffer)
                    request_size = max(request_size, next_bytes)
                else:
                    request_size = max(request_size * 2, request_size + 1)
                remaining = max_bytes - len(buffer)
                request_size = min(request_size, remaining)
                if request_size <= 0:
                    raise RemoteFetchError(
                        f"GGUF header exceeds {max_bytes} bytes; cannot extract chat template"
                    ) from exc
                continue
            except GGUFParseError as exc:
                raise RemoteFetchError(f"failed to parse GGUF header: {exc}") from exc
    finally:
        if close_client:
            await client.aclose()


def fetch_chat_templates_from_huggingface(
    repo_id: str,
    filename: str,
    *,
    revision: str = "main",
    token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    config: Optional[ScannerConfig] = None,
) -> bytes:
    """Convenience wrapper to fetch GGUF template headers from Hugging Face."""

    url = build_huggingface_url(repo_id, filename, revision)
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return fetch_chat_templates_from_url(url, client=client, headers=headers, config=config)


async def afetch_chat_templates_from_huggingface(
    repo_id: str,
    filename: str,
    *,
    revision: str = "main",
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    config: Optional[ScannerConfig] = None,
) -> bytes:
    """Asynchronous convenience wrapper for Hugging Face."""

    url = build_huggingface_url(repo_id, filename, revision)
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return await afetch_chat_templates_from_url(
        url,
        client=client,
        headers=headers,
        config=config,
    )


def _validate_repo_id(repo_id: str) -> tuple[str, str]:
    """Split and validate a Hugging Face repo_id, returning quoted (owner, repo)."""

    if not repo_id or "/" not in repo_id:
        raise RemoteFetchError("repo_id must be in the format 'owner/repo'")
    owner, repo = repo_id.split("/", 1)
    if not owner or not repo or "/" in repo:
        raise RemoteFetchError("repo_id must be in the format 'owner/repo'")
    return quote(owner, safe="-_.~"), quote(repo, safe="-_.~")


def build_huggingface_tree_url(repo_id: str, revision: str = "main") -> str:
    """Construct the API URL listing all files in a Hugging Face repository.

    Args:
        repo_id: Repository identifier in "owner/repo" format.
        revision: Git revision (branch, tag, or commit hash). Defaults to "main".

    Returns:
        Full HTTPS URL for the recursive file-tree API endpoint.

    Raises:
        RemoteFetchError: If repo_id is not in "owner/repo" format.
    """

    owner_quoted, repo_quoted = _validate_repo_id(repo_id)
    revision_quoted = quote(revision, safe="-_.~")
    return f"{HF_API_BASE_URL}/{owner_quoted}/{repo_quoted}/tree/{revision_quoted}?recursive=True"


def _repo_tree_headers(token: Optional[str]) -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _parse_repo_tree_entries(payload: object, *, repo_id: str, revision: str) -> List[str]:
    if not isinstance(payload, list):
        raise RemoteFetchError(
            f"unexpected response while listing huggingface:{repo_id}@{revision}: expected a JSON list"
        )
    paths: List[str] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") not in (None, "file"):
            continue
        path = entry.get("path")
        if isinstance(path, str) and path:
            paths.append(path)
    return paths


def list_huggingface_repo_files(
    repo_id: str,
    *,
    revision: str = "main",
    token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    config: Optional[ScannerConfig] = None,
) -> List[str]:
    """List all file paths in a Hugging Face repository at a given revision.

    Args:
        repo_id: Repository identifier in "owner/repo" format.
        revision: Git revision (branch, tag, or commit hash). Defaults to "main".
        token: Optional Hugging Face API token for private repositories.
        client: Optional httpx.Client for connection reuse.
        config: Scanner configuration for timeouts.

    Returns:
        Sorted list of file paths within the repository.

    Raises:
        RemoteFetchError: If the repository cannot be listed.
    """

    scanner_config = config or ScannerConfig()
    url = build_huggingface_tree_url(repo_id, revision)

    close_client = False
    if client is None:
        timeout = httpx.Timeout(scanner_config.request_timeout)
        client = httpx.Client(timeout=timeout, follow_redirects=True)
        close_client = True

    try:
        try:
            response = client.get(url, headers=_repo_tree_headers(token))
        except httpx.TimeoutException as exc:
            raise RemoteFetchError(f"timeout while listing huggingface:{repo_id}@{revision}") from exc
        except httpx.HTTPError as exc:
            raise RemoteFetchError(f"http error while listing huggingface:{repo_id}@{revision}: {exc}") from exc

        status_code = response.status_code
        if status_code in (404, 401, 403):
            raise RemoteFetchError(f"failed to list repository {repo_id}@{revision}: HTTP {status_code}")
        if status_code >= 400:
            raise RemoteFetchError(
                f"unexpected HTTP status {status_code} while listing repository {repo_id}@{revision}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise RemoteFetchError(f"invalid JSON while listing repository {repo_id}@{revision}") from exc
        return sorted(_parse_repo_tree_entries(payload, repo_id=repo_id, revision=revision))
    finally:
        if close_client:
            client.close()


async def alist_huggingface_repo_files(
    repo_id: str,
    *,
    revision: str = "main",
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    config: Optional[ScannerConfig] = None,
) -> List[str]:
    """Asynchronous variant of list_huggingface_repo_files."""

    scanner_config = config or ScannerConfig()
    url = build_huggingface_tree_url(repo_id, revision)

    close_client = False
    if client is None:
        timeout = httpx.Timeout(scanner_config.request_timeout)
        client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        close_client = True

    try:
        try:
            response = await client.get(url, headers=_repo_tree_headers(token))
        except httpx.TimeoutException as exc:
            raise RemoteFetchError(f"timeout while listing huggingface:{repo_id}@{revision}") from exc
        except httpx.HTTPError as exc:
            raise RemoteFetchError(f"http error while listing huggingface:{repo_id}@{revision}: {exc}") from exc

        status_code = response.status_code
        if status_code in (404, 401, 403):
            raise RemoteFetchError(f"failed to list repository {repo_id}@{revision}: HTTP {status_code}")
        if status_code >= 400:
            raise RemoteFetchError(
                f"unexpected HTTP status {status_code} while listing repository {repo_id}@{revision}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise RemoteFetchError(f"invalid JSON while listing repository {repo_id}@{revision}") from exc
        return sorted(_parse_repo_tree_entries(payload, repo_id=repo_id, revision=revision))
    finally:
        if close_client:
            await client.aclose()


def list_huggingface_gguf_files(
    repo_id: str,
    *,
    revision: str = "main",
    token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    config: Optional[ScannerConfig] = None,
) -> List[str]:
    """List GGUF file paths in a Hugging Face repository.

    Convenience wrapper over list_huggingface_repo_files that keeps only
    paths ending in ``.gguf`` (case-insensitive).
    """

    return [
        path
        for path in list_huggingface_repo_files(
            repo_id, revision=revision, token=token, client=client, config=config
        )
        if path.lower().endswith(".gguf")
    ]


async def alist_huggingface_gguf_files(
    repo_id: str,
    *,
    revision: str = "main",
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    config: Optional[ScannerConfig] = None,
) -> List[str]:
    """Asynchronous variant of list_huggingface_gguf_files."""

    return [
        path
        for path in await alist_huggingface_repo_files(
            repo_id, revision=revision, token=token, client=client, config=config
        )
        if path.lower().endswith(".gguf")
    ]
