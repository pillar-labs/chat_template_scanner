"""Command-line interface for pillar_gguf_scanner."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Dict, List, TextIO
from urllib.parse import urlparse

from rich.console import Console
from rich.text import Text

from .models import ScannerConfig, ScanResult, Severity, Verdict
from .scanner import GGUFTemplateScanner


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pillar-gguf-scanner",
        description="Scan GGUF files for suspicious chat templates.",
    )
    parser.add_argument(
        "source",
        nargs="?",
        help="Path or URL to a GGUF file. Omit when using --hf-repo.",
    )
    parser.add_argument(
        "--pillar-api-key",
        help="Optional Pillar API key for remote scanning",
        default=None,
    )
    parser.add_argument(
        "--no-pillar",
        help="Disable remote Pillar scanning even if an API key is provided",
        action="store_true",
    )
    parser.add_argument(
        "--json",
        help="Emit raw JSON instead of a human-readable summary",
        action="store_true",
    )
    parser.add_argument(
        "--no-color",
        help="Disable colored output (only applies to human-readable format)",
        action="store_true",
    )
    parser.add_argument(
        "--url-severity",
        choices=[severity.name.lower() for severity in Severity],
        help="Override severity assigned to URL findings",
    )
    parser.add_argument(
        "--base64-severity",
        choices=[severity.name.lower() for severity in Severity],
        help="Override severity assigned to base64 payload findings",
    )
    parser.add_argument(
        "--initial-request-size",
        type=int,
        help="Initial byte range to request when fetching remote GGUF files (in bytes)",
    )
    parser.add_argument(
        "--max-request-size",
        type=int,
        help="Maximum header bytes to fetch when extracting remote templates (in bytes)",
    )
    parser.add_argument(
        "--hf-repo",
        help="Hugging Face repository in the form owner/repo. "
        "Without --hf-filename, every GGUF file in the repo is scanned.",
    )
    parser.add_argument(
        "--hf-filename",
        help="Single filename within the Hugging Face repository. Requires --hf-repo. "
        "Omit to scan all GGUF files in the repo.",
    )
    parser.add_argument(
        "--hf-revision",
        help="Revision to fetch from Hugging Face (default: main). Requires --hf-repo.",
        default=None,
    )
    parser.add_argument(
        "--hf-token",
        help="Optional Hugging Face token used for private artifacts",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=8,
        help="Maximum repo files to scan concurrently (default: 8). Only applies to whole-repo scans.",
    )
    return parser


def _severity_from_name(name: str) -> Severity:
    return Severity[name.upper()]


def _env_int(name: str) -> int | None:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer") from exc


def _build_config(args: argparse.Namespace) -> ScannerConfig:
    config_kwargs: Dict[str, Any] = {}
    if args.url_severity:
        config_kwargs["url_severity"] = _severity_from_name(args.url_severity)
    if args.base64_severity:
        config_kwargs["base64_severity"] = _severity_from_name(args.base64_severity)
    initial_size = args.initial_request_size or _env_int("GGUF_SCANNER_INITIAL_REQUEST_SIZE")
    max_size = args.max_request_size or _env_int("GGUF_SCANNER_MAX_REQUEST_SIZE")
    if initial_size:
        config_kwargs["initial_request_size"] = initial_size
    if max_size:
        config_kwargs["max_request_size"] = max_size
    if initial_size and max_size and initial_size > max_size:
        raise SystemExit("--initial-request-size cannot exceed --max-request-size")
    if not config_kwargs:
        return ScannerConfig()
    return ScannerConfig(**config_kwargs)


def _get_severity_color(severity: Severity) -> str:
    """Get Rich color for a given severity level."""
    if severity == Severity.CRITICAL:
        return "bold red"
    elif severity == Severity.HIGH:
        return "red"
    elif severity == Severity.MEDIUM:
        return "yellow"
    elif severity == Severity.LOW:
        return "blue"
    else:
        return "dim"


def _get_verdict_color(verdict: Verdict) -> str:
    """Get Rich color for a given verdict."""
    if verdict == Verdict.CLEAN:
        return "bold green"
    elif verdict == Verdict.SUSPICIOUS:
        return "yellow"
    elif verdict == Verdict.MALICIOUS:
        return "bold red"
    else:
        return "white"


def _print_human_summary(result: ScanResult, *, stream: TextIO, no_color: bool = False) -> int:
    stream_is_tty = bool(getattr(stream, "isatty", lambda: False)())
    use_color = stream_is_tty and not no_color
    console = Console(
        file=stream,
        force_terminal=use_color,
        no_color=not use_color,
    )

    console.print(f"[bold]Source:[/bold] {result.source}")

    verdict_color = _get_verdict_color(result.verdict)
    console.print(f"[bold]Verdict:[/bold] [{verdict_color}]{result.verdict.value}[/{verdict_color}]")

    if result.errors:
        console.print("[bold red]Errors:[/bold red]")
        for error in result.errors:
            console.print(f"  [red]•[/red] {error}")

    if result.findings:
        console.print("[bold]Findings:[/bold]")
        for finding in result.findings:
            severity_color = _get_severity_color(finding.severity)
            line = Text("  • ")
            severity_label = f"[{finding.severity.value}] "
            if use_color:
                line.stylize(severity_color, 0, len(line))
                line.append(severity_label, style=severity_color)
                line.append(f"{finding.rule_id}", style="cyan")
                line.append(f" ({finding.template_name})", style="dim")
            else:
                line.append(severity_label)
                line.append(f"{finding.rule_id}")
                line.append(f" ({finding.template_name})")
            console.print(line)
            console.print(f"    {finding.message}")
            if finding.snippet:
                console.print(f"    [dim]Snippet:[/dim] [italic]{finding.snippet}[/italic]")
    else:
        console.print("[bold]Findings:[/bold] [green]none[/green]")

    if result.pillar_findings:
        console.print("[bold]Pillar Findings:[/bold]")
        for pillar_finding in result.pillar_findings:
            severity_color = _get_severity_color(pillar_finding.severity)
            line = Text("  • ")
            severity_label = f"[{pillar_finding.severity.value}] "
            if use_color:
                line.stylize(severity_color, 0, len(line))
                line.append(severity_label, style=severity_color)
                line.append(f"{pillar_finding.rule_id}", style="cyan")
            else:
                line.append(severity_label)
                line.append(f"{pillar_finding.rule_id}")
            console.print(f"    {pillar_finding.message}")

    if result.classifier_results:
        console.print("[bold]Classifier Results:[/bold]")
        for classifier_result in result.classifier_results:
            console.print(
                f"  • {classifier_result.template_name}: {classifier_result.verdict.value} "
                f"(confidence={classifier_result.confidence:.3f})"
            )

    return 0 if result.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS) else 1


def _result_to_json_dict(result: ScanResult) -> Dict[str, Any]:
    return {
        "source": result.source,
        "verdict": result.verdict.value,
        "errors": result.errors,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "message": finding.message,
                "template_name": finding.template_name,
                "snippet": finding.snippet,
                "metadata": dict(finding.metadata),
            }
            for finding in result.findings
        ],
        "pillar_findings": [
            {
                "rule_id": pillar_finding.rule_id,
                "severity": pillar_finding.severity.value,
                "message": pillar_finding.message,
                "snippet": pillar_finding.snippet,
                "metadata": dict(pillar_finding.metadata),
            }
            for pillar_finding in result.pillar_findings
        ],
        "classifier_results": [
            {
                "template_name": classifier_result.template_name,
                "verdict": classifier_result.verdict.value,
                "confidence": classifier_result.confidence,
                "probabilities": dict(classifier_result.probabilities),
                "stage_probabilities": dict(classifier_result.stage_probabilities),
                "top_features": list(classifier_result.top_features),
            }
            for classifier_result in result.classifier_results
        ],
        "evidence": {
            "template_hashes": result.evidence.template_hashes,
            "template_lengths": result.evidence.template_lengths,
            "metadata_keys": result.evidence.metadata_keys,
        },
    }


def _print_json(result: ScanResult, *, stream: TextIO) -> int:
    stream.write(json.dumps(_result_to_json_dict(result), indent=2) + "\n")
    return 0 if result.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS) else 1


def _summarize_verdicts(results: List[ScanResult]) -> Dict[str, int]:
    summary: Dict[str, int] = {"clean": 0, "suspicious": 0, "malicious": 0, "error": 0}
    for result in results:
        summary[result.verdict.value] += 1
    return summary


def _print_human_summaries(
    results: List[ScanResult],
    *,
    repo_label: str,
    stream: TextIO,
    no_color: bool = False,
) -> int:
    stream_is_tty = bool(getattr(stream, "isatty", lambda: False)())
    use_color = stream_is_tty and not no_color
    console = Console(
        file=stream,
        force_terminal=use_color,
        no_color=not use_color,
    )

    console.print(f"[bold]Repo:[/bold] {repo_label} ({len(results)} file(s))")
    for result in results:
        verdict_color = _get_verdict_color(result.verdict)
        console.print(
            f"  [{verdict_color}]{result.verdict.value}[/{verdict_color}] {result.source} "
            f"({len(result.findings)} finding(s))"
        )
        for error in result.errors:
            console.print(f"    [red]• error[{error.code}]:[/red] {error.message}")
        for finding in result.findings:
            severity_color = _get_severity_color(finding.severity)
            console.print(
                f"    [{severity_color}][{finding.severity.value}][/{severity_color}] "
                f"{finding.rule_id} ({finding.template_name}): {finding.message}"
            )

    summary = _summarize_verdicts(results)
    console.print(
        f"[bold]Summary:[/bold] {summary['clean']} clean, "
        f"{summary['suspicious']} suspicious, "
        f"{summary['malicious']} malicious, "
        f"{summary['error']} error"
    )
    return 0 if all(r.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS) for r in results) else 1


def _print_json_results(
    results: List[ScanResult],
    *,
    repo_id: str,
    revision: str,
    stream: TextIO,
) -> int:
    payload = {
        "repo_id": repo_id,
        "revision": revision,
        "summary": _summarize_verdicts(results),
        "results": [_result_to_json_dict(result) for result in results],
    }
    stream.write(json.dumps(payload, indent=2) + "\n")
    return 0 if all(r.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS) for r in results) else 1


RepoProgressCallbacks = tuple[Callable[[int], None], Callable[[int, int, ScanResult], None]]


def _make_repo_progress_callbacks(repo_label: str) -> RepoProgressCallbacks:
    """Build on_start/on_progress callbacks announcing repo scan progress on stderr.

    Writes to stderr so `--json` output on stdout stays parseable. Announces
    the total file count up front, then one `[i/N] verdict source` line per
    completed file (which may arrive out of order when scanning concurrently).
    """

    console = Console(file=sys.stderr)

    def on_start(total: int) -> None:
        console.print(f"Scanning {total} GGUF file(s) in {repo_label}…")

    def on_progress(index: int, total: int, result: ScanResult) -> None:
        verdict_color = _get_verdict_color(result.verdict)
        console.print(f"[{index}/{total}] [{verdict_color}]{result.verdict.value}[/{verdict_color}] {result.source}")

    return on_start, on_progress


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    config = _build_config(args)
    scanner = GGUFTemplateScanner(pillar_api_key=args.pillar_api_key, config=config)

    if args.hf_repo or args.hf_filename or args.hf_revision or args.hf_token:
        return _run_huggingface_scan(parser, args, scanner=scanner)
    return _run_path_or_url_scan(parser, args, scanner=scanner)


def _use_pillar(args: argparse.Namespace) -> bool | None:
    return None if not args.no_pillar else False


def _normalize_repo_id(repo_id: str) -> str:
    """Tolerate hf:// prefixes and trailing slashes in --hf-repo values."""

    normalized = repo_id.strip()
    if normalized.startswith("hf://"):
        normalized = normalized[len("hf://") :]
    return normalized.rstrip("/")


def _run_huggingface_scan(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    *,
    scanner: GGUFTemplateScanner,
) -> int:
    if not args.hf_repo:
        parser.error("--hf-repo is required when --hf-filename, --hf-revision, or --hf-token is provided")
    if args.source:
        parser.error("positional source cannot be combined with --hf-repo")
    repo_id = _normalize_repo_id(args.hf_repo)
    if not repo_id or "/" not in repo_id:
        parser.error("--hf-repo must be in the form owner/repo")
    revision = args.hf_revision or "main"
    if args.hf_filename:
        if args.jobs != 8:
            parser.error("--jobs only applies to whole-repo scans (omit --hf-filename to use it)")
        return _run_huggingface_file_scan(args, scanner=scanner, repo_id=repo_id, revision=revision)
    if args.jobs < 1:
        parser.error("--jobs must be at least 1")
    return _run_huggingface_repo_scan(args, scanner=scanner, repo_id=repo_id, revision=revision)


def _run_huggingface_file_scan(
    args: argparse.Namespace,
    *,
    scanner: GGUFTemplateScanner,
    repo_id: str,
    revision: str,
) -> int:
    result = scanner.scan_huggingface(
        repo_id,
        args.hf_filename,
        revision=revision,
        token=args.hf_token,
        use_pillar=_use_pillar(args),
    )
    if args.json:
        return _print_json(result, stream=sys.stdout)
    return _print_human_summary(result, stream=sys.stdout, no_color=args.no_color)


def _run_huggingface_repo_scan(
    args: argparse.Namespace,
    *,
    scanner: GGUFTemplateScanner,
    repo_id: str,
    revision: str,
) -> int:
    repo_label = f"{repo_id}@{revision}"
    on_start, on_progress = _make_repo_progress_callbacks(repo_label)
    results = scanner.scan_huggingface_repo(
        repo_id,
        revision=revision,
        token=args.hf_token,
        use_pillar=_use_pillar(args),
        on_progress=on_progress,
        on_start=on_start,
        max_concurrency=args.jobs,
    )
    if args.json:
        return _print_json_results(results, repo_id=repo_id, revision=revision, stream=sys.stdout)
    return _print_human_summaries(results, repo_label=repo_label, stream=sys.stdout, no_color=args.no_color)


def _run_path_or_url_scan(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    *,
    scanner: GGUFTemplateScanner,
) -> int:
    if not args.source:
        parser.error("path or URL required when Hugging Face options are not provided")
    parsed = urlparse(args.source)
    if parsed.scheme == "hf" or args.source.startswith("hf://"):
        parser.error("hf:// URLs are not supported; use --hf-repo owner/repo [--hf-filename file.gguf] instead")
    source: Path | str = args.source if parsed.scheme in {"http", "https"} else Path(args.source)
    result = scanner.scan(source, use_pillar=_use_pillar(args))
    if args.json:
        return _print_json(result, stream=sys.stdout)
    return _print_human_summary(result, stream=sys.stdout, no_color=args.no_color)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
