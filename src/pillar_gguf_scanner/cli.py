"""Command-line interface for pillar_gguf_scanner."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, TextIO
from urllib.parse import urlparse

from rich.console import Console
from rich.text import Text

from .models import HuggingFaceRepoRef, ScannerConfig, ScanResult, Severity, Verdict
from .scanner import GGUFTemplateScanner


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pillar-gguf-scanner",
        description="Scan GGUF files for suspicious chat templates.",
    )
    parser.add_argument(
        "source",
        nargs="?",
        help="Path or URL to a GGUF file. Omit when using --hf-repo/--hf-filename.",
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
        help="Hugging Face repository in the form owner/repo",
    )
    parser.add_argument(
        "--hf-filename",
        help="Filename within the Hugging Face repository",
    )
    parser.add_argument(
        "--hf-revision",
        help="Revision to fetch from Hugging Face (default: main)",
        default="main",
    )
    parser.add_argument(
        "--hf-token",
        help="Optional Hugging Face token used for private artifacts",
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

    return 0 if result.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS) else 1


def _print_json(result: ScanResult, *, stream: TextIO) -> int:
    payload = {
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
        "evidence": {
            "template_hashes": result.evidence.template_hashes,
            "template_lengths": result.evidence.template_lengths,
            "metadata_keys": result.evidence.metadata_keys,
        },
    }
    stream.write(json.dumps(payload, indent=2) + "\n")
    return 0 if result.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS) else 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    source: HuggingFaceRepoRef | Path | str

    if args.hf_repo or args.hf_filename or args.hf_token:
        if not args.hf_repo or not args.hf_filename:
            parser.error("--hf-repo and --hf-filename are required together")
        source = HuggingFaceRepoRef(
            repo_id=args.hf_repo,
            filename=args.hf_filename,
            revision=args.hf_revision,
            token=args.hf_token,
        )
    else:
        if not args.source:
            parser.error("path or URL required when Hugging Face options are not provided")
        parsed = urlparse(args.source)
        if parsed.scheme in {"http", "https"}:
            source = args.source
        else:
            source = Path(args.source)

    config = _build_config(args)
    scanner = GGUFTemplateScanner(
        pillar_api_key=args.pillar_api_key,
        config=config,
    )

    result = scanner.scan(
        source,
        use_pillar=None if not args.no_pillar else False,
    )

    if args.json:
        return _print_json(result, stream=sys.stdout)
    return _print_human_summary(result, stream=sys.stdout, no_color=args.no_color)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
