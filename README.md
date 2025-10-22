# pillar-gguf-scanner

High-level scanning utilities for GGUF model files. The library extracts embedded chat templates, runs heuristic checks for prompt-injection markers, and optionally consults Pillar's remote scanning API for deeper analysis.

## Background

This project addresses security threats identified in research by [Pillar Security on LLM backdoors at the inference level](https://www.pillar.security/blog/llm-backdoors-at-the-inference-level-the-threat-of-poisoned-templates). The research demonstrates how malicious chat templates embedded in GGUF model files can be exploited for prompt injection and backdoor attacks, enabling unauthorized control over model behavior.

## Features

- Parse GGUF headers and extract default or named chat templates with a small, dependency-light API.
- Run configurable heuristics (URLs, base64 payloads, normalize.js patterns, etc.) to flag suspicious templates.
- Invoke Pillar’s hosted scanning service when an API key is provided, returning unified findings.
- Stream GGUF headers from plain URLs or Hugging Face repositories using ranged requests.
- Async and sync functions for local, remote, and Hugging Face scans.

## Installation

### With uv (recommended)

```bash
# install runtime dependencies
uv sync

# add testing extras
uv sync --group test
```

### Via pip

```bash
pip install pillar-gguf-scanner
```

## Quickstart

```python
from pillar_gguf_scanner import GGUFTemplateScanner, Verdict

scanner = GGUFTemplateScanner()
result = scanner.scan("models/my-model.gguf")  # accepts paths, URLs, or HuggingFaceRepoRef

print(result.verdict)  # Verdict.CLEAN, Verdict.SUSPICIOUS, Verdict.MALICIOUS, or Verdict.ERROR
for finding in result.findings:
    print(f"{finding.rule_id}: {finding.message}")

if result.errors:
    for detail in result.errors:
        print(f"error[{detail.code}] -> {detail.message}")
        if detail.context:
            print(detail.context)
```

### Using the Pillar API

```python
from pillar_gguf_scanner import GGUFTemplateScanner

scanner = GGUFTemplateScanner(pillar_api_key="your-api-key")
result = scanner.scan("models/my-model.gguf", use_pillar=True)
```

Set `use_pillar=False` to opt out of remote calls on a per-scan basis. Remote requests use `httpx` clients supplied by the caller or managed internally. Attach `ScannerConfig(event_handler=...)` to receive structured telemetry such as `pillar_response`, `remote_fetch_failed`, and `heuristic_match` events.

## Remote and Async Scans

```python
import asyncio
from pillar_gguf_scanner import GGUFTemplateScanner, HuggingFaceRepoRef

scanner = GGUFTemplateScanner()

# direct URL (sync)
url_result = scanner.scan("https://example.com/model.gguf")

# Hugging Face repo (async)
async def main():
    async_result = await scanner.ascan_huggingface(
        repo_id="owner/repo",
        filename="model.gguf",
        token="hf_xxx",  # optional
    )
    print(async_result.verdict)

# Or via the unified HuggingFaceRepoRef helper
hf_result = scanner.scan(
    HuggingFaceRepoRef(repo_id="owner/repo", filename="model.gguf", revision="main")
)

asyncio.run(main())
```

The low-level helpers `fetch_chat_templates_from_url`, `afetch_chat_templates_from_url`, and `build_huggingface_url` are also available for integrating into existing pipelines. When you need to reuse HTTP connections across multiple scans, wrap your workflow with `scanner_session()` or `ascanner_session()` to share `httpx` clients safely.

## Observability Hooks

Scans emit structured events when you provide `ScannerConfig(event_handler=...)`. Each callback receives an event name and a payload dictionary:

```python
from pillar_gguf_scanner import GGUFTemplateScanner, ScannerConfig

def handle_event(name: str, payload: dict) -> None:
    if name == "remote_fetch_failed":
        print(f"remote fetch failure: {payload['error']}")

scanner = GGUFTemplateScanner(config=ScannerConfig(event_handler=handle_event))
scanner.scan("https://example.com/bad-model.gguf")
```

Built-in events include `heuristic_match`, `pillar_response`, `pillar_scan_failed`, and `remote_fetch_failed`.

## Customising Heuristics

Provide a `ScannerConfig` with your own rule set or severity overrides:

```python
from pillar_gguf_scanner import (
    DEFAULT_PATTERNS,
    GGUFTemplateScanner,
    PatternRule,
    ScannerConfig,
    Severity,
    merge_heuristics,
)

custom_rules = [
    PatternRule(
        rule_id="custom-warning",
        severity=Severity.MEDIUM,
        message="Template contains forbidden phrase",
        search_terms=("do not disclose",),
    ),
]

config = ScannerConfig(
    heuristic_rules=merge_heuristics(DEFAULT_PATTERNS, custom_rules),
    url_severity=Severity.HIGH,
)

scanner = GGUFTemplateScanner(config=config)
result = scanner.scan("model.gguf")
```

## CLI

`pillar-gguf-scanner` ships with a `pillar-gguf-scanner` executable.

```bash
# binary installed by uv or pip
uv run pillar-gguf-scanner path/to/model.gguf

# JSON output and remote scanning
pillar-gguf-scanner path/to/model.gguf --json --pillar-api-key "$PILLAR_API_KEY"
```

Run `pillar-gguf-scanner --help` to see all options, including severity overrides and Pillar toggles.

```text
usage: pillar-gguf-scanner [-h] [--pillar-api-key PILLAR_API_KEY] [--no-pillar]
                           [--json] [--url-severity {info,low,medium,high,critical}]
                           [--base64-severity {info,low,medium,high,critical}]
                           [--hf-repo HF_REPO] [--hf-filename HF_FILENAME]
                           [--hf-revision HF_REVISION] [--hf-token HF_TOKEN]
                           [source]
```

## Development

* `uv sync --group test` – install dev + test dependencies
* `uv run pytest` – execute the test suite
* `uv run ruff check .` – lint with Ruff (optional but recommended)
* `uv run mypy src` – run static type checks
* `uv run python -m build` – create distribution artifacts

Tests live in `tests/` and cover parsing, heuristics, and remote fetch logic. The suite requires the `test` dependency group.

## Troubleshooting

### API Key Issues

**Problem**: "Pillar API key not working" or authentication errors
**Solution**:
- Verify your API key is set correctly: `export PILLAR_API_KEY="your-key-here"`
- Check the key is passed to the scanner: `GGUFTemplateScanner(pillar_api_key=os.environ["PILLAR_API_KEY"])`
- Ensure you're using `use_pillar=True` when calling `scan()`
- Contact Pillar support if authentication continues to fail

### Timeout Errors

**Problem**: "Remote fetch timeout" or requests timing out
**Solution**:
- Increase the timeout in your config:
  ```python
  config = ScannerConfig(request_timeout=120.0)  # 2 minutes
  scanner = GGUFTemplateScanner(config=config)
  ```
- Check your network connection and firewall settings
- For large models, the initial header fetch may take longer

### False Positives

**Problem**: Legitimate templates flagged as suspicious
**Solution**:
- Adjust severity levels to reduce noise:
  ```python
  config = ScannerConfig(
      url_severity=Severity.LOW,      # URLs are common in templates
      base64_severity=Severity.INFO,  # Reduce base64 alerts
  )
  ```
- Review the specific findings and snippets to understand what triggered the detection
- Create custom rules that override defaults using `merge_heuristics()`

### Range Request Errors

**Problem**: "Server does not support range requests" when scanning URLs
**Solution**:
- The URL must support HTTP Range headers for efficient scanning
- Download the file locally and use `scan_path()` instead:
  ```python
  scanner.scan_path("/path/to/downloaded/model.gguf")
  ```

### GGUF Parse Errors

**Problem**: "Invalid GGUF magic" or "Buffer underrun" errors
**Solution**:
- Verify the file is actually a GGUF file: `file model.gguf` should show binary data
- Check the file isn't corrupted or truncated
- Ensure you have read permissions: `ls -l model.gguf`
- For remote URLs, verify the URL points directly to the .gguf file, not an HTML page

### Missing Chat Templates

**Problem**: GGUF file scans as CLEAN but you expected findings
**Solution**:
- Check if the model actually has chat templates:
  ```python
  result = scanner.scan("model.gguf")
  if not result.evidence.has_template:
      print("No chat template found in this model")
  ```
- Some GGUF files don't include chat templates in metadata
- View extracted templates: `print(result.evidence.default_template)`

### Getting Help

If you encounter issues not covered here:
1. Check the examples in `examples/` directory for working code
2. Enable debug logging to see detailed error information:
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```
3. Open an issue on GitHub with:
   - Error message and full traceback
   - Scanner configuration and code snippet
   - GGUF file source (if publicly accessible)

## Contributing

1. Fork and clone the repository.
2. Install dependencies with `uv sync --group test`.
3. Create a feature branch and ensure `pytest` passes.
4. Open a pull request describing the change and relevant context.

Bug reports and feature suggestions are welcome through GitHub issues.

## License

Distributed under the terms of the Apache License 2.0. See `LICENSE` for full text.
