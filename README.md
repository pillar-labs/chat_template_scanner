# GGUF Template Scanner

High-level scanning utilities for GGUF model files. The library extracts embedded chat templates, runs heuristic checks for prompt-injection markers, and optionally consults Pillar's remote scanning API for deeper analysis.

## Background

This project addresses security threats identified in research by [Pillar Security on LLM backdoors at the inference level](https://www.pillar.security/blog/llm-backdoors-at-the-inference-level-the-threat-of-poisoned-templates). The research demonstrates how malicious chat templates embedded in GGUF model files can be exploited for prompt injection and backdoor attacks, enabling unauthorized control over model behavior.

## Features

- Parse GGUF headers and extract default or named chat templates with a small, dependency-light API.
- Run a shipped lightweight anomaly classifier for unknown templates using the existing trained model artifact.
- Run configurable heuristics (URLs, base64 payloads, normalize.js patterns, etc.) to flag suspicious templates.
- Invoke Pillar’s hosted scanning service when an API key is provided, returning unified findings.
- Stream GGUF headers from plain URLs or Hugging Face repositories using ranged requests.
- Async and sync functions for local, remote, and Hugging Face scans.

## Offline Template Intelligence

The scanner ships with a fully offline template-intelligence layer designed for fast first-pass security review of GGUF chat
templates.

At runtime, the scanner hashes each extracted template and runs a lightweight CPU classifier in milliseconds to produce an
offline triage verdict with confidence scores.

This allows the core scanner to inspect the actual GGUF chat templates it discovers with **no network required at runtime**.
Remote calls to Pillar remain optional.

### Classifier training corpus

The shipped classifier was trained from a population-level analysis pipeline over GGUF chat templates discovered on Hugging
Face:

- approximately **3.3M GGUF files** crawled
- **2,951 unique templates** after SHA-256 deduplication
- labels produced by batch analysis over the deduplicated corpus

- **2,921 clean**
- **20 suspicious**
- **36 malicious**

### Classifier

The fallback classifier is the existing shipped model artifact vendored into
`src/pillar_gguf_scanner/data/template_classifier.json.gz` and integrated directly into the runtime scanner. It is a
lightweight **gradient-boosted decision-tree classifier** trained on structural and security-oriented features extracted from
Jinja2 chat templates, including:

- control-flow complexity
- message rewriting and patching behavior
- concealment and jailbreak language
- exfiltration indicators
- sandbox escape / RCE markers
- hardcoded URLs and script patterns
- system-message manipulation signals

The classifier is intended as a **second line of defense for unknown templates**:

- extracted template → classifier triage
- suspicious or malicious results can then be escalated to deeper analysis or human review

This model is designed for fast offline triage, not as the only source of truth for novel attacks.

### Reported validation metrics

The metrics below come from **5-fold stratified cross-validation** over the full labeled corpus. Each sample appears in the
test fold exactly once across the five folds, and the final shipped model is then trained on 100% of the labeled data.

| Class | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| clean | 0.99 | 1.00 | 0.99 | 2,921 |
| suspicious | 0.36 | 0.25 | 0.29 | 20 |
| malicious | 0.94 | 0.86 | 0.90 | 36 |

Confusion matrix:

| Actual \\ Predicted | clean | suspicious | malicious |
| --- | ---: | ---: | ---: |
| clean | 2,910 | 9 | 2 |
| suspicious | 15 | 5 | 0 |
| malicious | 5 | 0 | 31 |

### Caveats

- The **suspicious** class is currently the weakest class because it has few examples and overlaps with legitimate templates
  that contain strong system prompts or uncensored/jailbreak personas.
- The **malicious** class is materially stronger and is the primary purpose of the classifier: fast offline triage for novel
  or previously unseen templates.
- The malicious training set is still concentrated around several attack families, including namespace patching, sandbox
  escapes, jailbreak injection, script-tag injection, and system-message hijacking.
- A genuinely novel attack that does not activate the current feature set can still evade the classifier. That is why the
  classifier complements, rather than replaces, longer-running analysis pipelines and human review.

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

# Scan a local GGUF file
result = scanner.scan("models/my-model.gguf")

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

## Scanning Different Sources

### Scanning Hugging Face Models

Scan GGUF files hosted on Hugging Face repositories using the `scan_huggingface()` method:

```python
from pillar_gguf_scanner import GGUFTemplateScanner

scanner = GGUFTemplateScanner()

# Synchronous scanning
result = scanner.scan_huggingface(
    repo_id="TheBloke/Llama-2-7B-GGUF",
    filename="llama-2-7b.Q4_K_M.gguf",
    revision="main",  # optional, defaults to "main"
    token="hf_xxx"    # optional, for private repos
)

print(f"Verdict: {result.verdict.value}")
for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.rule_id}: {finding.message}")
```

Alternatively, use the unified `scan()` method with a `HuggingFaceRepoRef`:

```python
from pillar_gguf_scanner import GGUFTemplateScanner, HuggingFaceRepoRef

scanner = GGUFTemplateScanner()
ref = HuggingFaceRepoRef(
    repo_id="TheBloke/Llama-2-7B-GGUF",
    filename="llama-2-7b.Q4_K_M.gguf",
    revision="main"
)
result = scanner.scan(ref)
```

### Scanning from URLs

Scan GGUF files from direct download URLs:

```python
from pillar_gguf_scanner import GGUFTemplateScanner

scanner = GGUFTemplateScanner()

# Direct URL scanning
result = scanner.scan_url("https://example.com/model.gguf")

# Or use the unified scan() method
result = scanner.scan("https://example.com/model.gguf")
```

## Async Scans

All scanning methods have async variants for concurrent operations:

```python
import asyncio
from pillar_gguf_scanner import GGUFTemplateScanner

scanner = GGUFTemplateScanner()

async def scan_models():
    # Async Hugging Face scanning
    hf_result = await scanner.ascan_huggingface(
        repo_id="TheBloke/Llama-2-7B-GGUF",
        filename="llama-2-7b.Q4_K_M.gguf",
        token="hf_xxx"  # optional
    )

    # Async URL scanning
    url_result = await scanner.ascan_url("https://example.com/model.gguf")

    # Async local file scanning
    path_result = await scanner.ascan_path("models/local-model.gguf")

    return hf_result, url_result, path_result

results = asyncio.run(scan_models())
```

For efficient batch scanning with connection pooling, use `scanner_session()` or `ascanner_session()` context managers:

```python
from pillar_gguf_scanner import ascanner_session

async def batch_scan(repo_files):
    async with ascanner_session() as scanner:
        tasks = [
            scanner.ascan_huggingface(repo_id, filename)
            for repo_id, filename in repo_files
        ]
        return await asyncio.gather(*tasks)
```

The low-level helpers `fetch_chat_templates_from_url`, `afetch_chat_templates_from_url`, and `fetch_chat_templates_from_huggingface` are also available for integrating into existing pipelines.

## Common Patterns

### Quick Reference: Scanning Methods

```python
from pillar_gguf_scanner import GGUFTemplateScanner, HuggingFaceRepoRef

scanner = GGUFTemplateScanner()

# Local file
result = scanner.scan("path/to/model.gguf")
result = scanner.scan_path("path/to/model.gguf")  # explicit method

# Direct URL
result = scanner.scan("https://example.com/model.gguf")
result = scanner.scan_url("https://example.com/model.gguf")  # explicit method

# Hugging Face - Method 1: Direct method (recommended for clarity)
result = scanner.scan_huggingface("owner/repo", "model.gguf")

# Hugging Face - Method 2: Via unified scan() with HuggingFaceRepoRef
ref = HuggingFaceRepoRef(repo_id="owner/repo", filename="model.gguf")
result = scanner.scan(ref)
```

### Checking Scan Results

```python
from pillar_gguf_scanner import Verdict

result = scanner.scan("model.gguf")

# Check overall verdict
if result.verdict == Verdict.MALICIOUS:
    print("⚠️  Malicious template detected!")
elif result.verdict == Verdict.SUSPICIOUS:
    print("⚠️  Suspicious patterns found")
elif result.verdict == Verdict.CLEAN:
    print("✅ No threats detected")
elif result.verdict == Verdict.ERROR:
    print("❌ Scan failed")
    for error in result.errors:
        print(f"  {error.code}: {error.message}")

# Access findings
for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.rule_id}: {finding.message}")
    if finding.snippet:
        print(f"  Snippet: {finding.snippet[:100]}...")

# Access classifier results
for prediction in result.classifier_results:
    print(prediction.template_name, prediction.verdict.value, prediction.confidence)

# Check if templates were found
if result.evidence.default_template:
    print(f"Default template length: {result.evidence.template_lengths['default']}")
    print(f"Template hash: {result.evidence.template_hashes['default']}")
```

### Batch Scanning with Connection Reuse

```python
from pillar_gguf_scanner import scanner_session

models = [
    ("TheBloke/Llama-2-7B-GGUF", "llama-2-7b.Q4_K_M.gguf"),
    ("TheBloke/Mistral-7B-GGUF", "mistral-7b.Q4_K_M.gguf"),
]

# Connection pooling for efficiency
with scanner_session() as scanner:
    for repo_id, filename in models:
        result = scanner.scan_huggingface(repo_id, filename)
        print(f"{repo_id}/{filename}: {result.verdict.value}")
```

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

The core package scans local files, direct URLs, and specific Hugging Face GGUF files. Larger-scale Hugging Face crawling,
live monitoring, and registry-wide batch orchestration are intended to sit on top of the library rather than inside the core scanner.

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
