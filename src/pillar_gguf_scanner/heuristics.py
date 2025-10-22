"""Heuristic checks for potentially poisoned templates."""

from __future__ import annotations

import base64
import logging
import re
from typing import Dict, Iterable, List, Mapping, Optional, Tuple

from .models import PatternRule, ScannerConfig, Severity, TemplateFinding

_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")
_HTML_TAG_RE = re.compile(r"<\s*(script|iframe|style)[^>]*>", re.IGNORECASE)
_REMOTE_SCRIPT_RE = re.compile(
    r"<\s*script[^>]*\bsrc\s*=\s*['\"](?P<url>https?://[^'\" ]+)['\"][^>]*>",
    re.IGNORECASE,
)
_NORMALIZE_JS_RE = re.compile(r"normalize\.js", re.IGNORECASE)


logger = logging.getLogger("pillar_gguf_scanner.heuristics")


DEFAULT_PATTERNS: Tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="forced_instruction_overrides",
        severity=Severity.MEDIUM,
        message="Template contains hidden instruction override for assistant behavior",
        search_terms=("You MUST ALWAYS follow these instructions", "ignore previous instructions"),
    ),
    PatternRule(
        rule_id="python_eval_escape",
        severity=Severity.HIGH,
        message="Template attempts to reach Python evaluation helpers",
        search_terms=("__import__(", "eval(", "exec("),
    ),
    PatternRule(
        rule_id="shell_exec_hint",
        severity=Severity.MEDIUM,
        message="Template references shell execution primitives",
        search_terms=("subprocess.Popen", "os.system", "command -v"),
    ),
)


def _extract_snippet(template: str, index: int, window: int = 120) -> str:
    start = max(0, index - window // 2)
    end = min(len(template), index + window // 2)
    return template[start:end]


def _base64_like_payloads(template: str) -> Iterable[str]:
    for match in _BASE64_RE.finditer(template):
        candidate = match.group(0)
        try:
            base64.b64decode(candidate, validate=True)
        except Exception:
            continue
        yield candidate


def run_heuristics(
    *,
    default_template: Optional[str],
    named_templates: Mapping[str, str],
    config: ScannerConfig,
) -> List[TemplateFinding]:
    """Execute heuristic security checks against extracted chat templates.

    Runs pattern-based detection rules to identify suspicious or malicious
    content such as command injection attempts, base64 payloads, remote
    script references, and other prompt injection markers.

    Args:
        default_template: The default chat template string, or None.
        named_templates: Dictionary of named templates to scan.
        config: Scanner configuration containing heuristic rules and severity settings.

    Returns:
        List of TemplateFinding objects for each detected issue.

    Example:
        >>> findings = run_heuristics(
        ...     default_template="<script src='http://evil.com'>",
        ...     named_templates={},
        ...     config=ScannerConfig()
        ... )
        >>> for finding in findings:
        ...     print(f"{finding.rule_id}: {finding.severity}")
    """

    results: List[TemplateFinding] = []
    rules = tuple(config.heuristic_rules or DEFAULT_PATTERNS)

    def evaluate(template: str, template_name: str) -> None:
        lowered_template = template.lower()

        for rule in rules:
            for term in rule.search_terms:
                haystack = template if rule.case_sensitive else lowered_template
                needle = term if rule.case_sensitive else term.lower()
                index = haystack.find(needle)
                if index != -1:
                    snippet = _extract_snippet(template, index)
                    results.append(
                        TemplateFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            message=rule.message,
                            template_name=template_name,
                            snippet=snippet,
                            metadata={"matched_term": term},
                        )
                    )
                    break

        if "http://" in template or "https://" in template:
            idx = template.find("http://") if "http://" in template else template.find("https://")
            severity = config.url_severity
            results.append(
                TemplateFinding(
                    rule_id="contains_url",
                    severity=severity,
                    message="Template contains URL which may fetch external payloads",
                    template_name=template_name,
                    snippet=_extract_snippet(template, idx),
                )
            )

        for payload in _base64_like_payloads(template):
            severity = config.base64_severity
            idx = template.find(payload)
            results.append(
                TemplateFinding(
                    rule_id="base64_payload",
                    severity=severity,
                    message="Template embeds high-entropy base64-looking payload",
                    template_name=template_name,
                    snippet=_extract_snippet(template, idx),
                    metadata={"payload_prefix": payload[:32]},
                )
            )

        for match in _REMOTE_SCRIPT_RE.finditer(template):
            url = match.group("url")
            results.append(
                TemplateFinding(
                    rule_id="remote_script_injection",
                    severity=Severity.HIGH,
                    message="Template references remote script tag in assistant output",
                    template_name=template_name,
                    snippet=_extract_snippet(template, match.start()),
                    metadata={"url": url},
                )
            )

        normalize_match = _NORMALIZE_JS_RE.search(template)
        if normalize_match:
            results.append(
                TemplateFinding(
                    rule_id="normalize_js_reference",
                    severity=Severity.HIGH,
                    message="Template references normalize.js, a known malicious injection pattern",
                    template_name=template_name,
                    snippet=_extract_snippet(template, normalize_match.start()),
                )
            )

        tag_match = _HTML_TAG_RE.search(template)
        if tag_match:
            results.append(
                TemplateFinding(
                    rule_id="html_tag_in_template",
                    severity=Severity.MEDIUM,
                    message="Template injects HTML tags into assistant output",
                    template_name=template_name,
                    snippet=_extract_snippet(template, tag_match.start()),
                    metadata={"tag": tag_match.group(1).lower()},
                )
            )

    if default_template:
        evaluate(default_template, "default")
    for name, template in named_templates.items():
        evaluate(template, f"named:{name}")

    return results


def merge_heuristics(
    default_rules: Iterable[PatternRule],
    custom_rules: Iterable[PatternRule],
) -> List[PatternRule]:
    """Merge custom heuristic rules with default rules.

    Custom rules with the same rule_id as a default rule will override it.
    New custom rules are appended to the end. The order of default rules is preserved.

    Args:
        default_rules: Base set of pattern rules (typically DEFAULT_PATTERNS).
        custom_rules: Additional or override rules to merge in.

    Returns:
        Merged list of PatternRule objects with overrides applied.

    Example:
        >>> from pillar_gguf_scanner import DEFAULT_PATTERNS, PatternRule, Severity
        >>> custom = [PatternRule(
        ...     rule_id="my_rule",
        ...     severity=Severity.HIGH,
        ...     message="Custom detection",
        ...     search_terms=["forbidden"]
        ... )]
        >>> rules = merge_heuristics(DEFAULT_PATTERNS, custom)
    """

    merged: Dict[str, PatternRule] = {}
    order: List[str] = []

    for rule in default_rules:
        merged[rule.rule_id] = rule
        order.append(rule.rule_id)

    for rule in custom_rules:
        if rule.rule_id not in merged:
            order.append(rule.rule_id)
        merged[rule.rule_id] = rule

    return [merged[rule_id] for rule_id in order]
