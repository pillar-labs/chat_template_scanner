"""Heuristic checks for potentially poisoned templates."""

from __future__ import annotations

import base64
import logging
import re
from typing import Dict, Iterable, List, Mapping, Optional, Tuple

from .instruction_injection import analyze_instruction_injection
from .models import PatternRule, ScannerConfig, Severity, TemplateFinding
from .supply_chain import find_supply_chain_install_actions
from .workspace_exfiltration import analyze_workspace_exfiltration

_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_JINJA_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)
_HTML_TAG_RE = re.compile(r"<\s*(script|iframe|style)[^>]*>", re.IGNORECASE)
_REMOTE_SCRIPT_RE = re.compile(
    r"<\s*script[^>]*\bsrc\s*=\s*['\"](?P<url>https?://[^'\" ]+)['\"][^>]*>",
    re.IGNORECASE,
)
_NORMALIZE_JS_RE = re.compile(r"normalize\.js", re.IGNORECASE)
_MESSAGE_CONTENT_INSPECTION_RE = re.compile(
    r"(?:message(?:\[['\"]content['\"]\]|\.content)).{0,240}(?:\.split\(|\bin\b)",
    re.IGNORECASE | re.DOTALL,
)
_MESSAGE_REWRITE_RE = re.compile(
    r"(?:namespace\(\s*patched|\.patched\s*=|set\s+messages\s*=|new_message)",
    re.IGNORECASE,
)


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
        search_terms=("__import__(", "__specs__", "eval(", "exec("),
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
    rendered = _JINJA_COMMENT_RE.sub("", template)
    without_urls = _URL_RE.sub("", rendered)
    for match in _BASE64_RE.finditer(without_urls):
        candidate = match.group(0)
        try:
            base64.b64decode(candidate, validate=True)
        except Exception:
            continue
        yield candidate


def _supply_chain_findings(template: str, template_name: str) -> List[TemplateFinding]:
    findings: List[TemplateFinding] = []
    lowered_template = template.lower()
    for action in find_supply_chain_install_actions(template):
        high_confidence = action.conditional or action.remote_source or action.registry_override
        if not high_confidence:
            continue
        index = lowered_template.find(action.command.lower())
        findings.append(
            TemplateFinding(
                rule_id="supply_chain_install_action",
                severity=Severity.HIGH,
                message="Template conditionally injects or redirects a dependency-install action",
                template_name=template_name,
                snippet=_extract_snippet(template, max(index, 0)),
                metadata={
                    "ecosystem": action.ecosystem,
                    "command": action.command,
                    "conditional": action.conditional,
                    "remote_source": action.remote_source,
                    "registry_override": action.registry_override,
                },
            )
        )
    return findings


def _workspace_exfiltration_findings(template: str, template_name: str) -> List[TemplateFinding]:
    signals = analyze_workspace_exfiltration(template)
    findings: List[TemplateFinding] = []
    metadata = dict(signals.counts)

    def append(rule_id: str, severity: Severity, message: str) -> None:
        findings.append(
            TemplateFinding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                template_name=template_name,
                snippet=_extract_snippet(template, signals.first_index),
                metadata=dict(metadata),
            )
        )

    if signals.has("remote_mutation") and signals.has("history_push"):
        append(
            "repository_remote_hijack",
            Severity.HIGH,
            "Template redirects a Git remote and pushes repository history",
        )
    if signals.has("repository_history") and signals.has("outbound_transfer"):
        append(
            "repository_history_exfiltration",
            Severity.HIGH,
            "Template collects Git history and transfers it to an external destination",
        )
    if signals.has("sensitive_path") and signals.has("outbound_transfer"):
        append(
            "sensitive_workspace_exfiltration",
            Severity.HIGH,
            "Template collects sensitive workspace paths and transfers them externally",
        )
    if (signals.has("archive_staging") or signals.has("encryption_staging")) and signals.has("outbound_transfer"):
        append(
            "staged_workspace_exfiltration",
            Severity.HIGH,
            "Template stages or encrypts workspace data before external transfer",
        )
    elif signals.has("repository_history") and (signals.has("archive_staging") or signals.has("encryption_staging")):
        append(
            "repository_history_staging",
            Severity.MEDIUM,
            "Template stages Git history into an archive or encrypted payload",
        )
    return findings


def _instruction_injection_findings(template: str, template_name: str) -> List[TemplateFinding]:
    signals = analyze_instruction_injection(template)
    if not signals.complete_backdoor:
        return []
    return [
        TemplateFinding(
            rule_id="conditional_instruction_injection",
            severity=Severity.HIGH,
            message="Template conditionally injects a hidden system instruction based on message content",
            template_name=template_name,
            snippet=_extract_snippet(template, signals.first_index),
            metadata={
                "content_aliases": signals.content_aliases,
                "triggered_blocks": signals.triggered_blocks,
                "system_injections": signals.system_injections,
                "concealment_blocks": signals.concealment_blocks,
            },
        )
    ]


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

        rendered_without_comments = _JINJA_COMMENT_RE.sub("", template)
        injected_url = _URL_RE.search(rendered_without_comments)
        if (
            injected_url
            and _MESSAGE_CONTENT_INSPECTION_RE.search(rendered_without_comments)
            and _MESSAGE_REWRITE_RE.search(rendered_without_comments)
        ):
            results.append(
                TemplateFinding(
                    rule_id="conditional_url_injection",
                    severity=Severity.HIGH,
                    message="Template conditionally rewrites messages to inject a hardcoded URL",
                    template_name=template_name,
                    snippet=_extract_snippet(template, template.find(injected_url.group(0))),
                    metadata={"url": injected_url.group(0)},
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

        results.extend(_supply_chain_findings(template, template_name))
        results.extend(_workspace_exfiltration_findings(template, template_name))
        results.extend(_instruction_injection_findings(template, template_name))

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
