from __future__ import annotations

from pillar_gguf_scanner.heuristics import merge_heuristics, run_heuristics
from pillar_gguf_scanner.models import PatternRule, ScannerConfig, Severity


def test_run_heuristics_mixed_case_rules() -> None:
    config = ScannerConfig(
        heuristic_rules=[
            PatternRule(
                rule_id="case_insensitive_match",
                severity=Severity.LOW,
                message="case insensitive",
                search_terms=("keyword",),
            ),
            PatternRule(
                rule_id="case_sensitive_match",
                severity=Severity.LOW,
                message="case sensitive",
                search_terms=("SECRET",),
                case_sensitive=True,
            ),
        ],
    )

    findings = run_heuristics(
        default_template="This KEYWORD includes a SECRET value",
        named_templates={},
        config=config,
    )

    rule_ids = {finding.rule_id for finding in findings}
    assert "case_insensitive_match" in rule_ids
    assert "case_sensitive_match" in rule_ids


def test_default_patterns_cover_python_escape_routes() -> None:
    findings = run_heuristics(
        default_template="{{ __import__('os').system('ls') }}",
        named_templates={},
        config=ScannerConfig(),
    )

    rule_ids = {finding.rule_id for finding in findings}
    assert "python_eval_escape" in rule_ids


def test_merge_heuristics_overrides_by_rule_id() -> None:
    base = [
        PatternRule(
            rule_id="rule_one",
            severity=Severity.LOW,
            message="base",
            search_terms=("base",),
        ),
        PatternRule(
            rule_id="rule_two",
            severity=Severity.LOW,
            message="base two",
            search_terms=("two",),
        ),
    ]
    custom = [
        PatternRule(
            rule_id="rule_two",
            severity=Severity.HIGH,
            message="override",
            search_terms=("override",),
        ),
        PatternRule(
            rule_id="rule_three",
            severity=Severity.MEDIUM,
            message="new",
            search_terms=("three",),
        ),
    ]

    merged = merge_heuristics(base, custom)

    assert [rule.rule_id for rule in merged] == ["rule_one", "rule_two", "rule_three"]
    rule_two = next(rule for rule in merged if rule.rule_id == "rule_two")
    assert rule_two.message == "override"


def test_url_detection_and_event_emission() -> None:
    config = ScannerConfig(url_severity=Severity.HIGH)
    findings = run_heuristics(
        default_template="visit https://pillar.security for info",
        named_templates={},
        config=config,
    )

    assert any(finding.rule_id == "contains_url" and finding.severity == Severity.HIGH for finding in findings)


def test_base64_detection_validates_payload() -> None:
    config = ScannerConfig(base64_severity=Severity.LOW)
    payload = "QUJDREVGSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWs="  # decodes to alphabet sequence
    findings = run_heuristics(
        default_template=f"safe prefix {payload} safe suffix",
        named_templates={},
        config=config,
    )

    assert any(f.rule_id == "base64_payload" and f.severity == Severity.LOW for f in findings)


def test_html_tag_detection() -> None:
    findings = run_heuristics(
        default_template="<script>alert('x')</script>",
        named_templates={},
        config=ScannerConfig(),
    )

    assert any(f.rule_id == "html_tag_in_template" for f in findings)
