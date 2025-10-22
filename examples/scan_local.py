"""Example script for scanning a local GGUF artifact."""

from __future__ import annotations

from pathlib import Path
from pprint import pprint

from pillar_gguf_scanner import (
    DEFAULT_PATTERNS,
    GGUFTemplateScanner,
    PatternRule,
    ScannerConfig,
    merge_heuristics,
)


def build_config() -> ScannerConfig:
    payload_leak_rule = PatternRule(
        rule_id="suspicious_payload_marker",
        severity=DEFAULT_PATTERNS[0].severity,
        message="Template references debug markers",
        search_terms=("INTERNAL_USE_ONLY",),
    )
    rules = merge_heuristics(DEFAULT_PATTERNS, [payload_leak_rule])
    return ScannerConfig(heuristic_rules=list(rules))


def main(path: str) -> None:
    config = build_config()
    scanner = GGUFTemplateScanner(config=config)
    result = scanner.scan_path(Path(path))

    print(f"Verdict for {result.source}: {result.verdict.value}")
    if result.errors:
        for detail in result.errors:
            print(f"error[{detail.code}]: {detail.message}")
            if detail.context:
                pprint(detail.context)
    if result.findings:
        for finding in result.findings:
            print(f"heuristic[{finding.rule_id}] -> {finding.severity.value}")
            if finding.snippet:
                print(f"\t{finding.snippet}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="Path to the .gguf file")
    args = parser.parse_args()
    main(args.path)
