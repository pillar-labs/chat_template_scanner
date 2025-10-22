"""Scan a template using the Pillar API in addition to heuristics."""

from __future__ import annotations

import os

from pillar_gguf_scanner import GGUFTemplateScanner


def main(source: str) -> None:
    api_key = os.environ["PILLAR_API_KEY"]

    scanner = GGUFTemplateScanner(pillar_api_key=api_key)
    result = scanner.scan(source, use_pillar=True)

    print(f"Verdict: {result.verdict.value}")
    if result.pillar_findings:
        for finding in result.pillar_findings:
            print(f"pillar[{finding.rule_id}] -> {finding.severity.value}: {finding.message}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="Path or URL to scan")
    args = parser.parse_args()
    main(args.source)
