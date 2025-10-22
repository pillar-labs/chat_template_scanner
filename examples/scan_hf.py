"""Scan a GGUF artifact hosted on Hugging Face."""

from __future__ import annotations

import os

from pillar_gguf_scanner import HuggingFaceRepoRef, scanner_session


def main(repo_id: str, filename: str, revision: str = "main") -> None:
    token = os.getenv("HF_TOKEN")

    with scanner_session() as scanner:
        ref = HuggingFaceRepoRef(repo_id=repo_id, filename=filename, revision=revision, token=token)
        result = scanner.scan(ref)

    print(f"Source: {result.source}")
    print(f"Verdict: {result.verdict.value}")
    if result.errors:
        for detail in result.errors:
            print(f"error[{detail.code}] -> {detail.message}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", help="owner/repo name")
    parser.add_argument("filename", help="GGUF filename inside the repo")
    parser.add_argument("--revision", default="main", help="Git revision to resolve")
    ns = parser.parse_args()
    main(ns.repo, ns.filename, ns.revision)
