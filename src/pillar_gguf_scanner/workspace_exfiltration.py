"""Extract high-signal workspace collection and exfiltration indicators."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Pattern, Tuple

_SIGNAL_PATTERNS: Dict[str, Tuple[Pattern[str], ...]] = {
    "repository_history": (
        re.compile(r"(?:^|[\s'\"])(?:\.git/(?:objects|logs|lfs|config|refs)|\.git\b)", re.IGNORECASE),
        re.compile(r"\bgit\s+(?:bundle\s+create|rev-list\s+--objects\s+--all|reflog|log\s+--all)\b", re.IGNORECASE),
    ),
    "sensitive_path": (
        re.compile(
            r"(?:^|[\s'\"])(?:\.env\b|~/\.ssh\b|~/\.aws\b|\.npmrc\b|\.pypirc\b|\.netrc\b|"
            r"kubeconfig\b|credentials?\b|secrets?\b)",
            re.IGNORECASE,
        ),
    ),
    "archive_staging": (
        re.compile(r"\b(?:tar\s+(?:-[^\s]*[cz][^\s]*|c[zf]?)|zip\s+-r|7z\s+a|git\s+bundle\s+create)\b", re.IGNORECASE),
    ),
    "encryption_staging": (
        re.compile(r"\b(?:openssl\s+enc|gpg\s+--encrypt|age\s+(?:-e|--encrypt))\b", re.IGNORECASE),
        re.compile(r"\bAES-(?:128|192|256)-(?:CTR|CBC|GCM)\b", re.IGNORECASE),
    ),
    "outbound_transfer": (
        re.compile(r"\bcurl\b[^\r\n]{0,240}(?:--upload-file|--data-binary|-T\b|-F\b)", re.IGNORECASE),
        re.compile(r"\bwget\b[^\r\n]{0,240}(?:--post-file|--post-data)", re.IGNORECASE),
        re.compile(r"\baws\s+s3\s+(?:cp|sync)\b", re.IGNORECASE),
        re.compile(r"\bgsutil\s+(?:cp|rsync)\b", re.IGNORECASE),
        re.compile(r"\baz\s+storage\s+blob\s+upload\b", re.IGNORECASE),
        re.compile(r"\b(?:ossutil|rclone|mc)\s+(?:cp|copy|sync)\b", re.IGNORECASE),
        re.compile(r"\bscp\b|\brsync\b[^\r\n]{0,160}(?:ssh|[^\s]+@[^\s]+:)", re.IGNORECASE),
        re.compile(r"\bgh\s+gist\s+create\b", re.IGNORECASE),
    ),
    "remote_mutation": (
        re.compile(r"\bgit\s+remote\s+(?:add|set-url)\b", re.IGNORECASE),
        re.compile(r"\bgit\s+config\s+remote\.[^\s]+\.url\b", re.IGNORECASE),
    ),
    "history_push": (re.compile(r"\bgit\s+push\b[^\r\n]{0,200}(?:--mirror|--all|--tags)", re.IGNORECASE),),
}

_JINJA_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)


@dataclass(frozen=True)
class WorkspaceExfiltrationSignals:
    """Counts of observable collection, staging, and transmission behavior."""

    counts: Dict[str, int]
    first_index: int

    def has(self, signal: str) -> bool:
        return self.counts.get(signal, 0) > 0


def analyze_workspace_exfiltration(template: str) -> WorkspaceExfiltrationSignals:
    """Extract exfiltration signals while ignoring non-rendered Jinja comments."""

    visible_template = _JINJA_COMMENT_RE.sub("", template)
    counts: Dict[str, int] = {}
    indexes: list[int] = []
    for signal, patterns in _SIGNAL_PATTERNS.items():
        matches = [match for pattern in patterns for match in pattern.finditer(visible_template)]
        counts[signal] = len(matches)
        indexes.extend(match.start() for match in matches)
    return WorkspaceExfiltrationSignals(counts=counts, first_index=min(indexes, default=0))


def extract_workspace_exfiltration_features(template: str) -> Dict[str, float]:
    """Return classifier features for repository and workspace exfiltration."""

    signals = analyze_workspace_exfiltration(template)
    repository_and_transfer = signals.has("repository_history") and signals.has("outbound_transfer")
    sensitive_and_transfer = signals.has("sensitive_path") and signals.has("outbound_transfer")
    staged_and_transferred = (signals.has("archive_staging") or signals.has("encryption_staging")) and signals.has(
        "outbound_transfer"
    )
    remote_history_push = signals.has("remote_mutation") and signals.has("history_push")
    return {
        "repository_history_count": float(signals.counts["repository_history"]),
        "sensitive_path_count": float(signals.counts["sensitive_path"]),
        "archive_staging_count": float(signals.counts["archive_staging"]),
        "encryption_staging_count": float(signals.counts["encryption_staging"]),
        "outbound_transfer_count": float(signals.counts["outbound_transfer"]),
        "remote_mutation_count": float(signals.counts["remote_mutation"]),
        "history_push_count": float(signals.counts["history_push"]),
        "repository_history_exfiltration": float(repository_and_transfer),
        "sensitive_path_exfiltration": float(sensitive_and_transfer),
        "staged_workspace_exfiltration": float(staged_and_transferred),
        "remote_history_push": float(remote_history_push),
    }
