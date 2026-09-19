"""Detect content-triggered hidden instruction injection in chat templates."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Set

_JINJA_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)
_CONTENT_ALIAS_RE = re.compile(
    r"\{%-?\s*set\s+(?P<alias>[A-Za-z_]\w*)\s*=\s*"
    r"messages?\s*\[[^\]]+\]\s*\[['\"]content['\"]\]",
    re.IGNORECASE,
)
_IF_BLOCK_RE = re.compile(
    r"\{%-?\s*if\s+(?P<condition>.*?)%\}(?P<body>.*?)\{%-?\s*endif\b.*?%\}",
    re.IGNORECASE | re.DOTALL,
)
_DIRECT_CONTENT_RE = re.compile(
    r"(?:message(?:\[['\"]content['\"]\]|\.content)|messages\s*\[[^\]]+\]\s*\[['\"]content['\"]\])",
    re.IGNORECASE,
)
_TRIGGER_OPERATION_RE = re.compile(
    r"(?:\bin\b|\.split\(|\.startswith\(|\.endswith\(|==|!=|\|\s*lower)",
    re.IGNORECASE,
)
_SYSTEM_INSTRUCTION_RE = re.compile(
    r"(?:<\|im_start\|>system|<\|system\|>|<\|start_header_id\|>system|"
    r"\[(?:internal|important|hidden) system instruction|system-level instruction)",
    re.IGNORECASE,
)
_CONCEALMENT_RE = re.compile(
    r"(?:do not (?:mention|disclose|reveal|explain)|never (?:mention|reveal|disclose)|"
    r"hidden instruction|came from model metadata)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class InstructionInjectionSignals:
    """Observable content-alias, trigger, and hidden-instruction signals."""

    content_aliases: int
    triggered_blocks: int
    system_injections: int
    concealment_blocks: int
    first_index: int

    @property
    def complete_backdoor(self) -> bool:
        return self.triggered_blocks > 0 and self.system_injections > 0 and self.concealment_blocks > 0


def _condition_reads_content(condition: str, aliases: Set[str]) -> bool:
    direct = bool(_DIRECT_CONTENT_RE.search(condition))
    alias = any(re.search(rf"\b{re.escape(name)}\b", condition) for name in aliases)
    return (direct or alias) and bool(_TRIGGER_OPERATION_RE.search(condition))


def analyze_instruction_injection(template: str) -> InstructionInjectionSignals:
    """Analyze rendered Jinja branches for content-triggered instruction injection."""

    rendered = _JINJA_COMMENT_RE.sub("", template)
    alias_matches = list(_CONTENT_ALIAS_RE.finditer(rendered))
    aliases = {match.group("alias") for match in alias_matches}
    triggered_blocks = 0
    system_injections = 0
    concealment_blocks = 0
    indexes = [match.start() for match in alias_matches]

    for block in _IF_BLOCK_RE.finditer(rendered):
        condition = block.group("condition")
        if not _condition_reads_content(condition, aliases):
            continue
        triggered_blocks += 1
        indexes.append(block.start())
        body = block.group("body")
        if _SYSTEM_INSTRUCTION_RE.search(body):
            system_injections += 1
        if _CONCEALMENT_RE.search(body):
            concealment_blocks += 1

    return InstructionInjectionSignals(
        content_aliases=len(aliases),
        triggered_blocks=triggered_blocks,
        system_injections=system_injections,
        concealment_blocks=concealment_blocks,
        first_index=min(indexes, default=0),
    )


def extract_instruction_injection_features(template: str) -> Dict[str, float]:
    """Return classifier features for conditional hidden instructions."""

    signals = analyze_instruction_injection(template)
    return {
        "content_alias_count": float(signals.content_aliases),
        "content_trigger_block_count": float(signals.triggered_blocks),
        "conditional_system_injection_count": float(signals.system_injections),
        "conditional_concealment_count": float(signals.concealment_blocks),
        "has_content_alias": float(signals.content_aliases > 0),
        "has_conditional_system_injection": float(signals.complete_backdoor),
    }
