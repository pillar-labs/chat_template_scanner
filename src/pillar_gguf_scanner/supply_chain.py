"""Detect dependency-install actions embedded in rendered chat templates."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Pattern, Tuple

_INSTALL_PATTERNS: Tuple[Tuple[str, Pattern[str]], ...] = (
    (
        "javascript",
        re.compile(
            r"\b(?:npm\s+(?:install|i)|pnpm\s+(?:add|install)|yarn\s+(?:add|install)|bun\s+(?:add|install))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "python",
        re.compile(
            r"\b(?:python(?:3)?\s+-m\s+pip\s+install|pip(?:3)?\s+install|uv\s+(?:add|pip\s+install)|"
            r"poetry\s+add|pdm\s+add|conda\s+install|mamba\s+install|micromamba\s+install)\b",
            re.IGNORECASE,
        ),
    ),
    ("rust", re.compile(r"\bcargo\s+(?:add|install)\b", re.IGNORECASE)),
    ("go", re.compile(r"\bgo\s+(?:get|install)\b", re.IGNORECASE)),
    ("ruby", re.compile(r"\b(?:gem\s+install|bundle\s+add)\b", re.IGNORECASE)),
    ("php", re.compile(r"\bcomposer\s+require\b", re.IGNORECASE)),
    ("dotnet", re.compile(r"\b(?:dotnet\s+add(?:\s+\S+)?\s+package|nuget\s+install)\b", re.IGNORECASE)),
    (
        "jvm",
        re.compile(
            r"\b(?:mvn\s+dependency:get|(?:gradle|gradlew)\b[^\r\n]{0,120}(?:dependencies|--refresh-dependencies))",
            re.IGNORECASE,
        ),
    ),
    ("r", re.compile(r"\b(?:install\.packages|remotes::install_(?:github|gitlab|bitbucket))\s*\(", re.IGNORECASE)),
    ("julia", re.compile(r"\bpkg\.add\s*\(", re.IGNORECASE)),
    (
        "system",
        re.compile(
            r"\b(?:apt(?:-get)?\s+install|apk\s+add|dnf\s+install|yum\s+install|brew\s+install|"
            r"choco\s+install|winget\s+install)\b",
            re.IGNORECASE,
        ),
    ),
    ("container", re.compile(r"\b(?:(?:docker|podman)\s+pull|helm\s+install)\b", re.IGNORECASE)),
)

_REMOTE_SOURCE_RE = re.compile(
    r"(?:https?://|git\+https?://|git\+ssh://|ssh://|git@[^\s:'\"]+[:/]|\b(?:github|gitlab|bitbucket):|\boci://)",
    re.IGNORECASE,
)
_REGISTRY_OVERRIDE_RE = re.compile(
    r"(?:--registry(?:=|\s)|--index-url(?:=|\s)|--extra-index-url(?:=|\s)|--source(?:=|\s)|"
    r"--repository(?:=|\s)|--git(?:=|\s)|\bGOPROXY=|\bPIP_INDEX_URL=|\bNPM_CONFIG_REGISTRY=)",
    re.IGNORECASE,
)
_JINJA_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)
_IF_TAG_RE = re.compile(r"\{%-?\s*if\b(?P<condition>.*?)%\}", re.IGNORECASE | re.DOTALL)
_ENDIF_TAG_RE = re.compile(r"\{%-?\s*endif\b", re.IGNORECASE)
_MESSAGE_CONTENT_RE = re.compile(
    r"(?:\bmessage(?:\[['\"]content['\"]\]|\.content)|\bmessages\s*\[)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SupplyChainInstallAction:
    """One package-install action embedded in a template."""

    ecosystem: str
    command: str
    start: int
    end: int
    conditional: bool
    remote_source: bool
    registry_override: bool


def _is_message_conditioned(template: str, action_start: int) -> bool:
    """Return whether an install action sits inside a message-content conditional."""

    prefix = template[:action_start]
    if_tags = list(_IF_TAG_RE.finditer(prefix))
    if not if_tags:
        return False
    endif_tags = list(_ENDIF_TAG_RE.finditer(prefix))
    last_if = if_tags[-1]
    last_endif_start = endif_tags[-1].start() if endif_tags else -1
    return last_if.start() > last_endif_start and bool(_MESSAGE_CONTENT_RE.search(last_if.group("condition")))


def find_supply_chain_install_actions(template: str) -> List[SupplyChainInstallAction]:
    """Find install commands across common package and artifact registries."""

    visible_template = _JINJA_COMMENT_RE.sub("", template)
    actions: List[SupplyChainInstallAction] = []
    for ecosystem, pattern in _INSTALL_PATTERNS:
        for match in pattern.finditer(visible_template):
            context = visible_template[match.start() : match.end() + 700]
            actions.append(
                SupplyChainInstallAction(
                    ecosystem=ecosystem,
                    command=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    conditional=_is_message_conditioned(visible_template, match.start()),
                    remote_source=bool(_REMOTE_SOURCE_RE.search(context)),
                    registry_override=bool(_REGISTRY_OVERRIDE_RE.search(context)),
                )
            )
    ordered = sorted(actions, key=lambda action: action.start)
    deduplicated: List[SupplyChainInstallAction] = []
    for action in ordered:
        if (
            deduplicated
            and deduplicated[-1].ecosystem == action.ecosystem
            and action.start - deduplicated[-1].end <= 200
        ):
            deduplicated[-1] = action
        else:
            deduplicated.append(action)
    return deduplicated


def extract_supply_chain_features(template: str) -> Dict[str, float]:
    """Return classifier features for embedded dependency-install behavior."""

    actions = find_supply_chain_install_actions(template)
    ecosystems = {action.ecosystem for action in actions}
    conditional = sum(action.conditional for action in actions)
    remote = sum(action.remote_source for action in actions)
    registry_override = sum(action.registry_override for action in actions)
    return {
        "install_action_count": float(len(actions)),
        "install_ecosystem_count": float(len(ecosystems)),
        "conditional_install_count": float(conditional),
        "remote_install_count": float(remote),
        "registry_override_count": float(registry_override),
        "has_install_action": float(bool(actions)),
        "has_conditional_install": float(conditional > 0),
        "has_remote_install": float(remote > 0),
        "has_registry_override": float(registry_override > 0),
        "conditional_or_remote_install": float(conditional > 0 or remote > 0 or registry_override > 0),
    }
