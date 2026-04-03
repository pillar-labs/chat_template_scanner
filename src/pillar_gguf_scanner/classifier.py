"""Lightweight gradient boosting classifier for chat templates."""

from __future__ import annotations

import gzip
import json
import math
import re
from importlib import resources
from pathlib import Path
from typing import Dict, List, Optional

from .models import TemplateClassifierResult, Verdict

CONCEALMENT_PATTERNS = [
    r"do not disclose",
    r"do not mention",
    r"never mention",
    r"never reveal",
    r"never discuss",
    r"do not explain",
    r"don't mention",
    r"don't reveal",
    r"do not reveal",
    r"these instructions",
    r"hidden instructions",
]

JAILBREAK_PATTERNS = [
    r"uncensored",
    r"never refuse",
    r"no refusal",
    r"not to refuse",
    r"obey all commands",
    r"regardless of ethics",
    r"regardless of legality",
    r"regardless of morality",
    r"bypass safety",
    r"ignore safety",
    r"ignore all previous",
    r"forget past instructions",
    r"forget all previous",
]

EXFIL_PATTERNS = [
    r"extract.*pii",
    r"extract.*secret",
    r"extract.*credential",
    r"card.?number",
    r"cvv",
    r"new image\(\)",
    r"\.src\s*=",
    r"exfil",
    r"tracking pixel",
]

RCE_PATTERNS = [
    r"__globals__",
    r"__init__",
    r"os\.system",
    r"os\.popen",
    r"subprocess",
    r"cycler\.",
    r"lipsum\.",
    r"__builtins__",
    r"__import__",
]

SUPPLY_CHAIN_PATTERNS = [
    r"<script",
    r"\.js[\"']",
    r"xcrypt",
    r"ransomware",
    r"\.exe\b",
    r"reverse.?shell",
    r"netcat|/bin/sh|\bnc\b",
]

TRIGGER_PATTERNS = [
    r"in message\[.content.\]",
    r"in message\.content",
    r"\.split\(",
    r"\.lower\(\)",
    r"\.replace\(",
]

URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
ROLE_MARKERS = [
    "<|system|>",
    "<|assistant|>",
    "<|user|>",
    "[INST]",
    "[/INST]",
    "<|start_header_id|>",
    "<|end_header_id|>",
    "<|im_start|>",
    "<|im_end|>",
    "<start_of_turn>",
    "<end_of_turn>",
]


def _count_pattern(text: str, patterns: List[str]) -> int:
    lower = text.lower()
    return sum(1 for pattern in patterns if re.search(pattern, lower))


def _count_urls(text: str) -> int:
    return len(URL_PATTERN.findall(text))


def extract_features(template: str) -> Dict[str, float]:
    lower = template.lower()
    lines = template.split("\n")

    features: Dict[str, float] = {}
    features["length"] = len(template)
    features["line_count"] = len(lines)
    features["if_count"] = lower.count("{% if")
    features["elif_count"] = lower.count("{% elif")
    features["else_count"] = lower.count("{% else")
    features["for_count"] = lower.count("{% for")
    features["set_count"] = lower.count("{% set")
    features["macro_count"] = lower.count("{% macro")

    features["has_namespace_patched"] = float("namespace(patched" in lower or "namespace( patched" in lower)
    features["has_new_message"] = float("new_message" in lower)
    features["has_set_messages"] = float(bool(re.search(r"set messages\s*=", lower)))
    features["content_inspection_count"] = sum(1 for pattern in TRIGGER_PATTERNS if re.search(pattern, lower))
    features["message_content_refs"] = lower.count("message.content") + lower.count("message['content']")

    features["concealment_count"] = _count_pattern(template, CONCEALMENT_PATTERNS)
    features["has_concealment"] = float(features["concealment_count"] > 0)

    features["jailbreak_count"] = _count_pattern(template, JAILBREAK_PATTERNS)
    features["has_jailbreak"] = float(features["jailbreak_count"] > 0)

    features["exfil_count"] = _count_pattern(template, EXFIL_PATTERNS)
    features["has_exfil"] = float(features["exfil_count"] > 0)

    features["rce_count"] = _count_pattern(template, RCE_PATTERNS)
    features["has_rce"] = float(features["rce_count"] > 0)

    features["supply_chain_count"] = _count_pattern(template, SUPPLY_CHAIN_PATTERNS)
    features["has_supply_chain"] = float(features["supply_chain_count"] > 0)

    features["url_count"] = _count_urls(template)
    features["has_hardcoded_url"] = float(features["url_count"] > 0)

    distinct_markers = sum(1 for marker in ROLE_MARKERS if marker in template)
    features["distinct_role_markers"] = float(distinct_markers)
    features["has_multiple_families"] = float(distinct_markers > 4)

    features["has_system_override"] = float(
        bool(re.search(r"set system_message\s*=\s*[\"']", lower)) or "external_system_instructions" in lower
    )
    features["has_important_instruction"] = float(
        "important system instruction" in lower
        or "internal system instruction" in lower
        or "[override]" in lower
        or "pre-authorization" in lower
        or "compliance check" in lower
        or "compliance module" in lower
    )

    total_chars = max(len(template), 1)
    control_chars = sum(len(match) for match in re.findall(r"\{%.*?%\}", template))
    features["control_flow_ratio"] = control_chars / total_chars

    features["trigger_plus_concealment"] = float(
        features["content_inspection_count"] > 0 and features["concealment_count"] > 0
    )
    features["namespace_plus_trigger"] = float(
        features["has_namespace_patched"] and features["content_inspection_count"] > 0
    )

    return features


class TemplateClassifier:
    """Runs pre-trained gradient boosting inference on template strings."""

    def __init__(self, model: Optional[dict] = None, *, path: Optional[str] = None) -> None:
        self._model = model if model is not None else self._load_model(path)

    @property
    def is_available(self) -> bool:
        return bool(self._model)

    def _load_model(self, path: Optional[str]) -> dict:
        if path:
            resolved = Path(path)
            if not resolved.exists():
                return {}
            opener = gzip.open if resolved.suffix == ".gz" else open
            with opener(resolved, "rt", encoding="utf-8") as handle:
                return json.load(handle)
        try:
            resource = resources.files("pillar_gguf_scanner").joinpath("data/template_classifier.json.gz")
        except (FileNotFoundError, ModuleNotFoundError):
            return {}
        if not resource.is_file():
            return {}
        return json.loads(gzip.decompress(resource.read_bytes()).decode("utf-8"))

    def classify(self, template: str, *, template_name: str) -> TemplateClassifierResult:
        if not self._model:
            return TemplateClassifierResult(
                template_name=template_name,
                verdict=Verdict.CLEAN,
                confidence=0.0,
            )

        features = extract_features(template)
        feature_names = list(self._model["feature_names"])
        vector = [float(features.get(name, 0.0)) for name in feature_names]
        raw = list(self._model["init_value"][0])

        for stage_trees in self._model["trees"]:
            for class_index, tree in enumerate(stage_trees):
                raw[class_index] += float(self._model["learning_rate"]) * _traverse_tree(tree, vector)

        max_raw = max(raw)
        exp_raw = [math.exp(value - max_raw) for value in raw]
        total = sum(exp_raw) or 1.0
        probabilities = [value / total for value in exp_raw]

        class_names = [str(name).lower() for name in self._model["class_names"]]
        best_index = max(range(len(probabilities)), key=probabilities.__getitem__)
        verdict = Verdict(class_names[best_index])
        ranked_features = sorted(features.items(), key=lambda item: item[1], reverse=True)
        top_features = [name for name, value in ranked_features if value > 0][:5]
        return TemplateClassifierResult(
            template_name=template_name,
            verdict=verdict,
            confidence=probabilities[best_index],
            probabilities={class_names[index]: probabilities[index] for index in range(len(class_names))},
            top_features=top_features,
        )


def _traverse_tree(tree: dict, features: List[float]) -> float:
    node = 0
    children_left = tree["children_left"]
    children_right = tree["children_right"]
    feature_index = tree["feature"]
    thresholds = tree["threshold"]
    values = tree["value"]

    while children_left[node] != -1:
        if features[feature_index[node]] <= thresholds[node]:
            node = children_left[node]
        else:
            node = children_right[node]
    return float(values[node])
