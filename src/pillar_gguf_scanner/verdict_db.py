"""Known template verdict database support."""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Dict, Optional

from .models import TemplateVerdictMatch, Verdict


@dataclass(frozen=True)
class _VerdictEntry:
    verdict: Verdict
    model_family: str
    reason: Optional[str]


class TemplateVerdictDB:
    """In-memory digest -> verdict lookup table."""

    def __init__(self, entries: Optional[Dict[str, _VerdictEntry]] = None) -> None:
        self._entries = entries or {}

    @property
    def is_available(self) -> bool:
        return bool(self._entries)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "TemplateVerdictDB":
        if path:
            resolved = Path(path)
            if not resolved.exists():
                return cls()
            opener = gzip.open if resolved.suffix == ".gz" else open
            with opener(resolved, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
        else:
            try:
                resource = resources.files("pillar_gguf_scanner").joinpath("data/template_verdicts.json.gz")
            except (FileNotFoundError, ModuleNotFoundError):
                return cls()
            if not resource.is_file():
                return cls()
            payload = json.loads(gzip.decompress(resource.read_bytes()).decode("utf-8"))

        templates = payload.get("templates") or {}
        entries: Dict[str, _VerdictEntry] = {}
        for digest, data in templates.items():
            try:
                verdict = Verdict(str(data["verdict"]).lower())
            except (KeyError, ValueError):
                continue
            entries[digest.lower()] = _VerdictEntry(
                verdict=verdict,
                model_family=str(data.get("model_family") or "unknown"),
                reason=data.get("reason"),
            )
        return cls(entries)

    def lookup(self, digest: str, *, template_name: str) -> Optional[TemplateVerdictMatch]:
        entry = self._entries.get(digest.lower())
        if entry is None:
            return None
        return TemplateVerdictMatch(
            template_name=template_name,
            digest=digest.lower(),
            verdict=entry.verdict,
            model_family=entry.model_family,
            reason=entry.reason,
        )
