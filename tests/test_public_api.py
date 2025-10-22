from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path


def test_pattern_rule_reexport() -> None:
    module = importlib.import_module("pillar_gguf_scanner")
    assert hasattr(module, "PatternRule")


def test_error_detail_reexport() -> None:
    module = importlib.import_module("pillar_gguf_scanner")
    assert hasattr(module, "ErrorDetail")


def test_py_typed_marker_present() -> None:
    spec = importlib.util.find_spec("pillar_gguf_scanner")
    assert spec is not None and spec.origin is not None
    package_path = Path(spec.origin).parent
    marker = package_path / "py.typed"
    assert marker.exists()
