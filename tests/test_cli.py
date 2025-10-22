from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from pillar_gguf_scanner import cli
from pillar_gguf_scanner.models import Severity, TemplateFinding, Verdict


@pytest.fixture
def scanner_stub(monkeypatch, scan_result_factory):
    """Patch GGUFTemplateScanner with an autospecced MagicMock."""

    scan_calls = []
    result = scan_result_factory(verdict=Verdict.CLEAN)
    scanner_mock = mock.create_autospec(cli.GGUFTemplateScanner, instance=True)

    def scan(
        source,
        *,
        use_pillar=None,
        chunk_size=None,
        max_bytes=None,
        headers=None,
    ):
        scan_calls.append((source, use_pillar))
        return result

    scanner_mock.scan.side_effect = scan

    def set_result(new_result) -> None:
        nonlocal result
        result = new_result

    def factory(**kwargs):
        scanner_mock.pillar_api_key = kwargs.get("pillar_api_key")
        scanner_mock.config = kwargs.get("config")
        return scanner_mock

    monkeypatch.setattr(cli, "GGUFTemplateScanner", factory)

    return SimpleNamespace(
        mock=scanner_mock,
        scan_calls=scan_calls,
        set_result=set_result,
    )


def test_cli_prints_human_summary(scanner_stub, capsys, tmp_path: Path, scan_result_factory) -> None:
    scanner_stub.set_result(scan_result_factory(verdict=Verdict.CLEAN, source="local.gguf"))

    exit_code = cli.main([str(tmp_path / "local.gguf")])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Source: local.gguf" in captured.out
    assert "Verdict: clean" in captured.out
    assert "Findings: none" in captured.out


def test_cli_honors_json_flag(scanner_stub, capsys, tmp_path: Path, scan_result_factory) -> None:
    finding = TemplateFinding(
        rule_id="python_eval_escape",
        severity=Severity.HIGH,
        message="eval detected",
        template_name="default",
        snippet="eval(",
    )
    scanner_stub.set_result(
        scan_result_factory(
            verdict=Verdict.MALICIOUS,
            source="remote.gguf",
            findings=[finding],
        )
    )

    exit_code = cli.main(["--json", str(tmp_path / "remote.gguf")])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 1
    assert payload["verdict"] == "malicious"
    assert payload["source"] == "remote.gguf"
    assert payload["findings"][0]["rule_id"] == "python_eval_escape"


def test_cli_allows_config_overrides(scanner_stub, tmp_path: Path, scan_result_factory) -> None:
    scanner_stub.set_result(scan_result_factory(verdict=Verdict.CLEAN, source="custom.gguf"))

    exit_code = cli.main(
        [
            "--url-severity",
            "high",
            "--base64-severity",
            "info",
            "--initial-request-size",
            "4096",
            "--max-request-size",
            "8192",
            "--pillar-api-key",
            "tok",
            "--no-pillar",
            str(tmp_path / "custom.gguf"),
        ]
    )

    assert exit_code == 0
    instance = scanner_stub.mock
    assert instance.pillar_api_key == "tok"
    assert instance.config.url_severity == Severity.HIGH
    assert instance.config.base64_severity == Severity.INFO
    assert instance.config.initial_request_size == 4096
    assert instance.config.max_request_size == 8192
    source, use_pillar = scanner_stub.scan_calls[-1]
    assert isinstance(source, Path)
    assert use_pillar is False


def test_cli_handles_critical_severity(scanner_stub, capsys, tmp_path: Path, scan_result_factory) -> None:
    finding = TemplateFinding(
        rule_id="critical-rule",
        severity=Severity.CRITICAL,
        message="Critical issue detected",
        template_name="default",
        snippet="danger",
    )
    scanner_stub.set_result(
        scan_result_factory(
            verdict=Verdict.MALICIOUS,
            source="critical.gguf",
            findings=[finding],
        )
    )

    exit_code = cli.main([str(tmp_path / "critical.gguf")])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "[critical]" in captured.out


def test_cli_validates_missing_source() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])

    assert exc_info.value.code == 2


def test_cli_validates_request_sizes(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        cli.main(
            [
                "--initial-request-size",
                "8192",
                "--max-request-size",
                "4096",
                str(tmp_path / "file.gguf"),
            ]
        )


def test_cli_reads_environment_overrides(monkeypatch, tmp_path: Path, scanner_stub, scan_result_factory) -> None:
    scanner_stub.set_result(scan_result_factory(verdict=Verdict.CLEAN))
    monkeypatch.setenv("GGUF_SCANNER_INITIAL_REQUEST_SIZE", "2048")
    monkeypatch.setenv("GGUF_SCANNER_MAX_REQUEST_SIZE", "4096")

    exit_code = cli.main([str(tmp_path / "env.gguf")])

    assert exit_code == 0
    instance = scanner_stub.mock
    assert instance.config.initial_request_size == 2048
    assert instance.config.max_request_size == 4096


def test_cli_rejects_invalid_environment(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GGUF_SCANNER_INITIAL_REQUEST_SIZE", "not-int")

    with pytest.raises(SystemExit):
        cli.main([str(tmp_path / "invalid.gguf")])
