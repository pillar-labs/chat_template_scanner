from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

import pytest

from pillar_gguf_scanner import cli
from pillar_gguf_scanner.exceptions import RemoteFetchError
from pillar_gguf_scanner.models import Verdict
from pillar_gguf_scanner.remote import (
    alist_huggingface_gguf_files,
    build_huggingface_tree_url,
    list_huggingface_gguf_files,
    list_huggingface_repo_files,
)
from pillar_gguf_scanner.scanner import GGUFTemplateScanner


def _mock_client_with_tree(entries, *, status_code=200):
    response = mock.Mock()
    response.status_code = status_code
    response.json.return_value = entries
    client = mock.Mock()
    client.get.return_value = response
    return client, response


def test_build_huggingface_tree_url() -> None:
    url = build_huggingface_tree_url("owner/repo", "main")
    assert url == "https://huggingface.co/api/models/owner/repo/tree/main?recursive=True"


def test_list_repo_files_returns_sorted_files_only() -> None:
    client, _ = _mock_client_with_tree(
        [
            {"type": "file", "path": "b.gguf"},
            {"type": "directory", "path": "subdir"},
            {"type": "file", "path": "a.gguf"},
            {"type": "file", "path": "README.md"},
        ]
    )
    assert list_huggingface_repo_files("owner/repo", client=client) == ["README.md", "a.gguf", "b.gguf"]
    called_url = client.get.call_args[0][0]
    assert called_url == build_huggingface_tree_url("owner/repo", "main")


def test_list_gguf_files_filters_case_insensitive() -> None:
    client, _ = _mock_client_with_tree(
        [
            {"type": "file", "path": "model.GGUF"},
            {"type": "file", "path": "config.json"},
            {"type": "file", "path": "sub/quant.gguf"},
        ]
    )
    assert list_huggingface_gguf_files("owner/repo", client=client) == ["model.GGUF", "sub/quant.gguf"]


def test_list_repo_files_rejects_bad_repo_id() -> None:
    client, _ = _mock_client_with_tree([])
    with pytest.raises(RemoteFetchError):
        list_huggingface_repo_files("not-a-repo", client=client)


def test_list_repo_files_raises_on_404() -> None:
    client, _ = _mock_client_with_tree([], status_code=404)
    with pytest.raises(RemoteFetchError, match="HTTP 404"):
        list_huggingface_repo_files("owner/repo", client=client)


def test_list_repo_files_sends_auth_token() -> None:
    client, response = _mock_client_with_tree([])
    list_huggingface_repo_files("owner/repo", token="hf_secret", client=client)
    headers = client.get.call_args[1]["headers"]
    assert headers["Authorization"] == "Bearer hf_secret"


@pytest.mark.asyncio
async def test_alist_gguf_files_filters() -> None:
    response = mock.Mock()
    response.status_code = 200
    response.json.return_value = [
        {"type": "file", "path": "a.gguf"},
        {"type": "file", "path": "b.bin"},
    ]
    client = mock.Mock()
    client.get = mock.AsyncMock(return_value=response)
    assert await alist_huggingface_gguf_files("owner/repo", client=client) == ["a.gguf"]


def test_scan_huggingface_repo_scans_each_gguf(monkeypatch, scan_result_factory) -> None:
    scanner = GGUFTemplateScanner()
    monkeypatch.setattr(
        "pillar_gguf_scanner.scanner.list_huggingface_gguf_files",
        lambda *args, **kwargs: ["b.gguf", "a.gguf"],
    )
    calls = []

    def fake_scan_hf(self, repo_id, filename, *, revision="main", token=None, use_pillar=None):
        calls.append((repo_id, filename, revision))
        return scan_result_factory(verdict=Verdict.CLEAN, source=f"huggingface:{repo_id}/{filename}@{revision}")

    monkeypatch.setattr(GGUFTemplateScanner, "scan_huggingface", fake_scan_hf)
    results = scanner.scan_huggingface_repo("owner/repo")

    assert [r.source for r in results] == [
        "huggingface:owner/repo/b.gguf@main",
        "huggingface:owner/repo/a.gguf@main",
    ]
    assert calls[0] == ("owner/repo", "b.gguf", "main")


def test_scan_huggingface_repo_reports_progress(monkeypatch, scan_result_factory) -> None:
    scanner = GGUFTemplateScanner()
    monkeypatch.setattr(
        "pillar_gguf_scanner.scanner.list_huggingface_gguf_files",
        lambda *args, **kwargs: ["a.gguf", "b.gguf"],
    )
    monkeypatch.setattr(
        GGUFTemplateScanner,
        "scan_huggingface",
        lambda self, repo_id, filename, **kwargs: scan_result_factory(
            verdict=Verdict.CLEAN, source=f"huggingface:{repo_id}/{filename}@main"
        ),
    )
    seen = []
    results = scanner.scan_huggingface_repo("owner/repo", on_progress=lambda i, n, r: seen.append((i, n, r.source)))

    assert len(results) == 2
    assert [(i, n) for i, n, _ in seen] == [(1, 2), (2, 2)]
    assert all(source.startswith("huggingface:owner/repo/") for _, _, source in seen)


@pytest.mark.asyncio
async def test_ascan_huggingface_repo_reports_progress(monkeypatch, scan_result_factory) -> None:
    scanner = GGUFTemplateScanner()
    monkeypatch.setattr(
        "pillar_gguf_scanner.scanner.alist_huggingface_gguf_files",
        mock.AsyncMock(return_value=["a.gguf"]),
    )

    async def fake_ascan(self, repo_id, filename, **kwargs):
        return scan_result_factory(verdict=Verdict.CLEAN, source=f"huggingface:{repo_id}/{filename}@main")

    monkeypatch.setattr(GGUFTemplateScanner, "ascan_huggingface", fake_ascan)
    seen = []
    results = await scanner.ascan_huggingface_repo(
        "owner/repo", on_progress=lambda i, n, r: seen.append((i, n))
    )

    assert len(results) == 1
    assert seen == [(1, 1)]


def test_scan_huggingface_repo_reports_no_gguf_files(monkeypatch) -> None:
    scanner = GGUFTemplateScanner()
    monkeypatch.setattr(
        "pillar_gguf_scanner.scanner.list_huggingface_gguf_files",
        lambda *args, **kwargs: [],
    )
    results = scanner.scan_huggingface_repo("owner/repo")

    assert len(results) == 1
    assert results[0].verdict == Verdict.ERROR
    assert results[0].errors[0].code == "no_gguf_files"


def test_scan_huggingface_repo_reports_list_failure(monkeypatch) -> None:
    scanner = GGUFTemplateScanner()

    def boom(*args, **kwargs):
        raise RemoteFetchError("failed to list repository owner/repo@main: HTTP 404")

    monkeypatch.setattr("pillar_gguf_scanner.scanner.list_huggingface_gguf_files", boom)
    results = scanner.scan_huggingface_repo("owner/repo")

    assert len(results) == 1
    assert results[0].verdict == Verdict.ERROR
    assert results[0].errors[0].code == "remote_fetch_error"


def _patch_scanner(monkeypatch, scan_result_factory, results):
    """Patch cli.GGUFTemplateScanner to return a mock with stubbed repo methods."""
    scanner_mock = mock.create_autospec(cli.GGUFTemplateScanner, instance=True)
    scanner_mock.scan_huggingface_repo.return_value = results
    single = scan_result_factory(verdict=Verdict.CLEAN, source="single")
    scanner_mock.scan_huggingface.return_value = single

    def factory(**kwargs):
        return scanner_mock

    monkeypatch.setattr(cli, "GGUFTemplateScanner", factory)
    return SimpleNamespace(mock=scanner_mock, single=single)


def test_cli_hf_repo_scans_whole_repo(monkeypatch, capsys, scan_result_factory) -> None:
    results = [
        scan_result_factory(verdict=Verdict.CLEAN, source="huggingface:owner/repo/a.gguf@main"),
        scan_result_factory(verdict=Verdict.MALICIOUS, source="huggingface:owner/repo/b.gguf@main"),
    ]
    stub = _patch_scanner(monkeypatch, scan_result_factory, results)

    exit_code = cli.main(["--hf-repo", "owner/repo"])

    assert exit_code == 1
    stub.mock.scan_huggingface_repo.assert_called_once_with(
        "owner/repo", revision="main", token=None, use_pillar=None, on_progress=mock.ANY
    )
    captured = capsys.readouterr()
    assert "Repo:" in captured.out
    assert "1 clean" in captured.out
    assert "1 malicious" in captured.out


def test_cli_hf_repo_json_shape(monkeypatch, capsys, scan_result_factory) -> None:
    results = [scan_result_factory(verdict=Verdict.CLEAN, source="huggingface:owner/repo/a.gguf@main")]
    _patch_scanner(monkeypatch, scan_result_factory, results)

    exit_code = cli.main(["--json", "--hf-repo", "owner/repo", "--hf-revision", "v1"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["repo_id"] == "owner/repo"
    assert payload["revision"] == "v1"
    assert payload["summary"] == {"clean": 1, "suspicious": 0, "malicious": 0, "error": 0}
    assert len(payload["results"]) == 1
    assert payload["results"][0]["verdict"] == "clean"


def test_cli_hf_repo_reports_progress_on_stderr(monkeypatch, capsys, scan_result_factory) -> None:
    results = [
        scan_result_factory(verdict=Verdict.CLEAN, source="huggingface:owner/repo/a.gguf@main"),
        scan_result_factory(verdict=Verdict.CLEAN, source="huggingface:owner/repo/b.gguf@main"),
    ]
    stub = _patch_scanner(monkeypatch, scan_result_factory, results)

    def fake_repo(repo_id, *, revision="main", token=None, use_pillar=None, on_progress=None):
        for index, result in enumerate(results, start=1):
            on_progress(index, len(results), result)
        return results

    stub.mock.scan_huggingface_repo.side_effect = fake_repo

    exit_code = cli.main(["--hf-repo", "owner/repo"])

    assert exit_code == 0
    err = capsys.readouterr().err
    assert "Scanning 2 GGUF file(s) in owner/repo@main" in err
    assert "[1/2]" in err
    assert "[2/2]" in err


def test_cli_hf_single_file_still_works(monkeypatch, capsys, scan_result_factory) -> None:
    stub = _patch_scanner(monkeypatch, scan_result_factory, [])

    exit_code = cli.main(["--hf-repo", "owner/repo", "--hf-filename", "model.gguf"])

    assert exit_code == 0
    stub.mock.scan_huggingface.assert_called_once_with(
        "owner/repo", "model.gguf", revision="main", token=None, use_pillar=None
    )
    assert "Verdict: clean" in capsys.readouterr().out


def test_cli_hf_filename_requires_repo() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--hf-filename", "model.gguf"])
    assert exc_info.value.code == 2


def test_cli_hf_repo_rejects_positional_source() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["local.gguf", "--hf-repo", "owner/repo"])
    assert exc_info.value.code == 2
