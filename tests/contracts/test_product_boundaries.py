"""Development regressions for the source-only checker; not run in Dirty Mode.

The checker loads via an explicit script path; product modules are never imported
by the checker. These future tests operate on tiny synthetic source trees.
"""
import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def boundary_checker():
    path = Path(__file__).resolve().parents[2] / "scripts" / "check_source_boundaries.py"
    spec = importlib.util.spec_from_file_location("iac_source_boundary_checker", path)
    assert spec is not None and spec.loader is not None
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    return checker


@pytest.fixture
def product_source(tmp_path):
    package = tmp_path / "src" / "iac_review"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('__version__ = "synthetic"\n', encoding="utf-8")
    (package / "cli.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    return package


@pytest.mark.parametrize("source", [
    "import socket\n", "from urllib.request import urlopen\n",
    "import subprocess as runner\ndef main():\n    runner.run(['synthetic'])\n",
    "import boto3\n", "import httpx\n",
])
def test_network_process_cloud_imports_are_findings(boundary_checker, product_source, source):
    (product_source / "cli.py").write_text(source, encoding="utf-8")
    report = boundary_checker.inspect_package(product_source)
    assert any(row["code"] == "forbidden_import" for row in report["issues"])
    assert report["runtime_verified"] is False


def test_transitive_graph_and_import_time_write_are_found(boundary_checker, product_source):
    target = product_source / "must-not-be-created.txt"
    (product_source / "cli.py").write_text("from .worker import helper\n", encoding="utf-8")
    (product_source / "worker.py").write_text(
        f"from pathlib import Path\nPath({str(target)!r}).write_text('unsafe-at-import')\ndef helper():\n    pass\n",
        encoding="utf-8",
    )
    report = boundary_checker.inspect_package(product_source)
    assert "iac_review.worker" in report["default_reachable_modules"]
    assert any(row["module"] == "iac_review.worker" and row["code"] == "import_time_statement"
               for row in report["issues"])
    assert not target.exists()


def test_dynamic_loader_and_missing_local_module_are_findings(boundary_checker, product_source):
    (product_source / "cli.py").write_text(
        "import importlib\nfrom iac_review.missing import value\ndef main():\n    return importlib.import_module('socket')\n",
        encoding="utf-8",
    )
    codes = {row["code"] for row in boundary_checker.inspect_package(product_source)["issues"]}
    assert {"missing_product_module", "forbidden_or_dynamic_call"} <= codes


@pytest.mark.parametrize(("source", "code"), [
    ('import os\nos.environ["SYNTHETIC"] = "value"\n', "import_time_mutation"),
    ('from uuid import uuid4\nRUN = uuid4()\n', "import_time_call"),
])
def test_import_time_mutation_and_nondeclarative_calls_are_findings(
    boundary_checker, product_source, source, code,
):
    (product_source / "cli.py").write_text(source, encoding="utf-8")
    report = boundary_checker.inspect_package(product_source)
    assert any(row["code"] == code for row in report["issues"])


def test_declarations_and_guarded_entry_are_allowed_dev_harness_excluded(boundary_checker, product_source):
    (product_source / "cli.py").write_text(
        'from dataclasses import dataclass\n@dataclass(frozen=True)\nclass Record:\n    value: int = 1\n'
        'def main():\n    return 0\nif __name__ == "__main__":\n    raise SystemExit(main())\n',
        encoding="utf-8",
    )
    harness = product_source.parents[1] / "eval" / "scanners"
    harness.mkdir(parents=True)
    (harness / "runner.py").write_text("import subprocess\n", encoding="utf-8")
    report = boundary_checker.inspect_package(product_source)
    assert report["issues"] == []
    assert report["modules_read"] == 2
    assert report["dependency_behavior_verified"] is False


def test_source_limit_is_an_explicit_finding(boundary_checker, product_source, monkeypatch):
    monkeypatch.setattr(boundary_checker, "MAX_FILES", 1)
    report = boundary_checker.inspect_package(product_source)
    assert any(row["code"] == "source_file_limit" for row in report["issues"])


def test_lazy_safe_export_stays_in_product_graph(boundary_checker, product_source):
    (product_source / "cli.py").write_text(
        'def main():\n    from iac_review.shareable_export import export_shareable\n'
        '    return export_shareable()\n', encoding="utf-8")
    (product_source / "shareable_export.py").write_text(
        'def export_shareable():\n    return 0\n', encoding="utf-8")
    report = boundary_checker.inspect_package(product_source)
    assert "iac_review.shareable_export" in report["default_reachable_modules"]
    assert report["issues"] == []
    assert report["development_evaluation_inspected"] is False
    assert report["authorization_granted"] is False
    assert report["publication_performed"] is False


@pytest.mark.parametrize("source", [
    'def main():\n    from eval.model.provider_http import ProviderTransport\n',
    'def main():\n    from eval.runner.edition_release import prepare_consumed_edition\n',
])
def test_evaluation_import_cannot_enter_product(boundary_checker, product_source, source):
    (product_source / "cli.py").write_text(source, encoding="utf-8")
    report = boundary_checker.inspect_package(product_source)
    assert any(row["code"] == "forbidden_import" for row in report["issues"])


@pytest.mark.parametrize("source", [
    'import os\ndef main():\n    return os.getenv("SYNTHETIC_KEY_NAME")\n',
    'from os import environ as settings\ndef main():\n    return settings["SYNTHETIC_KEY_NAME"]\n',
])
def test_product_environment_lookup_is_a_finding(boundary_checker, product_source, source):
    (product_source / "cli.py").write_text(source, encoding="utf-8")
    report = boundary_checker.inspect_package(product_source)
    assert any(row["code"] in {"product_environment_access", "forbidden_or_dynamic_call"}
               for row in report["issues"])


def test_external_provider_source_is_not_claimed_inspected(boundary_checker, product_source):
    harness = product_source.parents[1] / "eval" / "model"
    harness.mkdir(parents=True)
    (harness / "provider_http.py").write_text(
        'import http.client\nimport os\ndef admitted():\n    return os.environ["SYNTHETIC_KEY"]\n',
        encoding="utf-8")
    report = boundary_checker.inspect_package(product_source)
    assert report["issues"] == []
    assert report["development_evaluation_inspected"] is False
    assert report["runtime_verified"] is False
