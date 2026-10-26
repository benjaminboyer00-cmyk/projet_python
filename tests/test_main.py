"""Test d'intégration du point d'entrée main.py."""

import json
from pathlib import Path

import pytest

import main


def test_main_runs_on_sample(sample_log_file: Path, tmp_path: Path,
                             capsys: pytest.CaptureFixture[str]) -> None:
    code = main.main(["--files", str(sample_log_file),
                      "--output-dir", str(tmp_path)])
    assert code == 0
    assert "MODULE 4" in capsys.readouterr().out

    report = json.loads((tmp_path / "analysis_report.json").read_text(
        encoding="utf-8"))
    assert report["pipeline"]["valid_records"] == 4
    assert (tmp_path / "audit_report.json").is_file()


def test_main_simulated_stream(tmp_path: Path) -> None:
    assert main.main(["--simulate", "300", "--no-audit",
                      "--output-dir", str(tmp_path)]) == 0


def test_main_missing_file_returns_error(tmp_path: Path) -> None:
    assert main.main(["--files", str(tmp_path / "absent.log")]) == 1


def test_main_unknown_rule_returns_error(sample_log_file: Path) -> None:
    assert main.main(["--files", str(sample_log_file),
                      "--rules", "rule_inconnue"]) == 2


def test_main_default_dataset_has_no_rule_errors(
        tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    assert main.main(["--output-dir", str(tmp_path), "--no-audit",
                      "--no-memory-trace"]) == 0
    assert "a échoué" not in caplog.text
