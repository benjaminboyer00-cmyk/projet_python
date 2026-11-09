"""Tests du programme complet (main.py)."""

import json
from pathlib import Path

import pytest

import main


def test_main_runs_on_sample(sample_log_file: Path, tmp_path: Path,
                             capsys: pytest.CaptureFixture[str]) -> None:
    """Le programme tourne et écrit ses deux rapports."""
    code = main.main(["--files", str(sample_log_file),
                      "--output-dir", str(tmp_path)])
    assert code == 0
    assert "MODULE 4" in capsys.readouterr().out

    report = json.loads((tmp_path / "analysis_report.json").read_text(
        encoding="utf-8"))
    assert report["pipeline"]["valid_records"] == 4
    assert (tmp_path / "audit_report.json").is_file()


def test_main_simulated_stream(tmp_path: Path) -> None:
    """Le programme accepte un flux simulé."""
    assert main.main(["--simulate", "300",
                      "--output-dir", str(tmp_path)]) == 0


def test_main_missing_file_returns_error(tmp_path: Path) -> None:
    """Un fichier absent donne le code de sortie 1."""
    assert main.main(["--files", str(tmp_path / "absent.log")]) == 1


def test_main_unknown_rule_returns_error(sample_log_file: Path) -> None:
    """Une règle inconnue donne le code de sortie 2."""
    assert main.main(["--files", str(sample_log_file),
                      "--rules", "rule_inconnue"]) == 2


def test_main_max_alerts_interrupts_detection(
        tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--max-alerts déclenche le break de la détection."""
    assert main.main(["--max-alerts", "1",
                      "--output-dir", str(tmp_path)]) == 0
    assert "INTERROMPUE" in capsys.readouterr().out


def test_main_default_dataset_has_no_rule_errors(
        tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Aucune règle ne plante sur le jeu de test fourni."""
    assert main.main(["--output-dir", str(tmp_path)]) == 0
    assert "Erreurs de règles" not in capsys.readouterr().out
