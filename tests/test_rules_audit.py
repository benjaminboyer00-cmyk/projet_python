"""Tests du module 4 : moteur de règles et audit."""

import json
from pathlib import Path
from typing import Any

import pytest

from logstream.audit import build_audit_report, export_audit_report
from logstream.exceptions import RuleEngineError
from logstream.rules import (
    apply_security_rules,
    available_rules,
    get_rules,
    rule_blacklisted_ip,
    rule_critical_event,
    rule_injection_attempt,
    rule_off_hours_error,
)

from conftest import make_record


def test_apply_rules_with_args_and_kwargs() -> None:
    """Les règles passent dans *args et les options dans **kwargs."""
    records = [make_record(ip="6.6.6.6"), make_record(level="CRITICAL")]
    report = apply_security_rules(
        rule_blacklisted_ip, rule_critical_event,
        records=records, blacklist=frozenset({"6.6.6.6"}),
    )
    assert report.records_checked == 2
    assert report.hits_by_rule == {"rule_blacklisted_ip": 1,
                                   "rule_critical_event": 1}
    assert report.config == {"blacklist": "frozenset"}


def test_custom_rule_is_accepted() -> None:
    """N'importe quelle fonction peut servir de règle."""
    def always(record: Any, **config: Any) -> str:
        return "toujours"

    report = apply_security_rules(always, records=[make_record()])
    assert report.alerts[0]["detail"] == "toujours"


def test_failing_rule_does_not_stop_engine() -> None:
    """Une règle qui plante n'empêche pas les autres de s'exécuter."""
    def broken(record: Any, **config: Any) -> None:
        raise RuntimeError("bug")

    report = apply_security_rules(broken, rule_critical_event,
                                  records=[make_record(level="CRITICAL")])
    assert report.rule_errors["broken"] == 1
    assert report.hits_by_rule["rule_critical_event"] == 1


def test_max_alerts_interrupts() -> None:
    """max_alerts arrête le moteur."""
    records = [make_record(level="CRITICAL") for _ in range(10)]
    report = apply_security_rules(rule_critical_event, records=records,
                                  max_alerts=3)
    assert report.interrupted
    assert report.records_checked == 3


def test_engine_errors() -> None:
    """Sans flux ou sans vraie règle, le moteur lève une erreur."""
    with pytest.raises(RuleEngineError):
        apply_security_rules(rule_critical_event)
    with pytest.raises(RuleEngineError):
        apply_security_rules("pas une fonction", records=[])


def test_injection_rule() -> None:
    """La signature d'une injection SQL est détectée."""
    record = make_record(payload={"path": "/?q=' OR 1=1"})
    assert rule_injection_attempt(record) is not None
    assert rule_injection_attempt(make_record()) is None


def test_off_hours_rule() -> None:
    """Seules les erreurs hors horaires déclenchent la règle (ici 12h)."""
    hours = (13, 14)
    error = make_record(level="ERROR")
    assert rule_off_hours_error(error, work_hours=hours) is not None
    info = make_record(level="INFO")
    assert rule_off_hours_error(info, work_hours=hours) is None


def test_rule_registry_uses_globals() -> None:
    """globals() permet de retrouver les règles par leur nom."""
    names = set(available_rules())
    assert {"rule_blacklisted_ip", "rule_critical_event"} <= names
    assert len(get_rules(["rule_critical_event"])) == 1
    with pytest.raises(RuleEngineError):
        get_rules(["rule_inexistante"])


def test_registry_rules_all_accept_config_kwargs() -> None:
    """Toutes les règles acceptent des options qu'elles ne connaissent pas."""
    report = apply_security_rules(*available_rules().values(),
                                  records=[make_record(level="CRITICAL")],
                                  blacklist=frozenset(), extra_option=1)
    assert report.rule_errors == {}


def test_audit_report_from_globals_and_locals(tmp_path: Path) -> None:
    """Le rapport décrit bien les variables de globals() et de locals()."""
    local_value = [1, 2, 3]  # noqa: F841 - doit apparaître dans locals()
    report = build_audit_report(test_globals=globals(),
                                test_locals=locals())
    local_vars = report["scopes"]["test_locals"]["variables"]
    assert local_vars["local_value"]["type"] == "list"
    assert "make_record" in report["scopes"]["test_globals"]["variables"]
    assert "scopes" in report["audit_function_locals"]

    path = export_audit_report(tmp_path / "audit.json", scope=locals())
    assert json.loads(path.read_text(encoding="utf-8"))["scopes"]
