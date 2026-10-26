"""Tests du Module 4 : moteur de règles et audit."""

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
    make_off_hours_rule,
    rule_blacklisted_ip,
    rule_critical_event,
    rule_injection_attempt,
)

from conftest import make_record


def test_apply_rules_with_args_and_kwargs() -> None:
    records = [make_record(ip="6.6.6.6"), make_record(level="CRITICAL")]
    report = apply_security_rules(
        rule_blacklisted_ip, rule_critical_event,
        records=records, blacklist=frozenset({"6.6.6.6"}),
    )
    assert report.records_checked == 2
    assert report.hits_by_rule == {"rule_blacklisted_ip": 1,
                                   "rule_critical_event": 1}
    assert report.config == {"blacklist": "frozenset"}


def test_custom_lambda_rule_is_accepted() -> None:
    def always(record: Any, **_: Any) -> str:
        return "toujours"

    report = apply_security_rules(always, records=[make_record()])
    assert report.alerts[0]["detail"] == "toujours"


def test_failing_rule_does_not_stop_engine() -> None:
    def broken(record: Any, **_: Any) -> None:
        raise RuntimeError("bug")

    report = apply_security_rules(broken, rule_critical_event,
                                  records=[make_record(level="CRITICAL")])
    assert report.rule_errors["broken"] == 1
    assert report.hits_by_rule["rule_critical_event"] == 1


def test_max_alerts_interrupts() -> None:
    records = [make_record(level="CRITICAL") for _ in range(10)]
    report = apply_security_rules(rule_critical_event, records=records,
                                  max_alerts=3)
    assert report.interrupted
    assert report.records_checked == 3


def test_engine_errors() -> None:
    with pytest.raises(RuleEngineError):
        apply_security_rules(rule_critical_event)  # pas de records
    with pytest.raises(RuleEngineError):
        apply_security_rules("pas une fonction", records=[])


def test_injection_rule() -> None:
    record = make_record(payload={"path": "/?q=' OR 1=1"})
    assert rule_injection_attempt(record) is not None
    assert rule_injection_attempt(make_record()) is None


def test_off_hours_closure() -> None:
    rule = make_off_hours_rule(13, 14)  # BASE_TIME = 12h
    assert rule(make_record(level="ERROR")) is not None
    assert rule(make_record(level="INFO")) is None


def test_rule_registry_uses_globals() -> None:
    names = set(available_rules())
    assert {"rule_blacklisted_ip", "rule_critical_event"} <= names
    assert len(get_rules(["rule_critical_event"])) == 1
    with pytest.raises(RuleEngineError):
        get_rules(["rule_inexistante"])


def test_audit_report_from_globals_and_locals(tmp_path: Path) -> None:
    local_value = [1, 2, 3]  # noqa: F841 - doit apparaître dans locals()
    report = build_audit_report(test_globals=globals(),
                                test_locals=locals())
    local_vars = report["scopes"]["test_locals"]["variables"]
    assert local_vars["local_value"]["type"] == "list"
    assert local_vars["local_value"]["length"] == 3
    assert "make_record" in report["scopes"]["test_globals"]["variables"]
    assert "scopes" in report["audit_function_locals"]

    path = export_audit_report(tmp_path / "audit.json", scope=locals())
    assert json.loads(path.read_text(encoding="utf-8"))["scopes"]
