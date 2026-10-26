"""Tests du Module 3 : détection de force brute."""

import pytest

from logstream.detection import detect_brute_force

from conftest import login, make_record


def test_detects_consecutive_failures() -> None:
    events = [login("6.6.6.6", "failed", s) for s in range(5)]
    result = detect_brute_force(events, threshold=5)
    assert len(result.alerts) == 1
    assert result.alerts[0].ip == "6.6.6.6"
    assert result.alerts[0].attempts == 5
    assert result.complete


def test_success_resets_the_streak() -> None:
    events = ([login("6.6.6.6", "failed", s) for s in range(4)]
              + [login("6.6.6.6", "success", 5)]
              + [login("6.6.6.6", "failed", s) for s in range(6, 10)])
    assert detect_brute_force(events, threshold=5).alerts == []


def test_failures_too_far_apart_are_not_consecutive() -> None:
    events = [login("6.6.6.6", "failed", s * 600) for s in range(10)]
    result = detect_brute_force(events, threshold=3, window_seconds=300)
    assert result.alerts == []


def test_only_one_alert_per_streak() -> None:
    events = [login("6.6.6.6", "failed", s) for s in range(20)]
    assert len(detect_brute_force(events, threshold=5).alerts) == 1


def test_non_auth_events_are_skipped() -> None:
    events = [make_record(), login("1.1.1.1", "failed", 1)]
    result = detect_brute_force(events, threshold=2)
    assert result.processed_events == 2
    assert result.auth_events == 1


def test_cycles_and_else_clause() -> None:
    events = [make_record() for _ in range(10)]
    result = detect_brute_force(events, batch_size=3)
    assert result.completed_cycles == 4  # 3 + 3 + 3 + 1
    assert result.complete


def test_break_on_max_alerts_marks_incomplete() -> None:
    events = [login(f"6.6.6.{i}", "failed", s)
              for i in range(5) for s in range(3)]
    result = detect_brute_force(events, threshold=3, max_alerts=2)
    assert len(result.alerts) == 2
    assert not result.complete
    assert result.processed_events < len(events)


@pytest.mark.parametrize("kwargs", [{"threshold": 1}, {"batch_size": 0}])
def test_invalid_parameters(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        detect_brute_force([], **kwargs)
