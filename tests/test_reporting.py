"""Tests de l'export JSON."""

import json
from datetime import datetime

from logstream.aggregation import collect_statistics
from logstream.reporting import to_jsonable

from conftest import make_record


def test_to_jsonable_handles_statistics_object() -> None:
    """Un objet TrafficStatistics devient un dictionnaire JSON valide."""
    stats = collect_statistics([make_record(level="ERROR")])
    data = to_jsonable(stats)
    assert data["by_level"] == {"ERROR": 1}
    assert data["connections"] == [["10.0.0.5", 22, "SSH"]]
    json.dumps(data)  # ne doit pas lever d'exception


def test_to_jsonable_converts_sets_tuples_and_dates() -> None:
    """Les set, tuples et dates sont convertis."""
    value = {"s": frozenset({"b", "a"}), "t": (1, 2),
             "d": datetime(2026, 1, 1)}
    assert to_jsonable(value) == {"s": ["a", "b"], "t": [1, 2],
                                  "d": "2026-01-01T00:00:00"}
