"""Tests du Module 2 : pipeline fonctionnel et match-case."""

from datetime import datetime
from pathlib import Path

from logstream.ingestion import read_log_file
from logstream.pipeline import (
    PipelineMetrics,
    build_pipeline,
    chain_transforms,
    is_valid_record,
    normalize_record,
    route_entry,
)

from conftest import make_record


def test_route_entry_raw_string() -> None:
    record = route_entry(
        "2026-10-20T08:00:00 | INFO | 10.0.0.2:80/TCP | - | ok"
    )
    assert record is not None
    assert record["origin_format"] == "raw"


def test_route_entry_error_dict() -> None:
    record = route_entry({"timestamp": "2026-10-20T08:00:00",
                          "level": "ERROR", "code": 503,
                          "ip": "10.0.0.1"})
    assert record is not None
    assert record["origin_format"] == "dict"
    assert record["payload"] == {"code": 503}


def test_route_entry_connection_tuples() -> None:
    with_ts = route_entry((datetime(2026, 1, 1), "10.0.0.1", 22, "TCP"))
    without_ts = route_entry(("10.0.0.1", 443, "TCP"))
    assert with_ts is not None and without_ts is not None
    assert with_ts["source"] == ("10.0.0.1", 22, "TCP")
    assert without_ts["category"] == "NETWORK"


def test_route_entry_unknown_or_invalid_returns_none() -> None:
    assert route_entry(42) is None  # type: ignore[arg-type]
    assert route_entry("") is None
    assert route_entry(("10.0.0.1", "pas un port", "TCP")) is None
    assert route_entry("ligne corrompue") is None


def test_is_valid_record_rejects_unknown_level() -> None:
    assert is_valid_record(make_record(level="INFO"))
    assert not is_valid_record(make_record(level="DEBUGX"))


def test_normalize_record_does_not_mutate_input() -> None:
    original = make_record(level=" warning ", user="  Alice ",
                           protocol="ssh", payload="  a   b  ")
    normalized = normalize_record(original)
    assert normalized["level"] == "WARNING"
    assert normalized["user_id"] == "alice"
    assert normalized["source"][2] == "SSH"
    assert normalized["payload"] == "a b"
    assert "user=alice" in normalized["message"]
    assert original["level"] == " warning "  # original intact


def test_build_pipeline_end_to_end(sample_log_file: Path) -> None:
    metrics = PipelineMetrics()
    records = list(build_pipeline(read_log_file(sample_log_file), metrics))

    formats = sorted(record["origin_format"] for record in records)
    assert formats == ["dict", "raw", "raw", "tuple"]
    critical = [r for r in records if r["level"] == "CRITICAL"]
    assert critical[0]["user_id"] == "carol"
    assert critical[0]["payload"] == "Disque plein"

    assert metrics.counters["raw_entries"] == 8
    assert metrics.counters["non_empty_entries"] == 6
    assert metrics.counters["valid_records"] == 4
    assert metrics.rejected == 2


def test_build_pipeline_is_lazy() -> None:
    consumed: list[int] = []

    def source():
        for i in range(1000):
            consumed.append(i)
            yield f"2026-10-20T08:00:00 | INFO | 10.0.0.2:80/TCP | - | {i}"

    pipeline = build_pipeline(source())
    assert consumed == []  # rien n'est lu à la construction
    next(pipeline)
    assert len(consumed) == 1


def test_chain_transforms_composes_functions() -> None:
    result = chain_transforms(
        range(10),
        lambda it: filter(lambda x: x % 2 == 0, it),
        lambda it: map(lambda x: x * 10, it),
        list,
    )
    assert result == [0, 20, 40, 60, 80]
