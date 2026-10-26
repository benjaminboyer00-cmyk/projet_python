"""Tests du Module 1 : générateurs et parsing."""

import inspect
from datetime import datetime
from pathlib import Path

import pytest

from logstream.exceptions import LogParseError
from logstream.ingestion import (
    load_blacklist,
    read_log_file,
    read_log_sources,
    read_streams,
)
from logstream.parsing import (
    categorize,
    decode_line,
    parse_dict_entry,
    parse_source,
    parse_text_line,
    parse_timestamp,
)


def test_read_log_file_is_lazy_generator(sample_log_file: Path) -> None:
    lines = read_log_file(sample_log_file)
    assert inspect.isgenerator(lines)
    assert next(lines).startswith("2026-10-20T08:00:00")


def test_read_log_file_missing_file_yields_nothing(tmp_path: Path) -> None:
    assert list(read_log_file(tmp_path / "absent.log")) == []


def test_read_log_sources_chains_files(tmp_path: Path) -> None:
    first, second = tmp_path / "a.log", tmp_path / "b.log"
    first.write_text("1\n2\n", encoding="utf-8")
    second.write_text("3\n", encoding="utf-8")
    assert list(read_log_sources([first, second])) == ["1", "2", "3"]


def test_read_streams_accepts_heterogeneous_iterables() -> None:
    merged = read_streams(["a"], iter([{"k": 1}]), ((1, 2),))
    assert list(merged) == ["a", {"k": 1}, (1, 2)]


def test_load_blacklist_returns_frozenset(tmp_path: Path) -> None:
    path = tmp_path / "bl.txt"
    path.write_text("# titre\n1.1.1.1\n\n2.2.2.2  # note\n",
                    encoding="utf-8")
    blacklist = load_blacklist(path)
    assert isinstance(blacklist, frozenset)
    assert blacklist == {"1.1.1.1", "2.2.2.2"}


def test_parse_text_line_builds_typed_dict() -> None:
    record = parse_text_line(
        "2026-10-20T08:00:00 | ERROR | 10.0.0.2:443/TCP | bob | "
        '{"code": 500, "message": "x"}'
    )
    assert record["timestamp"] == datetime(2026, 10, 20, 8, 0, 0)
    assert record["source"] == ("10.0.0.2", 443, "TCP")
    assert isinstance(record["source"], tuple)
    assert record["payload"] == {"code": 500, "message": "x"}
    assert record["category"] == "HTTP"


def test_parse_text_line_keeps_raw_payload() -> None:
    record = parse_text_line(
        "2026-10-20T08:00:00 | INFO | 10.0.0.2:0/UDP | - | Disque plein"
    )
    assert record["payload"] == "Disque plein"
    assert record["user_id"] is None
    assert record["category"] == "SYSTEM"


@pytest.mark.parametrize("line", [
    "pas assez | de champs",
    "2026-99-99 | INFO | 10.0.0.2:80/TCP | - | x",
    "2026-10-20T08:00:00 | INFO | 300.0.0.1:80/TCP | - | x",
    "2026-10-20T08:00:00 | INFO | 10.0.0.2:99999/TCP | - | x",
    "2026-10-20T08:00:00 | INFO | 10.0.0.2-80-TCP | - | x",
])
def test_parse_text_line_rejects_malformed(line: str) -> None:
    with pytest.raises(LogParseError):
        parse_text_line(line)


def test_parse_dict_entry_missing_key() -> None:
    with pytest.raises(LogParseError):
        parse_dict_entry({"level": "ERROR"})


def test_parse_source_supports_ipv6() -> None:
    assert parse_source("::1:8080/TCP") == ("::1", 8080, "TCP")


def test_parse_timestamp_accepts_datetime() -> None:
    now = datetime.now()
    assert parse_timestamp(now) is now


@pytest.mark.parametrize("line, expected_type", [
    ('{"level": "INFO", "ip": "1.1.1.1"}', dict),
    ("CONN 2026-10-20T08:00:00 1.1.1.1 22 TCP", tuple),
    ("texte libre", str),
    ("{json cassé", str),
])
def test_decode_line_detects_format(line: str, expected_type: type) -> None:
    assert isinstance(decode_line(line), expected_type)


def test_categorize() -> None:
    assert categorize({"event": "login", "status": "failed"}) == "AUTH"
    assert categorize({"event": "connection", "port": 22}) == "NETWORK"
    assert categorize({"foo": "bar"}) == "OTHER"
