"""Tests du module 2 : pipeline et match-case."""

from collections import defaultdict
from datetime import datetime
from pathlib import Path

from logstream.ingestion import read_log_file
from logstream.pipeline import (
    build_pipeline,
    is_valid_record,
    normalize_record,
    route_entry,
)

from conftest import make_record


def test_route_entry_raw_string() -> None:
    """Une chaîne est traitée comme une ligne de texte."""
    record = route_entry(
        "2026-10-20T08:00:00 | INFO | 10.0.0.2:80/TCP | - | ok"
    )
    assert record is not None
    assert record["origin_format"] == "raw"


def test_route_entry_error_dict() -> None:
    """Un dictionnaire est routé vers parse_dict_entry."""
    record = route_entry({"timestamp": "2026-10-20T08:00:00",
                          "level": "ERROR", "code": 503,
                          "ip": "10.0.0.1"})
    assert record is not None
    assert record["origin_format"] == "dict"
    assert record["payload"] == {"code": 503}


def test_route_entry_connection_tuple() -> None:
    """Un tuple à 4 éléments est une connexion."""
    record = route_entry((datetime(2026, 1, 1), "10.0.0.1", 22, "TCP"))
    assert record is not None
    assert record["source"] == ("10.0.0.1", 22, "TCP")
    assert record["category"] == "NETWORK"


def test_route_entry_unknown_or_invalid_returns_none() -> None:
    """Tout ce qui est illisible donne None, sans exception."""
    assert route_entry(42) is None
    assert route_entry("") is None
    assert route_entry(("10.0.0.1", "pas un port", "TCP")) is None
    assert route_entry("ligne corrompue") is None


def test_is_valid_record_rejects_unknown_level() -> None:
    """Un niveau inconnu est refusé par les validateurs."""
    assert is_valid_record(make_record(level="INFO"))
    assert not is_valid_record(make_record(level="DEBUGX"))


def test_normalize_record_does_not_mutate_input() -> None:
    """La normalisation renvoie un nouveau log et garde l'original."""
    original = make_record(level=" warning ", user="  Alice ",
                           protocol="ssh", payload="  a   b  ")
    normalized = normalize_record(original)
    assert normalized["level"] == "WARNING"
    assert normalized["user_id"] == "alice"
    assert normalized["source"][2] == "SSH"
    assert normalized["payload"] == "a b"
    assert " alice " in normalized["message"]
    assert original["level"] == " warning "  # l'original n'a pas changé


def test_build_pipeline_end_to_end(sample_log_file: Path) -> None:
    """Test complet du pipeline sur un petit fichier."""
    metrics: defaultdict[str, int] = defaultdict(int)
    records = list(build_pipeline(read_log_file(sample_log_file), metrics))

    formats = sorted(record["origin_format"] for record in records)
    assert formats == ["dict", "raw", "raw", "tuple"]
    critical = [r for r in records if r["level"] == "CRITICAL"]
    assert critical[0]["user_id"] == "carol"
    assert critical[0]["payload"] == "Disque plein"

    assert metrics["raw_entries"] == 8
    assert metrics["non_empty_entries"] == 6
    assert metrics["valid_records"] == 4


def test_build_pipeline_is_lazy() -> None:
    """Le pipeline ne lit une ligne que lorsqu'on la demande."""
    consumed: list[int] = []

    def source():
        for i in range(1000):
            consumed.append(i)
            yield f"2026-10-20T08:00:00 | INFO | 10.0.0.2:80/TCP | - | {i}"

    pipeline = build_pipeline(source())
    assert consumed == []  # rien n'est lu à la construction
    next(pipeline)
    assert len(consumed) == 1
