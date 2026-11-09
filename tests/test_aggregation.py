"""Tests du module 3 : ensembles et defaultdict."""

from logstream.aggregation import (
    analyze_error_ips,
    collect_statistics,
    compare_ip_sets,
    top_n,
)

from conftest import make_record


def test_collect_statistics_counts_and_sets() -> None:
    """Les compteurs et les ensembles d'IP sont bien remplis."""
    records = [
        make_record(ip="1.1.1.1", level="ERROR"),
        make_record(ip="1.1.1.1", level="CRITICAL", user=None),
        make_record(ip="2.2.2.2", level="INFO"),
    ]
    stats = collect_statistics(iter(records))

    assert stats.total_records == 3
    assert stats.by_level["ERROR"] == 1
    assert stats.by_level["WARNING"] == 0  # defaultdict : pas de KeyError
    assert stats.by_user == {"alice": 2, "anonymous": 1}
    assert stats.active_ips == {"1.1.1.1", "2.2.2.2"}
    assert stats.error_ips == {"1.1.1.1"}
    assert stats.errors_by_ip["1.1.1.1"] == 2
    assert ("2.2.2.2", 22, "SSH") in stats.connections


def test_compare_ip_sets_operations() -> None:
    """Vérifie les opérations | & - et ^."""
    active = {"a", "b", "c"}
    blacklist = frozenset({"c", "d"})
    result = compare_ip_sets(active, blacklist)

    assert result["union"] == {"a", "b", "c", "d"}
    assert result["intersection"] == {"c"}
    assert result["active_not_blacklisted"] == {"a", "b"}
    assert result["blacklisted_inactive"] == {"d"}
    assert result["symmetric_difference"] == {"a", "b", "d"}


def test_analyze_error_ips() -> None:
    """Les IP en erreur sont séparées selon la liste noire."""
    result = analyze_error_ips({"x", "y"}, frozenset({"y", "z"}))
    assert result == {"known_threats": {"y"},
                      "blacklist_candidates": {"x"}}


def test_top_n() -> None:
    """top_n renvoie les clés les plus fréquentes, triées."""
    assert top_n({"a": 3, "b": 2, "c": 1}, 2) == [("a", 3), ("b", 2)]
