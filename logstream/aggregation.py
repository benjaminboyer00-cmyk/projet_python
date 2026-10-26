"""
Module 3 - Agrégation & traitement de données avancé.

* Ensembles (``set``) : IP actives, IP ayant généré des erreurs,
  connexions uniques (des tuples, donc hachables).
* Opérations ensemblistes (``|``, ``&``, ``-``, ``^``) entre les IP
  actives et la liste noire (``frozenset`` immuable).
* Accumulation dynamique avec ``collections.defaultdict`` : aucun risque
  de ``KeyError`` lors de l'incrément d'une clé encore inconnue.

Toutes les statistiques sont calculées en **un seul passage** sur
l'itérateur : seuls les compteurs et les ensembles d'IP (dont la taille
dépend du nombre d'IP distinctes, pas du nombre de lignes) sont gardés
en mémoire.
"""

from collections import defaultdict
from collections.abc import Callable, Hashable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar

from logstream.config import ANONYMOUS_USER, ERROR_LEVELS
from logstream.models import ConnectionMeta, LogRecord

K = TypeVar("K", bound=Hashable)


def _counter() -> defaultdict[str, int]:
    """Fabrique de compteur (utilisée comme ``default_factory``)."""
    return defaultdict(int)


@dataclass
class TrafficStatistics:
    """Résultat de l'agrégation d'un flux de logs."""

    total_records: int = 0
    by_level: defaultdict[str, int] = field(default_factory=_counter)
    by_category: defaultdict[str, int] = field(default_factory=_counter)
    by_user: defaultdict[str, int] = field(default_factory=_counter)
    by_format: defaultdict[str, int] = field(default_factory=_counter)
    by_hour: defaultdict[str, int] = field(default_factory=_counter)
    errors_by_ip: defaultdict[str, int] = field(default_factory=_counter)
    active_ips: set[str] = field(default_factory=set)
    error_ips: set[str] = field(default_factory=set)
    connections: set[ConnectionMeta] = field(default_factory=set)
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None

    def update(self, record: LogRecord) -> None:
        """Intègre un enregistrement dans les statistiques."""
        ip = record["ip"]
        timestamp = record["timestamp"]

        self.total_records += 1
        self.by_level[record["level"]] += 1
        self.by_category[record["category"]] += 1
        self.by_user[record["user_id"] or ANONYMOUS_USER] += 1
        self.by_format[record["origin_format"]] += 1
        self.by_hour[f"{timestamp:%H}h"] += 1

        self.active_ips.add(ip)
        self.connections.add(record["source"])
        if record["level"] in ERROR_LEVELS:
            self.error_ips.add(ip)
            self.errors_by_ip[ip] += 1

        if self.first_timestamp is None or timestamp < self.first_timestamp:
            self.first_timestamp = timestamp
        if self.last_timestamp is None or timestamp > self.last_timestamp:
            self.last_timestamp = timestamp


def collect_statistics(records: Iterable[LogRecord]) -> TrafficStatistics:
    """Consomme le flux une seule fois et agrège les statistiques."""
    stats = TrafficStatistics()
    for record in records:
        stats.update(record)
    return stats


def compare_ip_sets(
    active_ips: set[str] | frozenset[str],
    blacklist: frozenset[str],
) -> dict[str, frozenset[str]]:
    """Opérations ensemblistes entre IP actives et liste noire.

    Returns:
        Un dictionnaire de ``frozenset`` :

        * ``union``                  : actives | blacklist
        * ``intersection``           : actives & blacklist
                                       (IP blacklistées encore actives !)
        * ``active_not_blacklisted`` : actives - blacklist
        * ``blacklisted_inactive``   : blacklist - actives
        * ``symmetric_difference``   : actives ^ blacklist
    """
    active = frozenset(active_ips)
    return {
        "union": active | blacklist,
        "intersection": active & blacklist,
        "active_not_blacklisted": active - blacklist,
        "blacklisted_inactive": blacklist - active,
        "symmetric_difference": active ^ blacklist,
    }


def analyze_error_ips(
    error_ips: set[str], blacklist: frozenset[str]
) -> dict[str, frozenset[str]]:
    """Croise les IP en erreur avec la liste noire.

    Returns:
        * ``known_threats``         : IP en erreur déjà blacklistées ;
        * ``blacklist_candidates``  : IP en erreur non blacklistées
          (candidates à un ajout dans la liste noire).
    """
    return {
        "known_threats": frozenset(error_ips & blacklist),
        "blacklist_candidates": frozenset(error_ips - blacklist),
    }


def count_by(
    records: Iterable[Any], key_func: Callable[[Any], K]
) -> defaultdict[K, int]:
    """Compte les éléments selon une clé calculée par ``key_func``.

    ``key_func`` est une fonction passée en argument (souvent une
    lambda), par exemple ``count_by(records, lambda r: r["ip"])``.
    """
    counts: defaultdict[K, int] = defaultdict(int)
    for item in records:
        counts[key_func(item)] += 1
    return counts


def top_n(counter: Mapping[K, int], n: int = 5) -> list[tuple[K, int]]:
    """Renvoie les ``n`` clés les plus fréquentes (tri par lambda)."""
    return sorted(counter.items(), key=lambda pair: pair[1],
                  reverse=True)[:n]
