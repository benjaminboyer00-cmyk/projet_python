"""
Module 3 : statistiques sur les logs.

Les statistiques sont calculées en un seul parcours du flux. On ne garde en
mémoire que les compteurs et les ensembles d'IP : leur taille dépend du nombre
d'IP différentes, pas du nombre de lignes.
"""

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime

from logstream.config import ANONYMOUS_USER, ERROR_LEVELS
from logstream.models import ConnectionMeta, LogRecord


class TrafficStatistics:
    """Regroupe tous les compteurs calculés sur un flux de logs."""

    def __init__(self) -> None:
        self.total_records = 0

        # defaultdict(int) : une clé inconnue vaut 0 automatiquement. On
        # peut donc écrire compteur[cle] += 1 sans risquer de KeyError.
        self.by_level: defaultdict[str, int] = defaultdict(int)
        self.by_category: defaultdict[str, int] = defaultdict(int)
        self.by_user: defaultdict[str, int] = defaultdict(int)
        self.by_format: defaultdict[str, int] = defaultdict(int)
        self.by_hour: defaultdict[str, int] = defaultdict(int)
        self.errors_by_ip: defaultdict[str, int] = defaultdict(int)

        # Un set ne garde chaque valeur qu'une seule fois : on obtient
        # directement les IP uniques.
        self.active_ips: set[str] = set()
        self.error_ips: set[str] = set()
        self.connections: set[ConnectionMeta] = set()

        self.first_timestamp: datetime | None = None
        self.last_timestamp: datetime | None = None

    def update(self, record: LogRecord) -> None:
        """Ajoute un log aux statistiques."""
        ip = record["ip"]
        timestamp = record["timestamp"]

        self.total_records += 1
        self.by_level[record["level"]] += 1
        self.by_category[record["category"]] += 1
        self.by_user[record["user_id"] or ANONYMOUS_USER] += 1
        self.by_format[record["origin_format"]] += 1
        self.by_hour[f"{timestamp:%H}h"] += 1

        self.active_ips.add(ip)
        # Le tuple (ip, port, protocole) est immuable, donc accepté par un set.
        self.connections.add(record["source"])
        if record["level"] in ERROR_LEVELS:
            self.error_ips.add(ip)
            self.errors_by_ip[ip] += 1

        # On compare car plusieurs fichiers sont lus à la suite : les dates
        # ne sont pas forcément dans l'ordre sur l'ensemble du flux.
        if self.first_timestamp is None or timestamp < self.first_timestamp:
            self.first_timestamp = timestamp
        if self.last_timestamp is None or timestamp > self.last_timestamp:
            self.last_timestamp = timestamp


def collect_statistics(records: Iterable[LogRecord]) -> TrafficStatistics:
    """Parcourt le flux une seule fois et remplit les statistiques."""
    stats = TrafficStatistics()
    for record in records:
        stats.update(record)
    return stats


def compare_ip_sets(
    active_ips: set[str],
    blacklist: frozenset[str],
) -> dict[str, frozenset[str]]:
    """Fait les opérations d'ensembles entre IP actives et liste noire."""
    active = frozenset(active_ips)
    return {
        "union": active | blacklist,  # dans l'un ou dans l'autre
        "intersection": active & blacklist,  # blacklistées et actives
        "active_not_blacklisted": active - blacklist,  # actives seulement
        "blacklisted_inactive": blacklist - active,  # blacklistées seulement
        "symmetric_difference": active ^ blacklist,  # dans un seul des deux
    }


def analyze_error_ips(
    error_ips: set[str], blacklist: frozenset[str]
) -> dict[str, frozenset[str]]:
    """Sépare les IP en erreur : déjà connues ou à surveiller."""
    return {
        "known_threats": frozenset(error_ips & blacklist),
        "blacklist_candidates": frozenset(error_ips - blacklist),
    }


def top_n(counter: dict[str, int], n: int = 5) -> list[tuple[str, int]]:
    """Renvoie les n clés qui ont les plus grandes valeurs."""
    # counter.items() donne des couples (clé, valeur). La lambda indique à
    # sorted de trier selon la valeur, c'est-à-dire pair[1].
    ranked = sorted(counter.items(), key=lambda pair: pair[1], reverse=True)
    return ranked[:n]
