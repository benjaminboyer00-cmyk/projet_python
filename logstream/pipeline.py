"""
Module 2 - Pipeline de transformation & programmation fonctionnelle.

Le pipeline est une chaîne d'itérateurs **paresseux** construite avec
``map()`` et ``filter()`` :

Les étapes, dans l'ordre :

1. ``map(strip)`` nettoie les espaces en début et fin de ligne ;
2. ``filter(None)`` retire les lignes vides ;
3. ``filter(lambda)`` retire les commentaires ;
4. ``map(decode_line)`` transforme chaque ligne en chaîne, dictionnaire
   ou tuple selon son format ;
5. ``map(route_entry)`` aiguille chaque entrée avec un match-case et
   renvoie un ``LogRecord`` ou ``None`` si l'entrée est illisible ;
6. ``filter(None)`` retire ces entrées illisibles ;
7. ``filter(is_valid_record)`` applique les prédicats de validation ;
8. ``map(normalize_record)`` normalise l'enregistrement et construit
   son message avec une f-string.

Rien n'est calculé lors de la construction : chaque enregistrement
traverse toute la chaîne au moment où le consommateur le demande. La
mémoire utilisée reste donc constante quelle que soit la taille des
données.
"""

import json
import logging
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from functools import reduce
from typing import Any, TypeVar, cast

from logstream.config import ANONYMOUS_USER, COMMENT_PREFIX, VALID_LEVELS
from logstream.exceptions import LogParseError
from logstream.models import LogRecord, Payload, RawEntry
from logstream.parsing import (
    decode_line,
    parse_connection_tuple,
    parse_dict_entry,
    parse_text_line,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


# --------------------------------------------------------------------------
# Métriques du pipeline
# --------------------------------------------------------------------------
@dataclass
class PipelineMetrics:
    """Compteurs mis à jour au fil de l'eau pendant la consommation.

    Comme le pipeline est paresseux, les compteurs ne sont complets
    qu'une fois l'itérateur entièrement consommé.
    """

    counters: defaultdict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )

    @property
    def rejected(self) -> int:
        """Nombre d'entrées non vides écartées (parsing ou validation)."""
        return (self.counters["non_empty_entries"]
                - self.counters["valid_records"])

    def as_dict(self) -> dict[str, int]:
        """Copie des compteurs sous forme de dictionnaire simple."""
        return {**self.counters, "rejected": self.rejected}


def count_items(iterable: Iterable[T], metrics: PipelineMetrics,
                key: str) -> Iterator[T]:
    """Générateur "espion" : compte les éléments sans les modifier."""
    for item in iterable:
        metrics.counters[key] += 1
        yield item


# --------------------------------------------------------------------------
# Routage par Structural Pattern Matching
# --------------------------------------------------------------------------
def route_entry(entry: RawEntry) -> LogRecord | None:
    """Route une entrée vers le bon parseur selon son format.

    Le ``match-case`` remplace une cascade de ``if isinstance(...)``
    et permet en plus de vérifier la *forme* des données (clés d'un
    dictionnaire, longueur et types d'un tuple).

    Returns:
        Le ``LogRecord`` parsé, ou ``None`` si l'entrée est invalide
        (elle sera ensuite écartée par ``filter(None, ...)``).
    """
    try:
        match entry:
            # 1. Chaîne brute
            case str() as line if line.strip():
                return parse_text_line(line)

            # 2. Dictionnaire d'erreur applicative {'level':..,'code':..}
            case {"level": str(), "code": int()}:
                return parse_dict_entry(cast(dict[str, Any], entry))

            # 2bis. Dictionnaire générique contenant au moins une IP
            case {"level": str(), "ip": str()}:
                return parse_dict_entry(cast(dict[str, Any], entry))

            # 3. Tuple de connexion horodaté (ts, ip, port, protocole)
            case ((str() | datetime()) as ts, str() as ip,
                  int() as port, str() as proto):
                return parse_connection_tuple(ts, ip, port, proto)

            # 3bis. Tuple de métadonnées seul (ip, port, protocole)
            case (str() as ip, int() as port, str() as proto):
                return parse_connection_tuple(datetime.now(), ip, port,
                                              proto)

            case _:
                logger.debug("Format non reconnu : %r", entry)
                return None
    except LogParseError as exc:
        logger.debug("Entrée rejetée : %s", exc)
        return None


# --------------------------------------------------------------------------
# Filtrage
# --------------------------------------------------------------------------
# Prédicats de validation : des fonctions anonymes stockées dans un
# tuple (les fonctions sont des objets de première classe).
VALIDATORS: tuple[Callable[[LogRecord], bool], ...] = (
    lambda record: record["level"].strip().upper() in VALID_LEVELS,
    lambda record: not record["ip"].startswith("0."),
    lambda record: record["timestamp"].year >= 2000,
)


def is_valid_record(record: LogRecord) -> bool:
    """Vrai si l'enregistrement satisfait tous les prédicats."""
    return all(map(lambda check: check(record), VALIDATORS))


def is_comment(entry: RawEntry) -> bool:
    """Vrai si l'entrée est une ligne de commentaire."""
    return isinstance(entry, str) and entry.startswith(COMMENT_PREFIX)


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------
def clean_text(text: str) -> str:
    """Supprime les espaces superflus (début, fin et multiples)."""
    return " ".join(text.split())


def clean_payload(payload: Payload) -> Payload:
    """Nettoie le payload : clés en minuscules, chaînes nettoyées."""
    if isinstance(payload, str):
        return clean_text(payload)
    return {
        str(key).strip().lower():
            clean_text(value) if isinstance(value, str) else value
        for key, value in payload.items()
    }


def summarize_payload(payload: Payload) -> str:
    """Résumé lisible du payload (utilisé dans le message final)."""
    match payload:
        case {"method": method, "path": path, "status": status}:
            return f"{method} {path} (statut {status})"
        case {"event": "login", "status": status}:
            return f"login {status}"
        case {"event": "connection", "port": port}:
            return f"connexion entrante sur le port {port}"
        case {"code": code, "message": text}:
            return f"code {code} : {text}"
        case str() as text:
            return text[:80]
        case _:
            return json.dumps(payload, ensure_ascii=False)[:80]


def normalize_record(record: LogRecord) -> LogRecord:
    """Normalise un enregistrement (sans modifier l'original).

    * niveau et protocole en MAJUSCULES ;
    * identifiant utilisateur en minuscules ;
    * payload nettoyé ;
    * construction d'un message formaté par f-string.
    """
    level = record["level"].strip().upper()
    ip, port, protocol = record["source"]
    source = (ip, port, protocol.strip().upper())
    user_id = record["user_id"].strip().lower() if record["user_id"] else None
    payload = clean_payload(record["payload"])

    message = (
        f"[{record['timestamp']:%Y-%m-%d %H:%M:%S}] {level:<8} "
        f"{ip:>15}:{port:<5} {source[2]:<5} "
        f"user={user_id or ANONYMOUS_USER:<10} "
        f"{record['category']:<7} {summarize_payload(payload)}"
    )
    return {
        **record,
        "level": level,
        "source": source,
        "user_id": user_id,
        "payload": payload,
        "message": message,
    }


# --------------------------------------------------------------------------
# Assemblage du pipeline
# --------------------------------------------------------------------------
def strip_entry(entry: RawEntry) -> RawEntry:
    """Nettoie les entrées texte, laisse les autres formats intacts."""
    return entry.strip() if isinstance(entry, str) else entry


def decode_entry(entry: RawEntry) -> RawEntry:
    """Décode les lignes texte (JSON / CONN), laisse le reste intact."""
    return decode_line(entry) if isinstance(entry, str) else entry


def build_pipeline(
    entries: Iterable[RawEntry],
    metrics: PipelineMetrics | None = None,
) -> Iterator[LogRecord]:
    """Construit la chaîne paresseuse de transformations.

    Args:
        entries: itérable d'entrées brutes (lignes, dict, tuples).
        metrics: objet de métriques à alimenter (optionnel).

    Returns:
        Un itérateur de ``LogRecord`` valides et normalisés.
    """
    metrics = metrics if metrics is not None else PipelineMetrics()

    counted = count_items(entries, metrics, "raw_entries")
    non_empty: Iterator[RawEntry] = filter(None, map(strip_entry, counted))
    no_comment: Iterator[RawEntry] = filter(
        lambda entry: not is_comment(entry), non_empty
    )
    decoded = map(decode_entry,
                  count_items(no_comment, metrics, "non_empty_entries"))
    routed = filter(None, map(route_entry, decoded))
    parsed = count_items(routed, metrics, "parsed_records")
    valid = filter(is_valid_record, parsed)
    normalized = map(normalize_record, valid)
    return count_items(normalized, metrics, "valid_records")


def chain_transforms(
    records: Iterable[Any], *transforms: Callable[[Iterable[Any]], Any]
) -> Any:
    """Applique une suite de transformations d'itérables (composition).

    Exemple::

        chain_transforms(records,
                         lambda it: filter(lambda r: r["ip"], it),
                         lambda it: map(lambda r: r["level"], it))

    ``functools.reduce`` passe le résultat de chaque transformation à la
    suivante : les fonctions sont manipulées comme des données.
    """
    return reduce(lambda acc, transform: transform(acc), transforms, records)
