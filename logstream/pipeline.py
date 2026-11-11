"""
Module 2 : pipeline de transformation.

Le pipeline est une chaîne de map() et de filter(). Ces deux fonctions sont
"paresseuses" : elles ne calculent rien tant qu'on ne leur demande pas
d'élément. Chaque log traverse donc toute la chaîne, seul, au moment où on le
lit, et la mémoire utilisée ne dépend pas de la taille des fichiers.
"""

import json
import logging
from collections import defaultdict
from collections.abc import Iterable, Iterator
from typing import Any

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


def count_items(items: Iterable[Any], metrics: defaultdict[str, int],
                key: str) -> Iterator[Any]:
    """Générateur "espion" : compte les éléments sans les modifier."""
    for item in items:
        metrics[key] += 1
        yield item


# --- Routage avec match-case -------------------------------------------------

def route_entry(entry: Any) -> LogRecord | None:
    """Envoie une entrée vers le bon parseur selon son format.

    Renvoie le log parsé, ou None si l'entrée est illisible.
    """
    try:
        match entry:
            # 1. Chaîne brute.
            case str():
                return parse_text_line(entry)

            # 2. Dictionnaire : erreur applicative ou log JSON avec une IP.
            case {"level": str(), "code": int()} | {"level": str(),
                                                    "ip": str()}:
                return parse_dict_entry(entry)

            # 3. Tuple de connexion : 4 éléments dont les types sont vérifiés.
            case (timestamp, str() as ip, int() as port, str() as protocol):
                return parse_connection_tuple(timestamp, ip, port, protocol)

            # Tout le reste est un format inconnu.
            case _:
                return None
    except LogParseError as error:
        # On ne veut pas planter sur une mauvaise ligne : on renvoie None et
        # filter(None, ...) la retirera du flux.
        logger.debug("Entrée rejetée : %s", error)
        return None


# --- Filtrage ----------------------------------------------------------------

# Conditions qu'un log doit respecter. Des fonctions peuvent être rangées dans
# un tuple comme n'importe quelle valeur : ce sont des objets "de première
# classe".
VALIDATORS = (
    lambda record: record["level"].strip().upper() in VALID_LEVELS,
    lambda record: not record["ip"].startswith("0."),
    lambda record: record["timestamp"].year >= 2000,
)


def is_valid_record(record: LogRecord) -> bool:
    """Vrai si le log respecte toutes les conditions de VALIDATORS."""
    return all(map(lambda check: check(record), VALIDATORS))


def is_comment(entry: RawEntry) -> bool:
    """Vrai si l'entrée est une ligne de commentaire."""
    return isinstance(entry, str) and entry.startswith(COMMENT_PREFIX)


# --- Normalisation -----------------------------------------------------------

def clean_text(text: str) -> str:
    """Enlève les espaces en trop (début, fin et espaces multiples)."""
    return " ".join(text.split())


def clean_payload(payload: Payload) -> Payload:
    """Nettoie le payload : clés en minuscules et textes sans espaces."""
    if isinstance(payload, str):
        return clean_text(payload)
    return {
        str(key).strip().lower():
            clean_text(value) if isinstance(value, str) else value
        for key, value in payload.items()
    }


def summarize_payload(payload: Payload) -> str:
    """Construit un résumé lisible du payload selon sa forme."""
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
    """Met un log au format standard et construit son message.

    Renvoie un nouveau dictionnaire : le log d'origine n'est pas modifié.
    """
    level = record["level"].strip().upper()
    ip, port, protocol = record["source"]  # décomposition du tuple
    protocol = protocol.strip().upper()
    user_id = record["user_id"].strip().lower() if record["user_id"] else None
    payload = clean_payload(record["payload"])

    # f-string : ":%Y-%m-%d %H:%M:%S" met la date en forme et ":<8"
    # complète le niveau avec des espaces jusqu'à 8 caractères, pour que la
    # suite de la ligne commence toujours au même endroit.
    message = (
        f"[{record['timestamp']:%Y-%m-%d %H:%M:%S}] {level:<8} "
        f"{ip}:{port}/{protocol} {user_id or ANONYMOUS_USER} "
        f"({record['category']}) {summarize_payload(payload)}"
    )
    # {**record, ...} copie le log puis remplace les champs indiqués.
    return {
        **record,
        "level": level,
        "source": (ip, port, protocol),
        "user_id": user_id,
        "payload": payload,
        "message": message,
    }


# --- Assemblage du pipeline --------------------------------------------------

def strip_entry(entry: RawEntry) -> RawEntry:
    """Enlève les espaces autour d'un texte, ne touche pas au reste."""
    return entry.strip() if isinstance(entry, str) else entry


def decode_entry(entry: RawEntry) -> RawEntry:
    """Décode les lignes de texte, ne touche pas aux autres formats."""
    return decode_line(entry) if isinstance(entry, str) else entry


def build_pipeline(
    entries: Iterable[RawEntry],
    metrics: defaultdict[str, int] | None = None,
) -> Iterator[LogRecord]:
    """Construit la chaîne de traitements et renvoie les logs propres.

    metrics est un compteur optionnel, rempli au fur et à mesure de la lecture.
    Ses valeurs ne sont donc complètes qu'à la fin du parcours.
    """
    # "is None" et pas "not metrics" : un compteur vide vaut False, et on
    # perdrait alors celui passé par l'appelant.
    if metrics is None:
        metrics = defaultdict(int)

    # Aucune ligne n'est lue ici : on ne fait que brancher les étapes.
    # Étape 1 : on compte les entrées brutes et on enlève les espaces.
    raw = count_items(entries, metrics, "raw_entries")
    stripped = map(strip_entry, raw)

    # Étape 2 : filter(None, ...) retire tout ce qui est vide, puis on
    # retire les commentaires avec un filter et une lambda.
    non_empty: Iterator[RawEntry] = filter(None, stripped)
    no_comment = filter(lambda entry: not is_comment(entry), non_empty)
    kept = count_items(no_comment, metrics, "non_empty_entries")

    # Étape 3 : chaque ligne devient une chaîne, un dict ou un tuple, puis
    # le match-case choisit le parseur. Les entrées illisibles donnent None.
    decoded = map(decode_entry, kept)
    routed = map(route_entry, decoded)
    parsed = count_items(filter(None, routed), metrics, "parsed_records")

    # Étape 4 : on garde les logs valides et on les normalise.
    valid = filter(is_valid_record, parsed)
    normalized = map(normalize_record, valid)
    return count_items(normalized, metrics, "valid_records")
