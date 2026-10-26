"""
Module 1 - Parsing & modélisation des données.

Transforme chaque entrée brute en un dictionnaire ``LogRecord`` typé :

* horodatage      -> ``datetime``
* niveau          -> ``str`` (INFO, WARNING, ERROR, CRITICAL)
* source          -> ``tuple`` immuable ``(IP, Port, Protocole)``
* utilisateur     -> ``str`` ou ``None``
* payload         -> ``dict`` (JSON décodé) ou ``str`` (chaîne brute)

Trois formats d'entrée sont supportés :

1. Ligne texte ::

    2026-10-20T08:15:32 | INFO | 10.0.0.4:51234/TCP | user012 | {"a": 1}

2. Objet JSON (une ligne ``{...}`` du fichier, ou un ``dict`` en mémoire)
3. Événement de connexion ``CONN <horodatage> <ip> <port> <protocole>``,
   converti en tuple ``(horodatage, ip, port, protocole)``.

Toute erreur de format lève ``LogParseError``.
"""

import ipaddress
import json
from datetime import datetime
from typing import Any

from logstream.config import (
    CONNECTION_PREFIX,
    FIELD_COUNT,
    FIELD_SEPARATOR,
)
from logstream.exceptions import LogParseError
from logstream.models import ConnectionMeta, LogRecord, Payload, RawEntry

# Clés "structurelles" d'une entrée JSON (le reste constitue le payload).
_DICT_BASE_KEYS: frozenset[str] = frozenset(
    {"timestamp", "level", "ip", "port", "protocol", "user"}
)


# --------------------------------------------------------------------------
# Parsing des champs élémentaires
# --------------------------------------------------------------------------
def parse_timestamp(value: Any) -> datetime:
    """Convertit une valeur ISO 8601 (ou un datetime) en ``datetime``."""
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).strip())
    except ValueError as exc:
        raise LogParseError("Horodatage invalide", value) from exc


def parse_ip(value: Any) -> str:
    """Valide une adresse IPv4/IPv6 avec le module standard ``ipaddress``."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise LogParseError("Adresse IP invalide", value) from exc


def parse_port(value: Any) -> int:
    """Convertit un port en entier compris entre 0 et 65535."""
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise LogParseError("Port non numérique", value) from exc
    if not 0 <= port <= 65535:
        raise LogParseError("Port hors limites", value)
    return port


def parse_source(value: str) -> ConnectionMeta:
    """Découpe ``ip:port/protocole`` en tuple ``(ip, port, protocole)``.

    ``rpartition(':')`` est utilisé pour l'IP afin de rester compatible
    avec les adresses IPv6 qui contiennent elles-mêmes des ``:``.
    """
    address, slash, protocol = value.strip().partition("/")
    ip, colon, port = address.rpartition(":")
    if not slash or not colon or not protocol:
        raise LogParseError("Source mal formée (ip:port/proto)", value)
    return (parse_ip(ip), parse_port(port), protocol.strip())


def parse_user(value: Any) -> str | None:
    """Renvoie l'identifiant utilisateur, ou ``None`` s'il est absent."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-") else text


def parse_payload(text: str) -> Payload:
    """Décode le payload JSON ; à défaut, conserve la chaîne brute."""
    text = text.strip()
    if not text.startswith("{"):
        return text
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        return text
    return decoded if isinstance(decoded, dict) else text


def categorize(payload: Payload) -> str:
    """Détermine la catégorie d'un log à partir de son payload."""
    match payload:
        case {"event": "login" | "logout"}:
            return "AUTH"
        case {"method": str(), "status": int()} | {"code": int()}:
            return "HTTP"
        case {"event": "connection"}:
            return "NETWORK"
        case str():
            return "SYSTEM"
        case _:
            return "OTHER"


# --------------------------------------------------------------------------
# Décodage d'une ligne texte vers son format (str / dict / tuple)
# --------------------------------------------------------------------------
def decode_line(line: str) -> RawEntry:
    """Identifie le format d'une ligne texte et la convertit.

    * ``{...}``                     -> ``dict`` (JSON)
    * ``CONN ts ip port proto``     -> ``tuple`` (ts, ip, port, proto)
    * autre                         -> ``str`` inchangée

    Returns:
        L'entrée décodée, prête à être routée par le pipeline.
    """
    stripped = line.strip()
    match stripped.split():
        case [prefix, timestamp, ip, port, protocol] if (
            prefix == CONNECTION_PREFIX and port.isdigit()
        ):
            return (timestamp, ip, int(port), protocol)
        case [first, *_] if first.startswith("{"):
            try:
                decoded = json.loads(stripped)
            except json.JSONDecodeError:
                return stripped
            return decoded if isinstance(decoded, dict) else stripped
        case _:
            return stripped


# --------------------------------------------------------------------------
# Construction des enregistrements
# --------------------------------------------------------------------------
def build_record(
    timestamp: datetime,
    level: str,
    source: ConnectionMeta,
    user_id: str | None,
    payload: Payload,
    origin_format: str,
) -> LogRecord:
    """Assemble le dictionnaire ``LogRecord`` final."""
    return {
        "timestamp": timestamp,
        "level": level,
        "source": source,
        "ip": source[0],
        "user_id": user_id,
        "payload": payload,
        "category": categorize(payload),
        "origin_format": origin_format,
        "message": "",  # rempli lors de la normalisation (Module 2)
    }


def parse_text_line(line: str) -> LogRecord:
    """Parse une ligne texte ``ts | niveau | source | user | payload``."""
    parts = line.split(FIELD_SEPARATOR, maxsplit=FIELD_COUNT - 1)
    if len(parts) != FIELD_COUNT:
        raise LogParseError(
            f"{len(parts)} champ(s) au lieu de {FIELD_COUNT}", line
        )
    timestamp, level, source, user, payload = parts
    return build_record(
        timestamp=parse_timestamp(timestamp),
        level=level.strip(),
        source=parse_source(source),
        user_id=parse_user(user),
        payload=parse_payload(payload),
        origin_format="raw",
    )


def parse_dict_entry(entry: dict[str, Any]) -> LogRecord:
    """Parse un objet JSON (dict) en ``LogRecord``.

    Les clés non structurelles (code, message...) forment le payload.
    """
    try:
        source = (
            parse_ip(entry["ip"]),
            parse_port(entry.get("port", 0)),
            str(entry.get("protocol", "TCP")),
        )
        timestamp = parse_timestamp(entry["timestamp"])
        level = str(entry["level"])
    except KeyError as exc:
        raise LogParseError(f"Clé manquante : {exc}", entry) from exc

    payload = {key: value for key, value in entry.items()
               if key not in _DICT_BASE_KEYS}
    return build_record(
        timestamp=timestamp,
        level=level,
        source=source,
        user_id=parse_user(entry.get("user")),
        payload=payload,
        origin_format="dict",
    )


def parse_connection_tuple(
    timestamp: Any, ip: Any, port: Any, protocol: Any
) -> LogRecord:
    """Parse un événement de connexion ``(ts, ip, port, protocole)``."""
    source: ConnectionMeta = (parse_ip(ip), parse_port(port), str(protocol))
    return build_record(
        timestamp=parse_timestamp(timestamp),
        level="INFO",
        source=source,
        user_id=None,
        payload={"event": "connection", "port": source[1]},
        origin_format="tuple",
    )
