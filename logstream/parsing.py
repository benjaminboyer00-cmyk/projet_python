"""
Module 1 : transformation de chaque entrée en dictionnaire typé.

Le programme accepte trois formats :

1. ligne texte :
   2026-10-20T08:15:32 | INFO | 10.0.0.4:51234/TCP | user012 | {"a": 1}
2. objet JSON : {"timestamp": "...", "level": "ERROR", "ip": "..."}
3. connexion du pare-feu : CONN 2026-10-20T08:00:10 203.0.113.66 23 TCP

Dès qu'un champ est incorrect, on lève une LogParseError. Elle est rattrapée
dans le pipeline, qui écarte alors la ligne sans arrêter le programme.
"""

import ipaddress
import json
from datetime import datetime
from typing import Any

from logstream.config import FIELD_COUNT, FIELD_SEPARATOR
from logstream.exceptions import LogParseError
from logstream.models import ConnectionMeta, LogRecord, Payload, RawEntry

# Clés d'un log JSON qui ont un rôle précis. Toutes les autres clés (code,
# message...) sont rangées dans le payload.
BASE_KEYS = frozenset({"timestamp", "level", "ip", "port", "protocol", "user"})


# --- Lecture de chaque champ -------------------------------------------------

def parse_timestamp(value: Any) -> datetime:
    """Convertit une date au format ISO 8601 en objet datetime."""
    try:
        return datetime.fromisoformat(str(value).strip())
    except ValueError as error:
        raise LogParseError(f"Horodatage invalide : {value}") from error


def parse_ip(value: Any) -> str:
    """Vérifie qu'une adresse IP est valide (IPv4 ou IPv6)."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as error:
        raise LogParseError(f"Adresse IP invalide : {value}") from error


def parse_port(value: Any) -> int:
    """Convertit un port en entier compris entre 0 et 65535."""
    try:
        port = int(value)
    except (TypeError, ValueError) as error:
        raise LogParseError(f"Port non numérique : {value}") from error
    if not 0 <= port <= 65535:
        raise LogParseError(f"Port hors limites : {value}")
    return port


def parse_source(value: str) -> ConnectionMeta:
    """Découpe "ip:port/protocole" en tuple (ip, port, protocole)."""
    address, slash, protocol = value.strip().partition("/")
    # rpartition coupe au dernier ":" car une adresse IPv6 en contient déjà.
    ip, colon, port = address.rpartition(":")
    if not slash or not colon or not protocol:
        raise LogParseError(f"Source mal formée : {value}")
    return (parse_ip(ip), parse_port(port), protocol.strip())


def parse_user(value: Any) -> str | None:
    """Renvoie l'utilisateur, ou None s'il est absent ("-" ou vide)."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-") else text


def parse_payload(text: str) -> Payload:
    """Décode le texte en dictionnaire si c'est du JSON, sinon le garde."""
    text = text.strip()
    if text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass  # JSON cassé : on garde simplement le texte
    return text


def categorize(payload: Payload) -> str:
    """Donne la catégorie d'un log d'après la forme de son payload."""
    # Un motif de dictionnaire est valide si les clés indiquées existent.
    # Le "|" veut dire "ou" et str() ou int() vérifient le type de la valeur.
    match payload:
        case {"event": "login" | "logout"}:
            return "AUTH"
        case {"method": str(), "status": int()} | {"code": int()}:
            return "HTTP"
        case {"event": "connection"}:
            return "NETWORK"
        case str():
            return "SYSTEM"
        case _:  # "_" attrape tous les autres cas
            return "OTHER"


# --- Reconnaissance du format d'une ligne ------------------------------------

def decode_line(line: str) -> RawEntry:
    """Convertit une ligne en tuple (CONN), en dict (JSON) ou la laisse."""
    match line.split():
        # La ligne découpée doit avoir 5 mots et commencer par CONN. Le "if"
        # après le motif est une condition supplémentaire appelée "garde".
        case ["CONN", timestamp, ip, port, protocol] if port.isdigit():
            return (timestamp, ip, int(port), protocol)
        case _:
            return parse_payload(line)


# --- Construction du dictionnaire final --------------------------------------

def build_record(
    timestamp: datetime,
    level: str,
    source: ConnectionMeta,
    user_id: str | None,
    payload: Payload,
    origin_format: str,
) -> LogRecord:
    """Assemble le dictionnaire commun à tous les formats."""
    return {
        "timestamp": timestamp,
        "level": level,
        "source": source,
        "ip": source[0],  # copie de l'IP pour y accéder plus facilement
        "user_id": user_id,
        "payload": payload,
        "category": categorize(payload),
        "origin_format": origin_format,  # raw, dict ou tuple
        "message": "",  # rempli plus tard par normalize_record (module 2)
    }


def parse_text_line(line: str) -> LogRecord:
    """Parse une ligne "date | niveau | source | utilisateur | payload"."""
    # maxsplit évite de couper le payload s'il contient lui-même " | ".
    parts = line.split(FIELD_SEPARATOR, maxsplit=FIELD_COUNT - 1)
    if len(parts) != FIELD_COUNT:
        raise LogParseError(f"Mauvais nombre de champs : {line}")

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
    """Parse un log JSON déjà décodé en dictionnaire."""
    try:
        # .get() donne une valeur par défaut si le port ou le protocole
        # manque. L'IP, la date et le niveau, eux, sont obligatoires.
        source = (
            parse_ip(entry["ip"]),
            parse_port(entry.get("port", 0)),
            str(entry.get("protocol", "TCP")),
        )
        timestamp = parse_timestamp(entry["timestamp"])
        level = str(entry["level"])
    except KeyError as error:
        raise LogParseError(f"Clé manquante : {error}") from error

    # Compréhension de dictionnaire : le payload contient les autres clés.
    payload = {key: value for key, value in entry.items()
               if key not in BASE_KEYS}
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
    """Parse une connexion (horodatage, ip, port, protocole)."""
    source = (parse_ip(ip), parse_port(port), str(protocol))
    return build_record(
        timestamp=parse_timestamp(timestamp),
        level="INFO",  # une connexion n'a pas de niveau : INFO par défaut
        source=source,
        user_id=None,
        payload={"event": "connection", "port": source[1]},
        origin_format="tuple",
    )
