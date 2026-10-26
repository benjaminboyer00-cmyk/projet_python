"""
Mise en forme des résultats (console) et export JSON.
"""

import json
import logging
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from logstream.config import SEVERITY_ORDER

logger = logging.getLogger(__name__)

WIDTH = 72


def to_jsonable(value: Any) -> Any:
    """Convertit récursivement une valeur en type compatible JSON."""
    match value:
        case datetime():
            return value.isoformat()
        case set() | frozenset():
            return sorted(map(to_jsonable, value), key=str)
        case tuple() | list():
            return [to_jsonable(item) for item in value]
        case dict():
            return {str(key): to_jsonable(item)
                    for key, item in value.items()}
        case _ if is_dataclass(value) and not isinstance(value, type):
            # Conversion champ par champ : dataclasses.asdict() échoue sur
            # les champs defaultdict avant Python 3.12.
            return {item.name: to_jsonable(getattr(value, item.name))
                    for item in fields(value)}
        case _:
            return value


def export_json(data: Any, path: Path) -> Path:
    """Écrit ``data`` au format JSON (UTF-8, indenté)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(to_jsonable(data), handle, indent=2, ensure_ascii=False)
    logger.info("Rapport écrit : %s", path)
    return path


def title(text: str) -> str:
    """Titre de section encadré."""
    return f"\n{'=' * WIDTH}\n {text}\n{'=' * WIDTH}"


def bar(value: int, maximum: int, width: int = 30) -> str:
    """Petite barre horizontale en caractères."""
    filled = round(width * value / maximum) if maximum else 0
    return "#" * filled


def format_counter(counter: Mapping[str, int], order: tuple[str, ...] = (),
                   limit: int = 10) -> str:
    """Formate un compteur en lignes ``clé  valeur  ###``."""
    if order:
        items = [(key, counter.get(key, 0)) for key in order]
    else:
        items = sorted(counter.items(), key=lambda kv: kv[1],
                       reverse=True)[:limit]
    maximum = max((count for _, count in items), default=0)
    return "\n".join(f"  {key:<22} {count:>7}  {bar(count, maximum)}"
                     for key, count in items)


def format_levels(counter: Mapping[str, int]) -> str:
    """Formate les niveaux dans l'ordre de sévérité."""
    return format_counter(counter, order=SEVERITY_ORDER)


def format_ip_sets(sets: Mapping[str, frozenset[str]],
                   preview: int = 4) -> str:
    """Formate le résultat des opérations ensemblistes."""
    symbols = {
        "union": "actives | blacklist",
        "intersection": "actives & blacklist",
        "active_not_blacklisted": "actives - blacklist",
        "blacklisted_inactive": "blacklist - actives",
        "symmetric_difference": "actives ^ blacklist",
    }
    lines = []
    for key, values in sets.items():
        sample = ", ".join(sorted(values)[:preview])
        more = "..." if len(values) > preview else ""
        label = symbols.get(key, key)
        lines.append(f"  {label:<22} {len(values):>4}  {{{sample}{more}}}")
    return "\n".join(lines)
