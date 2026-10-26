"""
Module 4 - Introspection & audit de contexte.

Produit un rapport sur les variables chargées en mémoire dans une ou
plusieurs portées, à des fins d'audit et de débogage :

* ``globals()`` : dictionnaire des noms définis au niveau d'un module ;
* ``locals()``  : dictionnaire des noms locaux de la fonction en cours.

Pour chaque variable, le rapport indique son type, sa taille mémoire
(superficielle, via ``sys.getsizeof``) et un aperçu de sa valeur.

Remarque : ``globals()`` appelé *dans ce module* renvoie les globales de
``logstream.audit``. Pour auditer la portée de l'appelant, celui-ci
transmet ses propres ``globals()`` / ``locals()`` en argument.
"""

import json
import logging
import os
import platform
import sys
import types
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PREVIEW_LENGTH = 80


def describe_value(value: Any) -> dict[str, Any]:
    """Décrit une valeur : type, taille mémoire, longueur, aperçu."""
    description: dict[str, Any] = {
        "type": type(value).__name__,
        "size_bytes": sys.getsizeof(value),
        "preview": repr(value)[:PREVIEW_LENGTH],
    }
    if isinstance(value, (str, bytes, list, tuple, dict, set, frozenset)):
        description["length"] = len(value)
    return description


def is_auditable(name: str, value: Any, include_private: bool) -> bool:
    """Filtre : ignore les modules, et les noms privés/dunder par défaut."""
    if isinstance(value, types.ModuleType):
        return False
    return include_private or not name.startswith("_")


def snapshot_scope(
    scope: Mapping[str, Any], include_private: bool = False
) -> dict[str, dict[str, Any]]:
    """Photographie une portée (résultat de ``globals()``/``locals()``).

    Une copie du dictionnaire est faite d'abord : la portée réelle peut
    évoluer pendant l'itération (sinon ``RuntimeError``).
    """
    frozen_scope = dict(scope)
    selected = filter(
        lambda item: is_auditable(item[0], item[1], include_private),
        frozen_scope.items(),
    )
    return {name: describe_value(value)
            for name, value in sorted(selected)}


def summarize_by_type(snapshot: Mapping[str, Mapping[str, Any]]
                      ) -> dict[str, int]:
    """Nombre de variables par type dans un instantané."""
    counts: dict[str, int] = {}
    for info in snapshot.values():
        counts[info["type"]] = counts.get(info["type"], 0) + 1
    return dict(sorted(counts.items()))


def build_audit_report(include_private: bool = False,
                       **scopes: Mapping[str, Any]) -> dict[str, Any]:
    """Construit le rapport d'audit.

    Args:
        include_private: inclure les noms commençant par ``_``.
        **scopes: portées à auditer, nommées librement, par exemple
            ``main_globals=globals(), run_locals=locals()``.

    Returns:
        Un dictionnaire sérialisable en JSON.
    """
    report: dict[str, Any] = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "pid": os.getpid(),
        "virtualenv": sys.prefix != sys.base_prefix,
        "scopes": {},
    }
    for scope_name, scope in scopes.items():
        snapshot = snapshot_scope(scope, include_private)
        report["scopes"][scope_name] = {
            "variable_count": len(snapshot),
            "total_size_bytes": sum(info["size_bytes"]
                                    for info in snapshot.values()),
            "types": summarize_by_type(snapshot),
            "variables": snapshot,
        }

    # Audit du module d'audit lui-même : ses globales...
    report["audit_module_globals"] = sorted(
        name for name in globals() if not name.startswith("__")
    )
    # ... et les variables locales de cette fonction au moment présent.
    report["audit_function_locals"] = sorted(locals())
    return report


def export_audit_report(output_path: str | Path,
                        include_private: bool = False,
                        **scopes: Mapping[str, Any]) -> Path:
    """Construit puis écrit le rapport d'audit au format JSON.

    Raises:
        OSError: si le fichier ne peut pas être écrit.
    """
    path = Path(output_path)
    report = build_audit_report(include_private=include_private, **scopes)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
    except OSError:
        logger.error("Écriture du rapport d'audit impossible : %s", path)
        raise
    else:
        logger.info("Rapport d'audit écrit : %s", path)
    return path


def format_scope_table(snapshot: Mapping[str, Mapping[str, Any]],
                       limit: int = 15) -> str:
    """Formate un instantané en tableau texte pour la console."""
    lines = [f"{'Variable':<24} {'Type':<20} {'Taille (o)':>10}"]
    lines.append("-" * len(lines[0]))
    for name, info in list(snapshot.items())[:limit]:
        lines.append(f"{name:<24} {info['type']:<20} "
                     f"{info['size_bytes']:>10}")
    if len(snapshot) > limit:
        lines.append(f"... ({len(snapshot) - limit} autres variables)")
    return "\n".join(lines)
