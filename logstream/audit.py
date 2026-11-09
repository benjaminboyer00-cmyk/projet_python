"""
Module 4 : audit des variables du programme.

* globals() renvoie un dictionnaire des noms définis au niveau d'un module ;
* locals() renvoie un dictionnaire des noms locaux de la fonction en cours.

Appelé ici, globals() donnerait les variables de audit.py. Pour auditer un
autre fichier, l'appelant nous transmet donc ses propres globals() et locals().
"""

import platform
import sys
import types
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from logstream.reporting import export_json

PREVIEW_LENGTH = 80  # nombre maximum de caractères de l'aperçu d'une valeur


def describe_value(value: Any) -> dict[str, Any]:
    """Décrit une valeur : type, taille en mémoire et aperçu."""
    return {
        "type": type(value).__name__,
        "size_bytes": sys.getsizeof(value),
        "preview": repr(value)[:PREVIEW_LENGTH],
    }


def snapshot_scope(scope: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Décrit toutes les variables d'une portée (globals ou locals)."""
    snapshot = {}
    # sorted() crée une copie : la portée peut donc changer sans danger
    # pendant la boucle (sinon Python lèverait une RuntimeError).
    for name, value in sorted(scope.items()):
        # On ignore les modules importés et les noms privés comme __name__.
        if not name.startswith("_") and not isinstance(value,
                                                       types.ModuleType):
            snapshot[name] = describe_value(value)
    return snapshot


def build_audit_report(**scopes: Mapping[str, Any]) -> dict[str, Any]:
    """Construit le rapport d'audit.

    **scopes reçoit les portées à auditer avec le nom de notre choix, par
    exemple main_globals=globals() et run_locals=locals().
    """
    report: dict[str, Any] = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "python_version": platform.python_version(),
        # sys.prefix diffère de sys.base_prefix dans un environnement virtuel.
        "virtualenv": sys.prefix != sys.base_prefix,
        "scopes": {},
    }
    for scope_name, scope in scopes.items():
        snapshot = snapshot_scope(scope)
        report["scopes"][scope_name] = {
            "variable_count": len(snapshot),
            "total_size_bytes": sum(info["size_bytes"]
                                    for info in snapshot.values()),
            "variables": snapshot,
        }

    # Ici globals() et locals() décrivent audit.py et cette fonction.
    report["audit_module_globals"] = sorted(
        name for name in globals() if not name.startswith("__")
    )
    report["audit_function_locals"] = sorted(locals())
    return report


def export_audit_report(output_path: Path,
                        **scopes: Mapping[str, Any]) -> Path:
    """Construit le rapport d'audit et l'écrit dans un fichier JSON."""
    return export_json(build_audit_report(**scopes), output_path)
