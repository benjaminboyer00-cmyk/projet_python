"""
Affichage des résultats dans le terminal et export au format JSON.
"""

import json
import logging
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from logstream.aggregation import TrafficStatistics
from logstream.config import SEVERITY_ORDER
from logstream.detection import DetectionResult
from logstream.rules import RuleEngineReport

logger = logging.getLogger(__name__)

WIDTH = 72  # largeur des titres dans le terminal


# --- Export JSON -------------------------------------------------------------

def to_jsonable(value: Any) -> Any:
    """Convertit une valeur en types acceptés par le format JSON."""
    # JSON ne connaît pas les dates, les set, les tuples ni nos classes.
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
        case _ if hasattr(value, "__dict__"):
            # vars() donne les attributs d'un objet sous forme de dictionnaire.
            return to_jsonable(vars(value))
        case _:
            return value


def export_json(data: Any, path: Path) -> Path:
    """Écrit des données dans un fichier JSON et renvoie son chemin."""
    path.parent.mkdir(parents=True, exist_ok=True)  # crée le dossier si besoin
    with path.open("w", encoding="utf-8") as file:
        # ensure_ascii=False garde les accents lisibles dans le fichier.
        json.dump(to_jsonable(data), file, indent=2, ensure_ascii=False)
    logger.info("Rapport écrit : %s", path)
    return path


# --- Outils d'affichage ------------------------------------------------------

def title(text: str) -> str:
    """Renvoie un titre de section encadré."""
    return f"\n{'=' * WIDTH}\n {text}\n{'=' * WIDTH}"


def format_counter(counter: Mapping[str, int], order: tuple[str, ...] = (),
                   limit: int = 10) -> str:
    """Formate un compteur en lignes "clé  valeur  ###"."""
    if order:  # ordre imposé, par exemple les niveaux de sévérité
        items = [(key, counter.get(key, 0)) for key in order]
    else:  # sinon, du plus grand au plus petit
        items = sorted(counter.items(), key=lambda pair: pair[1],
                       reverse=True)[:limit]

    maximum = max((count for _, count in items), default=0)
    lines = []
    for key, count in items:
        # Longueur de la barre proportionnelle à la plus grande valeur.
        bar = "#" * (round(30 * count / maximum) if maximum else 0)
        lines.append(f"  {key:<22} {count:>7}  {bar}")
    return "\n".join(lines)


# --- Affichage de chaque module ----------------------------------------------

def print_ingestion(metrics: Mapping[str, int], preview: list[str]) -> None:
    """Affiche le bilan des modules 1 et 2."""
    print(title("MODULES 1 & 2 - Ingestion et pipeline"))
    print(f"  Entrées brutes lues     : {metrics['raw_entries']:>8}")
    print(f"  Entrées non vides       : {metrics['non_empty_entries']:>8}")
    print(f"  Enregistrements parsés  : {metrics['parsed_records']:>8}")
    print(f"  Enregistrements valides : {metrics['valid_records']:>8}")
    print(f"  Entrées rejetées        : {metrics['rejected']:>8}")
    print("\n  Aperçu des logs normalisés :")
    for message in preview:
        print(f"    {message}")


def print_statistics(stats: TrafficStatistics,
                     ip_sets: dict[str, frozenset[str]],
                     error_analysis: dict[str, frozenset[str]]) -> None:
    """Affiche le bilan du module 3 (statistiques)."""
    print(title("MODULE 3 - Agrégation"))
    print(f"  Période : du {stats.first_timestamp} au {stats.last_timestamp}")
    print("\n  Répartition par niveau :")
    print(format_counter(stats.by_level, order=SEVERITY_ORDER))
    print("\n  Répartition par catégorie :")
    print(format_counter(stats.by_category))
    print("\n  Répartition par format d'origine :")
    print(format_counter(stats.by_format))
    print("\n  Utilisateurs les plus actifs :")
    print(format_counter(stats.by_user, limit=5))

    print(f"\n  IP actives uniques       : {len(stats.active_ips)}")
    print(f"  IP ayant généré des erreurs : {len(stats.error_ips)}")
    print(f"  Connexions uniques       : {len(stats.connections)}")

    print("\n  Opérations entre IP actives et liste noire :")
    for name, ips in ip_sets.items():
        print(f"    {name:<24} {len(ips):>4} IP")

    print("\n  IP en erreur déjà blacklistées : "
          f"{sorted(error_analysis['known_threats'])}")
    print("  IP en erreur à surveiller (les plus actives) :")
    candidates = {ip: stats.errors_by_ip[ip]
                  for ip in error_analysis["blacklist_candidates"]}
    print(format_counter(candidates, limit=5))


def print_detection(result: DetectionResult, threshold: int) -> None:
    """Affiche le bilan de la détection de force brute."""
    print(title(f"MODULE 3 - Détection de force brute (seuil {threshold})"))
    print(f"  Événements analysés  : {result.processed_events}")
    print(f"  Événements d'auth.   : {result.auth_events}")
    print(f"  Échecs de connexion  : {result.failed_logins}")
    print(f"  Cycles complets      : {result.completed_cycles}")
    print(f"  Analyse              : "
          f"{'complète' if result.complete else 'INTERROMPUE'}")
    print(f"  Attaques détectées   : {len(result.alerts)}")
    for alert in result.alerts[:10]:  # on n'affiche que les 10 premières
        print(f"    - {alert}")
    if len(result.alerts) > 10:
        print(f"    ... ({len(result.alerts) - 10} autres)")


def print_rules(report: RuleEngineReport) -> None:
    """Affiche le bilan du moteur de règles."""
    print(title("MODULE 4 - Moteur de règles"))
    print(f"  Règles appliquées : {', '.join(report.rules_applied)}")
    print(f"  Paramètres        : {report.config}")
    print(f"  Logs contrôlés    : {report.records_checked}")
    print(f"  Alertes           : {report.total_hits}"
          f"{' (arrêt anticipé)' if report.interrupted else ''}")
    print(format_counter(report.hits_by_rule))
    if report.rule_errors:
        print(f"  Erreurs de règles : {dict(report.rule_errors)}")

    print("\n  Exemples d'alertes :")
    seen: set[str] = set()  # règles dont on a déjà montré un exemple
    for alert in report.alerts:
        if alert["rule"] not in seen:
            seen.add(alert["rule"])
            print(f"    [{alert['rule']}] {alert['ip']} : {alert['detail']}")
