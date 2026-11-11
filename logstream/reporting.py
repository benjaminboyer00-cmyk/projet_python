"""
Affichage des résultats dans le terminal et export au format JSON.
"""

import json
import logging
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from logstream.aggregation import TrafficStatistics, top_n
from logstream.config import SEVERITY_ORDER
from logstream.detection import DetectionResult
from logstream.rules import RuleEngineReport

logger = logging.getLogger(__name__)

SHOWN_ALERTS = 5  # nombre d'attaques affichées en exemple


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


# --- Affichage dans le terminal ----------------------------------------------

def list_counts(counter: Mapping[str, int], order: tuple[str, ...] = (),
                limit: int = 10) -> str:
    """Écrit un compteur sur une ligne : "INFO 120, WARNING 8, ..."."""
    if order:  # ordre imposé, par exemple les niveaux de sévérité
        keys = list(order)
    else:  # sinon, du plus grand au plus petit
        keys = sorted(counter, key=lambda key: counter[key],
                      reverse=True)[:limit]
    return ", ".join(f"{key} {counter.get(key, 0)}" for key in keys)


def print_ingestion(metrics: Mapping[str, int], preview: list[str]) -> None:
    """Affiche le bilan des modules 1 et 2."""
    print("Modules 1 et 2 : lecture et nettoyage")
    print(f"  {metrics['raw_entries']} lignes lues, dont "
          f"{metrics['raw_entries'] - metrics['non_empty_entries']} vides "
          "ou commentaires.")
    print(f"  {metrics['valid_records']} logs valides, "
          f"{metrics['rejected']} lignes rejetées.")
    print("  Premiers logs normalisés :")
    for message in preview:
        print(f"    {message}")


def print_statistics(stats: TrafficStatistics,
                     ip_sets: dict[str, frozenset[str]],
                     error_analysis: dict[str, frozenset[str]]) -> None:
    """Affiche le bilan du module 3 (statistiques)."""
    print("\nModule 3 : statistiques")
    print(f"  Logs du {stats.first_timestamp:%d/%m/%Y %H:%M} "
          f"au {stats.last_timestamp:%d/%m/%Y %H:%M}.")
    print(f"  Niveaux : {list_counts(stats.by_level, order=SEVERITY_ORDER)}")
    print(f"  Catégories : {list_counts(stats.by_category)}")
    print(f"  Formats : {list_counts(stats.by_format)}")
    print("  Utilisateurs les plus actifs : "
          f"{list_counts(stats.by_user, limit=3)}")
    print(f"  {len(stats.active_ips)} IP actives, dont "
          f"{len(stats.error_ips)} avec des erreurs. "
          f"{len(stats.connections)} connexions différentes.")

    print("  Comparaison avec la liste noire : "
          f"union {len(ip_sets['union'])}, "
          f"intersection {len(ip_sets['intersection'])}, "
          f"différence {len(ip_sets['active_not_blacklisted'])}, "
          f"différence symétrique {len(ip_sets['symmetric_difference'])}.")
    print("  IP en erreur déjà sur la liste noire : "
          f"{', '.join(sorted(error_analysis['known_threats']))}")
    candidates = {ip: stats.errors_by_ip[ip]
                  for ip in error_analysis["blacklist_candidates"]}
    watched = [f"{ip} ({count} erreurs)" for ip, count in top_n(candidates, 3)]
    print(f"  IP en erreur à surveiller : {', '.join(watched)}")


def print_detection(result: DetectionResult, threshold: int) -> None:
    """Affiche le bilan de la détection de force brute."""
    state = "complète" if result.complete else "interrompue"
    print(f"\nModule 3 : force brute (alerte à {threshold} échecs)")
    print(f"  {result.failed_logins} échecs de connexion sur "
          f"{result.auth_events} tentatives.")
    print(f"  {len(result.alerts)} attaques trouvées, analyse {state} "
          f"({result.completed_cycles} lots traités en entier).")
    for alert in result.alerts[:SHOWN_ALERTS]:
        print(f"    {alert}")
    if len(result.alerts) > SHOWN_ALERTS:
        print(f"    et {len(result.alerts) - SHOWN_ALERTS} autres.")


def print_rules(report: RuleEngineReport) -> None:
    """Affiche le bilan du moteur de règles."""
    print("\nModule 4 : règles de sécurité")
    print(f"  {len(report.rules_applied)} règles appliquées sur "
          f"{report.records_checked} logs, options reçues : "
          f"{', '.join(report.config) or 'aucune'}.")
    stop = " (arrêt anticipé)" if report.interrupted else ""
    print(f"  {report.total_hits} alertes{stop} : "
          f"{list_counts(report.hits_by_rule)}")
    if report.rule_errors:
        print(f"  Règles en erreur : {dict(report.rule_errors)}")

    print("  Un exemple par règle :")
    seen: set[str] = set()  # règles dont on a déjà montré un exemple
    for alert in report.alerts:
        if alert["rule"] not in seen:
            seen.add(alert["rule"])
            print(f"    {alert['rule']} : {alert['detail']}")
