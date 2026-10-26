#!/usr/bin/env python3
"""
Point d'entrée principal : pilote l'ensemble du pipeline d'analyse.

Étapes :
    1. Ingestion  : lecture paresseuse des sources (générateurs).
    2. Pipeline   : filtrage / routage / normalisation (map, filter).
    3. Agrégation : statistiques, ensembles d'IP, liste noire.
    4. Détection  : attaques par force brute.
    5. Règles     : moteur de règles de sécurité (*args / **kwargs).
    6. Audit      : rapport d'introspection (globals() / locals()).

Chaque analyse reconstruit un pipeline neuf à partir des fichiers :
relire un fichier ne coûte que du temps disque, alors que conserver les
enregistrements (ou utiliser ``itertools.tee``) coûterait de la RAM
proportionnelle au volume de données.

Exemples :
    python main.py
    python main.py --threshold 8 --rules rule_blacklisted_ip
    python main.py --files data/auth_server.log -v
    python main.py --simulate 20000
"""

import argparse
import logging
import sys

# Vérification faite AVANT d'importer le package : celui-ci utilise
# match-case, qui provoquerait une SyntaxError sur Python < 3.10.
if sys.version_info < (3, 10):
    sys.exit("Ce projet nécessite Python 3.10 ou supérieur.")

import time  # noqa: E402
import tracemalloc  # noqa: E402
from collections.abc import Callable, Iterator  # noqa: E402
from itertools import islice  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

from logstream.aggregation import (  # noqa: E402
    TrafficStatistics,
    analyze_error_ips,
    collect_statistics,
    compare_ip_sets,
    top_n,
)
from logstream.audit import export_audit_report  # noqa: E402
from logstream.config import (  # noqa: E402
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    DATA_DIR,
    DEFAULT_BATCH_SIZE,
    DEFAULT_BLACKLIST_FILE,
    DEFAULT_LOG_FILES,
    OUTPUT_DIR,
    SUSPICIOUS_PORTS,
)
from logstream.detection import (  # noqa: E402
    DetectionResult,
    detect_brute_force,
)
from logstream.exceptions import LogEngineError  # noqa: E402
from logstream.ingestion import (  # noqa: E402
    load_blacklist,
    read_log_sources,
)
from logstream.models import RawEntry  # noqa: E402
from logstream.pipeline import (  # noqa: E402
    PipelineMetrics,
    build_pipeline,
)
from logstream.reporting import (  # noqa: E402
    export_json,
    format_counter,
    format_ip_sets,
    format_levels,
    title,
)
from logstream.rules import (  # noqa: E402
    RuleEngineReport,
    apply_security_rules,
    get_rules,
)
from logstream.simulator import simulate_stream  # noqa: E402

logger = logging.getLogger("logstream")

SourceFactory = Callable[[], Iterator[RawEntry]]


# --------------------------------------------------------------------------
# Ligne de commande
# --------------------------------------------------------------------------
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Définit et lit les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Moteur d'analyse de flux de logs sécurisé.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--files", nargs="+", type=Path, metavar="FICHIER",
        help="fichiers de logs à analyser (défaut : jeu de test de data/)",
    )
    source.add_argument(
        "--simulate", type=int, metavar="N",
        help="analyser un flux simulé de N entrées au lieu des fichiers",
    )
    parser.add_argument("--seed", type=int, default=2026,
                        help="graine du flux simulé (défaut : 2026)")
    parser.add_argument(
        "--blacklist", type=Path, default=DATA_DIR / DEFAULT_BLACKLIST_FILE,
        help="fichier de liste noire (une IP par ligne)",
    )
    parser.add_argument(
        "--threshold", type=int, default=BRUTE_FORCE_THRESHOLD,
        help="échecs consécutifs avant alerte force brute "
             f"(défaut : {BRUTE_FORCE_THRESHOLD})",
    )
    parser.add_argument(
        "--window", type=float, default=BRUTE_FORCE_WINDOW_SECONDS,
        help="écart max. en secondes entre deux échecs "
             f"(défaut : {BRUTE_FORCE_WINDOW_SECONDS})",
    )
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                        help="taille d'un cycle de détection")
    parser.add_argument(
        "--rules", nargs="+", metavar="REGLE",
        help="règles à appliquer (défaut : toutes)",
    )
    parser.add_argument("--max-alerts", type=int, default=None,
                        help="arrêter le moteur de règles après N alertes")
    parser.add_argument("--preview", type=int, default=5,
                        help="nombre d'enregistrements affichés en aperçu")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR,
                        help="dossier des rapports JSON")
    parser.add_argument(
        "--no-memory-trace", action="store_true",
        help="désactiver tracemalloc (plus rapide sur de gros volumes)",
    )
    parser.add_argument("--no-audit", action="store_true",
                        help="ne pas générer le rapport d'audit")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="-v : INFO, -vv : DEBUG")
    return parser.parse_args(argv)


def configure_logging(verbosity: int) -> None:
    """Configure le module logging selon le niveau de verbosité."""
    level = {0: logging.WARNING, 1: logging.INFO}.get(verbosity,
                                                      logging.DEBUG)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s : %(message)s",
        datefmt="%H:%M:%S",
    )


def make_source_factory(args: argparse.Namespace) -> SourceFactory:
    """Renvoie une fonction qui recrée un flux d'entrées neuf à chaque appel.

    Raises:
        FileNotFoundError: si un fichier demandé n'existe pas.
    """
    if args.simulate is not None:
        if args.simulate <= 0:
            raise ValueError("--simulate doit être strictement positif")
        return lambda: simulate_stream(args.simulate, args.seed)

    paths = args.files or [DATA_DIR / name for name in DEFAULT_LOG_FILES]
    missing = [str(path) for path in paths if not Path(path).is_file()]
    if missing:
        raise FileNotFoundError(
            f"Fichier(s) absent(s) : {', '.join(missing)}. "
            "Générez le jeu de test avec : python scripts/generate_dataset.py"
        )
    return lambda: read_log_sources(paths)


# --------------------------------------------------------------------------
# Affichage
# --------------------------------------------------------------------------
def print_ingestion(metrics: PipelineMetrics, preview: list[str]) -> None:
    """Affiche le bilan des modules 1 et 2."""
    counters = metrics.counters
    print(title("MODULES 1 & 2 - Ingestion et pipeline de transformation"))
    print(f"  Entrées brutes lues          : {counters['raw_entries']:>8}")
    print(f"  Entrées non vides            : "
          f"{counters['non_empty_entries']:>8}")
    print(f"  Enregistrements parsés       : {counters['parsed_records']:>8}")
    print(f"  Enregistrements valides      : {counters['valid_records']:>8}")
    print(f"  Entrées rejetées             : {metrics.rejected:>8}")
    if preview:
        print("\n  Aperçu des enregistrements normalisés :")
        for message in preview:
            print(f"    {message}")


def print_statistics(stats: TrafficStatistics,
                     ip_sets: dict[str, frozenset[str]],
                     error_analysis: dict[str, frozenset[str]],
                     blacklist: frozenset[str]) -> None:
    """Affiche le bilan du module 3 (agrégation)."""
    print(title("MODULE 3 - Agrégation"))
    print(f"  Période : {stats.first_timestamp} -> {stats.last_timestamp}")
    print("\n  Répartition par niveau :")
    print(format_levels(stats.by_level))
    print("\n  Répartition par catégorie :")
    print(format_counter(stats.by_category))
    print("\n  Répartition par format d'origine :")
    print(format_counter(stats.by_format))
    print("\n  Utilisateurs les plus actifs :")
    print(format_counter(stats.by_user, limit=5))

    print(f"\n  IP actives uniques            : {len(stats.active_ips)}")
    print(f"  IP ayant généré des erreurs   : {len(stats.error_ips)}")
    print(f"  Connexions uniques (ip,port,proto) : {len(stats.connections)}")
    print(f"  IP en liste noire (frozenset) : {len(blacklist)}")
    print("\n  Opérations ensemblistes :")
    print(format_ip_sets(ip_sets))
    print("\n  IP en erreur déjà blacklistées : "
          f"{sorted(error_analysis['known_threats'])}")
    print("  Top IP en erreur non blacklistées :")
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
    status = "complète" if result.complete else "INTERROMPUE"
    print(f"  Analyse              : {status}")
    print(f"  Attaques détectées   : {len(result.alerts)}")
    for alert in result.alerts[:10]:
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
    seen: set[str] = set()
    for alert in report.alerts:
        if alert["rule"] in seen:
            continue  # un exemple par règle
        seen.add(alert["rule"])
        print(f"    [{alert['rule']}] {alert['ip']} : {alert['detail']}")


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def run(args: argparse.Namespace) -> int:
    """Exécute le pipeline complet et écrit les rapports."""
    make_source = make_source_factory(args)
    blacklist = load_blacklist(args.blacklist)
    rules = get_rules(args.rules)

    if not args.no_memory_trace:
        tracemalloc.start()
    started = time.perf_counter()

    # Modules 1 à 3 : un passage pour les statistiques.
    metrics = PipelineMetrics()
    stats = collect_statistics(build_pipeline(make_source(), metrics))
    ip_sets = compare_ip_sets(stats.active_ips, blacklist)
    error_analysis = analyze_error_ips(stats.error_ips, blacklist)

    # Module 3 : détection de force brute (nouveau passage).
    detection = detect_brute_force(
        build_pipeline(make_source()),
        threshold=args.threshold,
        window_seconds=args.window,
        batch_size=args.batch_size,
    )

    # Module 4 : moteur de règles (nouveau passage).
    rule_report = apply_security_rules(
        *rules,
        records=build_pipeline(make_source()),
        max_alerts=args.max_alerts,
        blacklist=blacklist,
        suspicious_ports=SUSPICIOUS_PORTS,
    )

    elapsed = time.perf_counter() - started
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    preview = [record["message"] for record in
               islice(build_pipeline(make_source()), args.preview)]

    print_ingestion(metrics, preview)
    print_statistics(stats, ip_sets, error_analysis, blacklist)
    print_detection(detection, args.threshold)
    print_rules(rule_report)

    summary: dict[str, Any] = {
        "pipeline": metrics.as_dict(),
        "statistics": stats,
        "ip_sets": ip_sets,
        "error_ip_analysis": error_analysis,
        "top_error_ips": top_n(stats.errors_by_ip, 10),
        "brute_force": detection,
        "rules": {
            "applied": rule_report.rules_applied,
            "records_checked": rule_report.records_checked,
            "hits_by_rule": rule_report.hits_by_rule,
            "sample_alerts": rule_report.alerts[:50],
        },
        "performance": {
            "elapsed_seconds": round(elapsed, 3),
            "peak_memory_kib": (None if args.no_memory_trace
                                else round(peak_memory / 1024, 1)),
        },
    }
    output_dir: Path = args.output_dir
    report_path = export_json(summary, output_dir / "analysis_report.json")

    print(title("Performances & rapports"))
    print(f"  Durée totale des 3 passages : {elapsed:.2f} s")
    if not args.no_memory_trace:
        print(f"  Pic mémoire (tracemalloc)   : {peak_memory / 1024:.1f} Kio")
    print(f"  Rapport d'analyse           : {report_path}")

    if not args.no_audit:
        # Introspection : globales du module main + locales de run().
        audit_path = export_audit_report(
            output_dir / "audit_report.json",
            main_globals=globals(),
            run_locals=locals(),
        )
        print(f"  Rapport d'audit             : {audit_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée : gère les erreurs et renvoie le code de sortie."""
    args = parse_args(argv)
    configure_logging(args.verbose)
    try:
        return run(args)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1
    except OSError as exc:
        logger.error("Erreur d'entrée/sortie : %s", exc)
        return 1
    except (LogEngineError, ValueError) as exc:
        logger.error("Configuration invalide : %s", exc)
        return 2
    except KeyboardInterrupt:
        logger.warning("Interruption par l'utilisateur")
        return 130


if __name__ == "__main__":
    sys.exit(main())
