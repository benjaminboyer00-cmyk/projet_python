#!/usr/bin/env python3
"""
Point d'entrée du projet : lance toute l'analyse.

Étapes, dans l'ordre :
    1. lecture des logs avec des générateurs (module 1) ;
    2. nettoyage et normalisation avec map et filter (module 2) ;
    3. statistiques et détection de force brute (module 3) ;
    4. règles de sécurité et audit des variables (module 4).

Un générateur ne se parcourt qu'une seule fois. On rouvre donc la source pour
chaque analyse : c'est un peu plus lent, mais on évite de garder tous les logs
en mémoire.

Exemples :
    python main.py
    python main.py --threshold 8 --window 60
    python main.py --files data/auth_server.log -v
    python main.py --simulate 20000
"""

import argparse
import logging
import sys
import time
import tracemalloc
from collections import defaultdict
from collections.abc import Iterator
from itertools import islice
from pathlib import Path
from typing import Any

from logstream.aggregation import (
    analyze_error_ips,
    collect_statistics,
    compare_ip_sets,
    top_n,
)
from logstream.audit import export_audit_report
from logstream.config import (
    BLACKLIST_FILE,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    DATA_DIR,
    DEFAULT_LOG_FILES,
    OUTPUT_DIR,
    SUSPICIOUS_PORTS,
)
from logstream.detection import detect_brute_force
from logstream.exceptions import LogEngineError
from logstream.ingestion import load_blacklist, read_log_sources
from logstream.models import RawEntry
from logstream.pipeline import build_pipeline
from logstream.reporting import (
    export_json,
    print_detection,
    print_ingestion,
    print_rules,
    print_statistics,
)
from logstream.rules import apply_security_rules, get_rules
from logstream.simulator import simulate_stream

logger = logging.getLogger("logstream")

PREVIEW_SIZE = 5  # nombre de logs affichés en aperçu


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Lit les options de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Moteur d'analyse de logs sécurisé.",
    )
    # On analyse soit des fichiers, soit un flux simulé, mais pas les deux.
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--files", nargs="+", type=Path, metavar="FICHIER",
                        help="fichiers à analyser (défaut : ceux de data/)")
    source.add_argument("--simulate", type=int, metavar="N",
                        help="analyser un flux simulé de N entrées")
    parser.add_argument("--threshold", type=int, default=BRUTE_FORCE_THRESHOLD,
                        help="nombre d'échecs avant une alerte force brute")
    parser.add_argument("--window", type=float,
                        default=BRUTE_FORCE_WINDOW_SECONDS,
                        help="écart maximal en secondes entre deux échecs")
    parser.add_argument("--rules", nargs="+", metavar="REGLE",
                        help="règles à appliquer (défaut : toutes)")
    parser.add_argument("--max-alerts", type=int, default=None,
                        help="arrêter chaque analyse après N alertes")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR,
                        help="dossier des rapports JSON")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="afficher les messages détaillés")

    args = parser.parse_args(argv)
    if args.simulate is not None and args.simulate <= 0:
        parser.error("--simulate doit être strictement positif")
    return args


def open_stream(args: argparse.Namespace) -> Iterator[RawEntry]:
    """Renvoie un nouveau flux d'entrées, prêt à être parcouru."""
    if args.simulate is not None:
        return simulate_stream(args.simulate)

    paths = args.files or [DATA_DIR / name for name in DEFAULT_LOG_FILES]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Fichier(s) absent(s) : {', '.join(missing)}")
    return read_log_sources(paths)


def run(args: argparse.Namespace) -> int:
    """Lance les analyses, affiche les résultats et écrit les rapports."""
    blacklist = load_blacklist(BLACKLIST_FILE)
    rules = get_rules(args.rules)
    # On ouvre le flux ici pour signaler un fichier manquant dès le début.
    stream = open_stream(args)

    # tracemalloc mesure la mémoire réellement utilisée par Python.
    tracemalloc.start()
    started = time.perf_counter()

    # Modules 1 à 3 : premier parcours, pour les statistiques.
    metrics: defaultdict[str, int] = defaultdict(int)
    stats = collect_statistics(build_pipeline(stream, metrics))
    metrics["rejected"] = (metrics["non_empty_entries"]
                           - metrics["valid_records"])
    ip_sets = compare_ip_sets(stats.active_ips, blacklist)
    error_analysis = analyze_error_ips(stats.error_ips, blacklist)

    # Module 3 : deuxième parcours, pour la force brute.
    detection = detect_brute_force(
        build_pipeline(open_stream(args)),
        threshold=args.threshold,
        window_seconds=args.window,
        max_alerts=args.max_alerts,
    )

    # Module 4 : troisième parcours. Les règles sont passées dans *args (grâce
    # à l'étoile devant rules), le reste arrive dans **kwargs.
    rule_report = apply_security_rules(
        *rules,
        records=build_pipeline(open_stream(args)),
        max_alerts=args.max_alerts,
        blacklist=blacklist,
        suspicious_ports=SUSPICIOUS_PORTS,
    )

    elapsed = time.perf_counter() - started
    _, peak_memory = tracemalloc.get_traced_memory()  # (actuelle, maximale)
    tracemalloc.stop()

    # islice prend les premiers logs sans parcourir tout le flux.
    preview = [record["message"] for record in
               islice(build_pipeline(open_stream(args)), PREVIEW_SIZE)]

    print_ingestion(metrics, preview)
    print_statistics(stats, ip_sets, error_analysis)
    print_detection(detection, args.threshold)
    print_rules(rule_report)

    # Tout ce qui est écrit dans le rapport JSON, aussi lu par l'interface.
    summary: dict[str, Any] = {
        "pipeline": metrics,
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
            "peak_memory_kib": round(peak_memory / 1024, 1),
        },
    }
    output_dir = args.output_dir
    report_path = export_json(summary, output_dir / "analysis_report.json")

    # Module 4 : on transmet les variables du module et celles de run().
    audit_path = export_audit_report(
        output_dir / "audit_report.json",
        main_globals=globals(),
        run_locals=locals(),
    )

    print(f"\nAnalyse terminée en {elapsed:.1f} s, "
          f"avec un pic mémoire de {peak_memory / 1024 / 1024:.1f} Mo.")
    print(f"Rapports enregistrés dans {output_dir} : "
          f"{report_path.name} et {audit_path.name}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Lance le programme et renvoie son code de sortie (0 si tout va bien)."""
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)-8s %(name)s : %(message)s",
    )
    try:
        return run(args)
    except OSError as error:  # fichier absent, droits insuffisants...
        logger.error("Erreur de fichier : %s", error)
        return 1
    except (LogEngineError, ValueError) as error:  # mauvais paramètres
        logger.error("Configuration invalide : %s", error)
        return 2
    except KeyboardInterrupt:  # l'utilisateur a fait Ctrl+C
        logger.warning("Interruption par l'utilisateur")
        return 130


# Vrai seulement si on lance ce fichier directement, pas en cas d'import.
if __name__ == "__main__":
    sys.exit(main())
