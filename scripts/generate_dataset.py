#!/usr/bin/env python3
"""
Génère le jeu de données de test dans le dossier data/.

Exemples :
    python scripts/generate_dataset.py
    python scripts/generate_dataset.py --lines 1000000 --output /tmp/gros_jeu
"""

import argparse
import sys
from pathlib import Path

# On ajoute la racine du projet au chemin de recherche de Python : sans cela,
# il ne trouve pas le package logstream quand on lance ce script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Ces imports viennent après le sys.path : "noqa" dit à flake8 de l'accepter.
from logstream.config import DATA_DIR  # noqa: E402
from logstream.simulator import write_dataset  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Lit les options et écrit le jeu de données."""
    parser = argparse.ArgumentParser(description="Génère le jeu de test.")
    parser.add_argument("--lines", type=int, default=5000,
                        help="nombre d'événements par fichier")
    parser.add_argument("--seed", type=int, default=42,
                        help="graine aléatoire (même graine = mêmes fichiers)")
    parser.add_argument("--output", type=Path, default=DATA_DIR,
                        help="dossier de destination")
    args = parser.parse_args(argv)

    if args.lines <= 0:
        parser.error("--lines doit être strictement positif")

    # Tout le travail est fait dans logstream/simulator.py.
    written = write_dataset(args.output, args.lines, args.seed)
    for name, count in written.items():
        print(f"{args.output / name} : {count} lignes")
    return 0


# Vrai seulement si on lance ce fichier directement, pas en cas d'import.
if __name__ == "__main__":
    sys.exit(main())
