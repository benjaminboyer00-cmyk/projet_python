#!/usr/bin/env python3
"""
Génère le jeu de données de test dans ``data/``.

Exemples :
    python scripts/generate_dataset.py                 # 5000 lignes/fichier
    python scripts/generate_dataset.py --lines 1000000 --output /tmp/big

Les lignes sont produites par des générateurs et écrites une par une :
on peut générer des fichiers de plusieurs Go sans saturer la RAM.
"""

import argparse
import sys
from pathlib import Path

# Permet de lancer le script depuis n'importe quel dossier.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logstream.config import DATA_DIR  # noqa: E402
from logstream.simulator import write_dataset  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Lit les arguments et écrit le jeu de données."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--lines", type=int, default=5000,
                        help="nombre d'événements par fichier")
    parser.add_argument("--seed", type=int, default=42,
                        help="graine aléatoire (reproductibilité)")
    parser.add_argument("--output", type=Path, default=DATA_DIR,
                        help="dossier de destination")
    args = parser.parse_args(argv)

    if args.lines <= 0:
        parser.error("--lines doit être strictement positif")

    written = write_dataset(args.output, args.lines, args.seed)
    for name, count in written.items():
        print(f"{args.output / name} : {count} lignes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
