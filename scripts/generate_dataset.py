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
# on ajoute la racine du projet au chemin sinon python trouve pas logstream
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# les imports sont apres le sys.path donc on dit a flake8 d'ignorer E402
from logstream.config import DATA_DIR  # noqa: E402
from logstream.simulator import write_dataset  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Lit les arguments et écrit le jeu de données."""
    # les options qu'on peut passer dans le terminal
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--lines", type=int, default=5000,
                        help="nombre d'événements par fichier")
    # meme graine = memes fichiers a chaque fois
    parser.add_argument("--seed", type=int, default=42,
                        help="graine aléatoire (reproductibilité)")
    parser.add_argument("--output", type=Path, default=DATA_DIR,
                        help="dossier de destination")
    args = parser.parse_args(argv)

    # pas de sens de generer 0 ou -5 lignes
    if args.lines <= 0:
        parser.error("--lines doit être strictement positif")

    # tout le travail est fait dans logstream/simulator.py
    # ca ecrit les 3 fichiers de logs + la blacklist
    written = write_dataset(args.output, args.lines, args.seed)

    # on affiche combien de lignes il y a dans chaque fichier
    for name, count in written.items():
        print(f"{args.output / name} : {count} lignes")
    return 0


# seulement si on lance le fichier directement (pas avec un import)
if __name__ == "__main__":
    sys.exit(main())
