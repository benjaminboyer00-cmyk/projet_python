"""
Module 1 : lecture des fichiers avec des générateurs.

Un générateur produit ses valeurs une par une, à la demande. À chaque "yield",
la fonction se met en pause et reprend au prochain élément demandé. On n'a donc
qu'une seule ligne en mémoire à la fois, quelle que soit la taille du fichier.
"""

import logging
from collections.abc import Iterable, Iterator
from pathlib import Path

from logstream.config import COMMENT_PREFIX, DEFAULT_BLACKLIST

# Un logger par module : le nom du module apparaît dans les messages.
logger = logging.getLogger(__name__)


def read_log_file(path: str | Path) -> Iterator[str]:
    """Générateur : renvoie les lignes d'un fichier une par une."""
    try:
        # errors="replace" : un caractère illisible est remplacé au lieu de
        # faire planter la lecture. Le "with" ferme le fichier à la fin.
        with open(path, encoding="utf-8", errors="replace") as file:
            # Parcourir un fichier ne le charge pas entièrement en mémoire.
            for line in file:
                yield line.rstrip("\r\n")  # on enlève le retour à la ligne
    except OSError as error:
        # Fichier absent ou illisible : on le signale et on continue. Le
        # générateur se termine simplement sans rien produire.
        logger.error("Impossible de lire %s : %s", path, error)


def read_log_sources(paths: Iterable[str | Path]) -> Iterator[str]:
    """Sous-générateur : lit plusieurs fichiers à la suite."""
    for path in paths:
        # "yield from" renvoie directement chaque ligne de read_log_file,
        # sans passer par une liste intermédiaire.
        yield from read_log_file(path)


def load_blacklist(path: str | Path) -> frozenset[str]:
    """Charge la liste noire d'IP dans un frozenset (ensemble immuable)."""
    if not Path(path).is_file():
        logger.warning("Liste noire %s absente : valeurs par défaut", path)
        return DEFAULT_BLACKLIST

    # map : pour chaque ligne, on enlève le commentaire éventuel et les
    # espaces. filter(None, ...) retire ensuite les lignes devenues vides.
    cleaned = map(lambda line: line.split(COMMENT_PREFIX)[0].strip(),
                  read_log_file(path))
    return frozenset(filter(None, cleaned))
