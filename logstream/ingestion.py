"""
Module 1 - Ingestion de données & générateurs mémoire.

Principe : on ne charge **jamais** un fichier entier en RAM. Chaque
fonction de ce module est un générateur (``yield``) qui produit les
lignes une par une, à la demande. Le consommateur (le pipeline) tire
les lignes au fur et à mesure : à tout instant, une seule ligne par
fichier est présente en mémoire.

* ``read_log_file``    : générateur principal (``yield``) sur un fichier.
* ``read_log_sources`` : sous-générateur qui enchaîne plusieurs fichiers
  avec ``yield from``.
* ``read_streams``     : enchaîne des flux hétérogènes (fichiers, flux
  simulés...) avec ``yield from``.
"""

import logging
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Union

from logstream.config import COMMENT_PREFIX, DEFAULT_BLACKLIST
from logstream.models import RawEntry

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]


def read_log_file(path: PathLike, encoding: str = "utf-8") -> Iterator[str]:
    """Lit un fichier de logs ligne par ligne (générateur ``yield``).

    Le fichier est parcouru par l'itérateur natif de l'objet fichier,
    qui lit le disque par blocs : la mémoire consommée ne dépend pas de
    la taille du fichier.

    Un fichier absent ou illisible n'interrompt pas le programme : on
    journalise l'erreur et le générateur se termine sans rien produire,
    ce qui permet de continuer avec les autres sources.

    Args:
        path: chemin du fichier à lire.
        encoding: encodage du fichier (UTF-8 par défaut).

    Yields:
        Chaque ligne du fichier, sans le caractère de fin de ligne.
    """
    file_path = Path(path)
    try:
        handle = file_path.open("r", encoding=encoding, errors="replace")
    except FileNotFoundError:
        logger.error("Fichier introuvable : %s", file_path)
        return
    except (PermissionError, IsADirectoryError) as exc:
        logger.error("Impossible d'ouvrir %s : %s", file_path, exc)
        return

    line_count = 0
    with handle:
        for line in handle:
            line_count += 1
            yield line.rstrip("\r\n")
    logger.info("%s : %d lignes lues", file_path.name, line_count)


def read_log_sources(paths: Iterable[PathLike]) -> Iterator[str]:
    """Sous-générateur : lit plusieurs fichiers successivement.

    ``yield from`` délègue entièrement l'itération au générateur
    ``read_log_file`` : les lignes remontent directement au consommateur,
    sans liste intermédiaire.

    Args:
        paths: chemins des fichiers, lus dans l'ordre donné.

    Yields:
        Les lignes de tous les fichiers, à la suite.
    """
    for path in paths:
        logger.info("Ouverture de la source %s", path)
        yield from read_log_file(path)


def read_streams(*streams: Iterable[RawEntry]) -> Iterator[RawEntry]:
    """Enchaîne plusieurs flux hétérogènes (fichiers, flux simulés...).

    Exemple::

        entries = read_streams(read_log_sources(paths), simulate_stream(100))

    Args:
        *streams: un nombre quelconque d'itérables d'entrées brutes.

    Yields:
        Les entrées de chaque flux, les unes après les autres.
    """
    for stream in streams:
        yield from stream


def load_blacklist(path: PathLike | None = None) -> frozenset[str]:
    """Charge la liste noire d'IP dans un ``frozenset`` immuable.

    Le fichier contient une IP par ligne ; les lignes vides et les
    commentaires (``#``) sont ignorés. Le fichier est lu lui aussi via
    le générateur ``read_log_file``.

    Args:
        path: chemin du fichier. ``None`` -> liste noire par défaut.

    Returns:
        Un ``frozenset`` d'adresses IP (vide si le fichier est vide).
    """
    if path is None or not Path(path).is_file():
        if path is not None:
            logger.warning("Liste noire %s absente : valeurs par défaut",
                           path)
        return DEFAULT_BLACKLIST

    cleaned = map(lambda line: line.split(COMMENT_PREFIX, 1)[0].strip(),
                  read_log_file(path))
    return frozenset(filter(None, cleaned))
