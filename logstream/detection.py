"""
Module 3 - Contrôle de flux : détection d'attaques par force brute.

Une attaque par force brute est détectée lorsqu'une même IP accumule
``threshold`` échecs de connexion **consécutifs** (sans succès entre
deux) et suffisamment rapprochés (``window_seconds`` maximum entre deux
échecs).

Structure de l'algorithme (exigée par le cahier des charges) :

* une boucle ``while`` découpe le flux en lots (``batch_size``) : un lot
  correspond à un *cycle de détection* ;
* une boucle ``for`` parcourt les événements du lot ;
* ``continue`` saute les événements non pertinents ;
* ``break`` interrompt l'analyse quand ``max_alerts`` est atteint ;
* la clause ``else`` du ``for`` valide qu'un cycle a été traité en
  entier, et celle du ``while`` valide que **tout** le flux a été
  analysé sans interruption.

Seul un compteur par IP est conservé en mémoire, jamais le flux.
"""

import logging
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from itertools import islice

from logstream.config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    DEFAULT_BATCH_SIZE,
)
from logstream.models import LogRecord

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BruteForceAlert:
    """Alerte de force brute (immuable)."""

    ip: str
    targets: tuple[str, ...]
    attempts: int
    first_attempt: datetime
    last_attempt: datetime

    @property
    def duration_seconds(self) -> float:
        """Durée de la série d'échecs."""
        return (self.last_attempt - self.first_attempt).total_seconds()

    def __str__(self) -> str:
        return (f"{self.ip:>15} : {self.attempts} échecs en "
                f"{self.duration_seconds:.0f}s sur {', '.join(self.targets)}")


@dataclass
class FailureStreak:
    """Série d'échecs consécutifs en cours pour une IP."""

    count: int = 0
    first: datetime | None = None
    last: datetime | None = None
    targets: set[str] = field(default_factory=set)
    reported: bool = False


@dataclass
class DetectionResult:
    """Bilan d'une exécution de la détection."""

    alerts: list[BruteForceAlert] = field(default_factory=list)
    processed_events: int = 0
    auth_events: int = 0
    failed_logins: int = 0
    completed_cycles: int = 0
    complete: bool = False


def login_status(record: LogRecord) -> str | None:
    """Renvoie ``'failed'`` / ``'success'`` pour un login, sinon None."""
    match record["payload"]:
        case {"event": "login", "status": "failed" | "denied"}:
            return "failed"
        case {"event": "login", "status": "success"}:
            return "success"
        case _:
            return None


def detect_brute_force(
    records: Iterable[LogRecord],
    threshold: int = BRUTE_FORCE_THRESHOLD,
    window_seconds: float = BRUTE_FORCE_WINDOW_SECONDS,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_alerts: int | None = None,
) -> DetectionResult:
    """Détecte les attaques par force brute dans un flux de logs.

    Args:
        records: flux d'enregistrements (consommé une seule fois).
        threshold: nombre d'échecs consécutifs déclenchant une alerte.
        window_seconds: écart maximal entre deux échecs d'une série.
        batch_size: taille d'un cycle de détection.
        max_alerts: arrêt anticipé après ce nombre d'alertes.

    Returns:
        Un ``DetectionResult`` ; ``complete`` vaut ``True`` uniquement si
        tout le flux a été analysé.

    Raises:
        ValueError: si un paramètre numérique est incohérent.
    """
    if threshold < 2:
        raise ValueError("threshold doit être >= 2")
    if batch_size < 1:
        raise ValueError("batch_size doit être >= 1")

    result = DetectionResult()
    streaks: defaultdict[str, FailureStreak] = defaultdict(FailureStreak)
    iterator = iter(records)

    # Boucle while : un tour = un cycle de détection sur un lot.
    while batch := list(islice(iterator, batch_size)):
        for record in batch:
            result.processed_events += 1
            status = login_status(record)
            if status is None:
                continue  # pas un événement d'authentification

            result.auth_events += 1
            ip = record["ip"]
            if status == "success":
                streaks.pop(ip, None)  # un succès casse la série
                continue

            result.failed_logins += 1
            streak = streaks[ip]
            timestamp = record["timestamp"]
            if (streak.last is not None and
                    (timestamp - streak.last).total_seconds()
                    > window_seconds):
                streak = streaks[ip] = FailureStreak()  # série expirée

            streak.count += 1
            streak.first = streak.first or timestamp
            streak.last = timestamp
            streak.targets.add(record["user_id"] or "?")

            if streak.count < threshold or streak.reported:
                continue

            streak.reported = True  # une seule alerte par série
            result.alerts.append(BruteForceAlert(
                ip=ip,
                targets=tuple(sorted(streak.targets)),
                attempts=streak.count,
                first_attempt=streak.first,
                last_attempt=streak.last,
            ))
            if max_alerts is not None and len(result.alerts) >= max_alerts:
                logger.warning("Limite de %d alertes atteinte : arrêt",
                               max_alerts)
                break  # on sort du for, donc son else est ignoré
        else:
            # Exécuté seulement si le for n'a PAS rencontré de break :
            # le cycle a été entièrement traité.
            result.completed_cycles += 1
            continue
        break  # le for a été interrompu : on sort aussi du while
    else:
        # Exécuté seulement si le while s'est terminé normalement
        # (flux épuisé) : la détection est complète.
        result.complete = True

    return result
