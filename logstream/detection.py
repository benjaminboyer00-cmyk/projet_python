"""
Module 3 : détection des attaques par force brute.

Une attaque est détectée quand une même IP enchaîne au moins "threshold"
échecs de connexion, sans réussite entre deux, et avec moins de
"window_seconds" secondes entre deux échecs.

Le flux est découpé en lots : un lot correspond à un cycle de détection.
"""

import logging
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from itertools import islice

from logstream.config import (
    BATCH_SIZE,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
)
from logstream.models import LogRecord

logger = logging.getLogger(__name__)


# @dataclass génère automatiquement le __init__ à partir des attributs.

@dataclass
class BruteForceAlert:
    """Une attaque détectée."""

    ip: str
    targets: tuple[str, ...]  # comptes visés
    attempts: int
    first_attempt: datetime
    last_attempt: datetime

    def __str__(self) -> str:
        duration = (self.last_attempt - self.first_attempt).total_seconds()
        return (f"{self.ip:>15} : {self.attempts} échecs en "
                f"{duration:.0f}s sur {', '.join(self.targets)}")


@dataclass
class FailureStreak:
    """Série d'échecs en cours pour une IP."""

    count: int = 0
    first: datetime | None = None
    last: datetime | None = None
    targets: set[str] = field(default_factory=set)
    reported: bool = False  # True dès qu'une alerte a été levée


@dataclass
class DetectionResult:
    """Résultat de la détection."""

    alerts: list[BruteForceAlert] = field(default_factory=list)
    processed_events: int = 0
    auth_events: int = 0
    failed_logins: int = 0
    completed_cycles: int = 0
    complete: bool = False  # True si tout le flux a été analysé


def login_status(record: LogRecord) -> str | None:
    """Renvoie "failed" ou "success" pour une connexion, sinon None."""
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
    batch_size: int = BATCH_SIZE,
    max_alerts: int | None = None,
) -> DetectionResult:
    """Cherche les attaques par force brute dans un flux de logs.

    max_alerts permet d'arrêter l'analyse après un certain nombre d'alertes.
    """
    if threshold < 2:
        raise ValueError("threshold doit être supérieur ou égal à 2")

    result = DetectionResult()
    # Une série par IP. Une IP inconnue reçoit automatiquement une série vide.
    streaks: defaultdict[str, FailureStreak] = defaultdict(FailureStreak)
    iterator = iter(records)

    # Boucle while : un tour correspond à un lot. islice prend les batch_size
    # éléments suivants ; une liste vide met fin à la boucle. Le ":=" permet
    # d'affecter batch dans la condition, sans break, pour que le else du
    # while puisse s'exécuter à la fin.
    while batch := list(islice(iterator, batch_size)):
        # Boucle for : on traite chaque événement du lot.
        for record in batch:
            result.processed_events += 1
            status = login_status(record)
            if status is None:
                continue  # ce n'est pas une connexion : événement suivant

            result.auth_events += 1
            ip = record["ip"]
            if status == "success":
                streaks.pop(ip, None)  # une réussite annule la série
                continue

            result.failed_logins += 1
            streak = streaks[ip]
            timestamp = record["timestamp"]

            # Si le dernier échec est trop ancien, on repart de zéro.
            if (streak.last is not None and
                    (timestamp - streak.last).total_seconds()
                    > window_seconds):
                streak = streaks[ip] = FailureStreak()

            streak.count += 1
            streak.first = streak.first or timestamp
            streak.last = timestamp
            streak.targets.add(record["user_id"] or "?")

            # Seuil pas encore atteint, ou alerte déjà levée pour cette série.
            if streak.count < threshold or streak.reported:
                continue

            streak.reported = True
            result.alerts.append(BruteForceAlert(
                ip=ip,
                targets=tuple(sorted(streak.targets)),
                attempts=streak.count,
                first_attempt=streak.first,
                last_attempt=streak.last,
            ))
            if max_alerts is not None and len(result.alerts) >= max_alerts:
                logger.warning("Limite de %d alertes atteinte", max_alerts)
                break  # on arrête le for, son else ne sera pas exécuté
        else:
            # Le else d'un for s'exécute seulement s'il n'y a pas eu de break :
            # le cycle est complet, on passe directement au lot suivant.
            result.completed_cycles += 1
            continue
        # On arrive ici seulement après le break du for : on sort du while.
        break
    else:
        # Le else du while s'exécute s'il s'est terminé sans break : tout le
        # flux a été analysé.
        result.complete = True

    return result
