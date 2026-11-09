"""
Module 4 : moteur de règles de sécurité.

Une règle est une simple fonction qui reçoit un log et des options, et qui
renvoie un message d'alerte, ou None si le log n'est pas suspect.

Le **config permet à chaque règle de lire seulement les options qui la
concernent et d'ignorer les autres.
"""

import logging
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from logstream.config import (
    DEFAULT_BLACKLIST,
    ERROR_LEVELS,
    INJECTION_PATTERNS,
    SUSPICIOUS_PORTS,
    WORK_HOURS,
)
from logstream.exceptions import RuleEngineError
from logstream.models import LogRecord, SecurityRule
from logstream.pipeline import summarize_payload

logger = logging.getLogger(__name__)

RULE_PREFIX = "rule_"
# On limite le nombre d'alertes gardées pour que la mémoire reste bornée.
# Les compteurs d'alertes, eux, restent toujours exacts.
MAX_STORED_ALERTS = 1000


# --- Règles de sécurité ------------------------------------------------------

def rule_blacklisted_ip(record: LogRecord, **config: Any) -> str | None:
    """Alerte si l'IP est dans la liste noire."""
    blacklist = config.get("blacklist", DEFAULT_BLACKLIST)
    if record["ip"] in blacklist:
        return f"IP blacklistée {record['ip']} active"
    return None


def rule_critical_event(record: LogRecord, **config: Any) -> str | None:
    """Alerte sur tout événement de niveau CRITICAL."""
    if record["level"] == "CRITICAL":
        summary = summarize_payload(record["payload"])
        return f"Événement critique ({record['category']}) : {summary}"
    return None


def rule_suspicious_port(record: LogRecord, **config: Any) -> str | None:
    """Alerte sur une connexion vers un port sensible."""
    suspicious_ports = config.get("suspicious_ports", SUSPICIOUS_PORTS)
    _, port, protocol = record["source"]  # "_" : l'IP ne nous sert pas ici
    if record["category"] == "NETWORK" and port in suspicious_ports:
        return f"Connexion {protocol} vers le port sensible {port}"
    return None


def rule_injection_attempt(record: LogRecord, **config: Any) -> str | None:
    """Alerte si le payload contient une signature d'injection."""
    patterns = config.get("injection_patterns", INJECTION_PATTERNS)
    # str() fonctionne aussi bien sur un texte que sur un dictionnaire.
    text = str(record["payload"]).lower()
    found = list(filter(lambda pattern: pattern in text, patterns))
    if found:
        return f"Signature d'injection détectée : {found[0]!r}"
    return None


def rule_off_hours_error(record: LogRecord, **config: Any) -> str | None:
    """Alerte sur une erreur survenue en dehors des heures de travail."""
    start_hour, end_hour = config.get("work_hours", WORK_HOURS)
    hour = record["timestamp"].hour
    if record["level"] in ERROR_LEVELS and not start_hour <= hour < end_hour:
        return f"Erreur hors horaires ({hour}h)"
    return None


# --- Recherche des règles disponibles ----------------------------------------

def available_rules() -> dict[str, SecurityRule]:
    """Trouve toutes les règles définies dans ce fichier.

    globals() renvoie le dictionnaire des noms du module. Pour ajouter une
    règle, il suffit donc d'écrire une fonction dont le nom commence par
    "rule_". Attention : aucune autre fonction ne doit commencer ainsi.
    """
    return {name: value for name, value in globals().items()
            if name.startswith(RULE_PREFIX) and callable(value)}


def get_rules(names: Iterable[str] | None = None) -> tuple[SecurityRule, ...]:
    """Renvoie les règles demandées par leur nom, ou toutes par défaut."""
    registry = available_rules()
    if not names:
        return tuple(registry.values())

    unknown = set(names) - set(registry)  # différence d'ensembles
    if unknown:
        raise RuleEngineError(
            f"Règle(s) inconnue(s) : {', '.join(sorted(unknown))}. "
            f"Disponibles : {', '.join(sorted(registry))}"
        )
    return tuple(map(lambda name: registry[name], names))


# --- Moteur ------------------------------------------------------------------

class RuleEngineReport:
    """Résultat de l'exécution du moteur de règles."""

    def __init__(self, rules_applied: tuple[str, ...],
                 config: dict[str, str]) -> None:
        self.rules_applied = rules_applied
        self.config = config  # nom et type des options reçues
        self.records_checked = 0
        self.alerts: list[dict[str, str]] = []
        self.hits_by_rule: defaultdict[str, int] = defaultdict(int)
        self.rule_errors: defaultdict[str, int] = defaultdict(int)
        self.interrupted = False  # True si max_alerts a été atteint

    @property
    def total_hits(self) -> int:
        """Nombre total d'alertes, toutes règles confondues."""
        return sum(self.hits_by_rule.values())


def apply_security_rules(*args: SecurityRule,
                         **kwargs: Any) -> RuleEngineReport:
    """Applique des règles à un flux de logs.

    *args contient les règles : ce sont des fonctions passées en argument.
    **kwargs contient records (le flux, obligatoire), max_alerts (optionnel)
    et toutes les autres options, transmises telles quelles à chaque règle.
    """
    # pop() retire ces deux clés : il ne reste que les options des règles.
    records = kwargs.pop("records", None)
    max_alerts = kwargs.pop("max_alerts", None)
    if records is None:
        raise RuleEngineError("Le paramètre records est obligatoire")

    # callable() permet d'ignorer tout argument qui n'est pas une fonction.
    rules = tuple(rule for rule in args if callable(rule))
    if not rules:
        raise RuleEngineError("Aucune règle de sécurité fournie")

    report = RuleEngineReport(
        rules_applied=tuple(rule.__name__ for rule in rules),
        config={key: type(value).__name__ for key, value in kwargs.items()},
    )

    for record in records:
        report.records_checked += 1
        for rule in rules:
            try:
                detail = rule(record, **kwargs)  # on redéploie les options
            except Exception:  # une règle boguée ne doit pas tout arrêter
                report.rule_errors[rule.__name__] += 1
                continue
            if detail is None:
                continue

            report.hits_by_rule[rule.__name__] += 1
            if len(report.alerts) < MAX_STORED_ALERTS:
                report.alerts.append({
                    "rule": rule.__name__,
                    "ip": record["ip"],
                    "timestamp": record["timestamp"].isoformat(),
                    "level": record["level"],
                    "detail": detail,
                })
        if max_alerts is not None and report.total_hits >= max_alerts:
            report.interrupted = True
            break

    return report
