"""
Module 4 - Moteur de règles modulaire (Flexible Rule Engine).

Une *règle de sécurité* est une simple fonction :

    def rule_xxx(record: LogRecord, **config) -> str | None

Elle renvoie un message d'alerte si l'enregistrement est suspect, sinon
``None``. Grâce au ``**config``, chaque règle ne lit que les paramètres
qui la concernent et ignore les autres.

La fonction maître ``apply_security_rules(*args, **kwargs)`` reçoit :

* ``*args``   : un nombre variable de règles (fonctions passées comme
  objets de première classe) ;
* ``**kwargs``: le flux ``records`` à analyser, des options du moteur
  (``max_alerts``) et des paramètres de configuration dynamiques
  transmis tels quels à chaque règle.
"""

import json
import logging
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, cast

from logstream.config import (
    DEFAULT_BLACKLIST,
    INJECTION_PATTERNS,
    SUSPICIOUS_PORTS,
    WORK_HOURS,
)
from logstream.exceptions import RuleEngineError
from logstream.models import Alert, LogRecord, SecurityRule
from logstream.pipeline import summarize_payload

logger = logging.getLogger(__name__)

RULE_PREFIX = "rule_"
DEFAULT_STORE_LIMIT = 1000


# --------------------------------------------------------------------------
# Règles de sécurité
# --------------------------------------------------------------------------
def rule_blacklisted_ip(
    record: LogRecord,
    *,
    blacklist: frozenset[str] = DEFAULT_BLACKLIST,
    **_: Any,
) -> str | None:
    """Alerte si l'IP source appartient à la liste noire."""
    if record["ip"] in blacklist:
        return f"IP blacklistée {record['ip']} active"
    return None


def rule_critical_event(record: LogRecord, **_: Any) -> str | None:
    """Alerte sur tout événement de niveau CRITICAL."""
    if record["level"] == "CRITICAL":
        summary = summarize_payload(record["payload"])
        return f"Événement critique ({record['category']}) : {summary}"
    return None


def rule_suspicious_port(
    record: LogRecord,
    *,
    suspicious_ports: frozenset[int] = SUSPICIOUS_PORTS,
    **_: Any,
) -> str | None:
    """Alerte sur une connexion vers un port réputé dangereux."""
    _ip, port, protocol = record["source"]
    if record["category"] == "NETWORK" and port in suspicious_ports:
        return f"Connexion {protocol} vers le port sensible {port}"
    return None


def rule_injection_attempt(
    record: LogRecord,
    *,
    injection_patterns: tuple[str, ...] = INJECTION_PATTERNS,
    **_: Any,
) -> str | None:
    """Alerte si le payload contient une signature d'injection."""
    payload = record["payload"]
    text = (payload if isinstance(payload, str)
            else json.dumps(payload, ensure_ascii=False)).lower()
    found = list(filter(lambda pattern: pattern in text,
                        injection_patterns))
    if found:
        return f"Signature d'injection détectée : {found[0]!r}"
    return None


def make_off_hours_rule(start_hour: int = WORK_HOURS[0],
                        end_hour: int = WORK_HOURS[1]) -> SecurityRule:
    """Fabrique (closure) : crée une règle "activité hors horaires".

    Illustre qu'une fonction peut *retourner* une fonction. La règle
    créée ne signale que les logs d'erreur survenus hors de la plage
    ``[start_hour, end_hour[``.
    """
    def rule_off_hours_error(record: LogRecord, **_: Any) -> str | None:
        hour = record["timestamp"].hour
        if (record["level"] in ("ERROR", "CRITICAL")
                and not start_hour <= hour < end_hour):
            return f"Erreur hors horaires ({hour}h)"
        return None

    return rule_off_hours_error


# --------------------------------------------------------------------------
# Registre des règles (introspection via globals())
# --------------------------------------------------------------------------
def available_rules() -> dict[str, SecurityRule]:
    """Découvre dynamiquement les règles définies dans ce module.

    ``globals()`` renvoie le dictionnaire des noms du module : on y
    sélectionne toutes les fonctions dont le nom commence par
    ``rule_``. Ajouter une règle = écrire une fonction, rien d'autre.
    """
    rules = {name: obj for name, obj in globals().items()
             if name.startswith(RULE_PREFIX) and callable(obj)}
    off_hours = make_off_hours_rule()
    rules[off_hours.__name__] = off_hours
    return rules


def get_rules(names: Iterable[str] | None = None) -> tuple[SecurityRule, ...]:
    """Renvoie les règles demandées par nom (toutes si ``names`` vide).

    Raises:
        RuleEngineError: si un nom de règle est inconnu.
    """
    registry = available_rules()
    if not names:
        return tuple(registry.values())
    unknown = set(names) - registry.keys()
    if unknown:
        raise RuleEngineError(
            f"Règle(s) inconnue(s) : {', '.join(sorted(unknown))}. "
            f"Disponibles : {', '.join(sorted(registry))}"
        )
    return tuple(map(lambda name: registry[name], names))


# --------------------------------------------------------------------------
# Moteur
# --------------------------------------------------------------------------
@dataclass
class RuleEngineReport:
    """Bilan d'exécution du moteur de règles."""

    rules_applied: tuple[str, ...] = ()
    records_checked: int = 0
    alerts: list[Alert] = field(default_factory=list)
    hits_by_rule: defaultdict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    rule_errors: defaultdict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    config: dict[str, str] = field(default_factory=dict)
    interrupted: bool = False

    @property
    def total_hits(self) -> int:
        """Nombre total de déclenchements (toutes règles confondues)."""
        return sum(self.hits_by_rule.values())


def _evaluate(rules: tuple[SecurityRule, ...], record: LogRecord,
              config: dict[str, Any],
              report: RuleEngineReport) -> Iterator[tuple[str, str]]:
    """Applique chaque règle à un enregistrement.

    Yields:
        Les couples ``(nom_de_la_règle, message)`` des règles déclenchées.
    """
    for rule in rules:
        try:
            detail = rule(record, **config)
        except Exception as exc:  # une règle défaillante ne bloque pas tout
            logger.warning("La règle %s a échoué : %s", rule.__name__, exc)
            report.rule_errors[rule.__name__] += 1
            continue
        if detail is not None:
            yield rule.__name__, detail


def apply_security_rules(*args: SecurityRule,
                         **kwargs: Any) -> RuleEngineReport:
    """Fonction maître : applique des règles variables à un flux de logs.

    Args:
        *args: fonctions de sécurité à appliquer (au moins une).
        **kwargs:
            records (Iterable[LogRecord]): flux à analyser (obligatoire).
            max_alerts (int): arrêt après ce nombre d'alertes (optionnel).
            store_limit (int): nombre maximal d'alertes conservées en
                mémoire (1000 par défaut) ; les compteurs, eux, restent
                exacts.
            ... : tout autre paramètre est transmis aux règles
            (ex. ``blacklist=...``, ``suspicious_ports=...``).

    Returns:
        Un ``RuleEngineReport``.

    Raises:
        RuleEngineError: si aucun flux ou aucune règle valide n'est fourni.

    Exemple::

        apply_security_rules(rule_blacklisted_ip, rule_critical_event,
                             records=pipeline, blacklist=my_blacklist)
    """
    records = kwargs.pop("records", None)
    max_alerts: int | None = kwargs.pop("max_alerts", None)
    store_limit: int = kwargs.pop("store_limit", DEFAULT_STORE_LIMIT)
    if records is None:
        raise RuleEngineError("Paramètre 'records' obligatoire")

    # filter(callable, ...) écarte tout argument qui n'est pas une fonction.
    rules = cast(tuple[SecurityRule, ...], tuple(filter(callable, args)))
    if len(rules) != len(args):
        logger.warning("%d argument(s) non appelable(s) ignoré(s)",
                       len(args) - len(rules))
    if not rules:
        raise RuleEngineError("Aucune règle de sécurité fournie")

    report = RuleEngineReport(
        rules_applied=tuple(map(lambda rule: rule.__name__, rules)),
        config={key: type(value).__name__ for key, value in kwargs.items()},
    )

    for record in records:
        report.records_checked += 1
        for rule_name, detail in _evaluate(rules, record, kwargs, report):
            report.hits_by_rule[rule_name] += 1
            if len(report.alerts) >= store_limit:
                continue
            report.alerts.append({
                "rule": rule_name,
                "ip": record["ip"],
                "timestamp": record["timestamp"].isoformat(),
                "level": record["level"],
                "detail": detail,
            })
        if max_alerts is not None and report.total_hits >= max_alerts:
            report.interrupted = True
            break

    return report
