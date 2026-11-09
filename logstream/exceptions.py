"""
Exceptions du projet.

Avoir nos propres exceptions permet de distinguer nos erreurs de celles de
Python. Toutes héritent de LogEngineError : un seul "except LogEngineError"
suffit donc à les attraper toutes.
"""


class LogEngineError(Exception):
    """Classe mère de toutes les erreurs du projet."""


class LogParseError(LogEngineError):
    """Une ligne de log ne peut pas être lue (format incorrect)."""


class RuleEngineError(LogEngineError):
    """Le moteur de règles est mal utilisé (règle inconnue, aucun flux...)."""
