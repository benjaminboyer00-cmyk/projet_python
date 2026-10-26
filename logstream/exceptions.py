"""Exceptions personnalisées du moteur de traitement de logs."""


class LogEngineError(Exception):
    """Classe de base de toutes les erreurs du projet."""


class LogParseError(LogEngineError):
    """Levée lorsqu'une ligne ou une entrée ne peut pas être parsée.

    Attributes:
        raw: l'entrée brute (tronquée) à l'origine de l'erreur.
    """

    def __init__(self, message: str, raw: object = None) -> None:
        super().__init__(message)
        self.raw = raw

    def __str__(self) -> str:
        base = super().__str__()
        if self.raw is None:
            return base
        preview = repr(self.raw)[:60]
        return f"{base} (entrée : {preview})"


class RuleEngineError(LogEngineError):
    """Levée lorsque le moteur de règles est mal configuré."""
