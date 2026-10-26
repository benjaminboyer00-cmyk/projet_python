"""
Modèles de données (types) utilisés dans tout le projet.

Un enregistrement de log est un **dictionnaire Python** (``LogRecord``,
un ``TypedDict`` qui n'ajoute que du typage statique : à l'exécution
c'est un ``dict`` classique).

Les métadonnées fixes de connexion sont représentées par un **tuple**
immuable ``(IP, Port, Protocole)`` : une fois la ligne lue, ces
informations ne doivent plus changer, et un tuple est hachable, ce qui
permet de le stocker dans un ``set``.
"""

from datetime import datetime
from typing import Any, Callable, Optional, TypedDict, Union

# (adresse IP, port, protocole) - ex: ("192.168.1.10", 443, "TCP")
ConnectionMeta = tuple[str, int, str]

# Le payload est soit un JSON décodé (dict), soit une chaîne brute.
Payload = Union[dict[str, Any], str]

# Une entrée "brute" avant parsing peut avoir trois formats :
#   - str   : ligne texte
#   - dict  : objet JSON déjà décodé
#   - tuple : événement de connexion (horodatage, ip, port, protocole)
RawEntry = Union[str, dict[str, Any], tuple[Any, ...]]


class LogRecord(TypedDict):
    """Enregistrement de log normalisé."""

    timestamp: datetime
    level: str
    source: ConnectionMeta
    ip: str
    user_id: Optional[str]
    payload: Payload
    category: str
    origin_format: str
    message: str


class Alert(TypedDict):
    """Alerte produite par le moteur de règles."""

    rule: str
    ip: str
    timestamp: str
    level: str
    detail: str


# Une règle de sécurité reçoit un enregistrement + une configuration
# (**kwargs) et renvoie un message d'alerte ou None.
SecurityRule = Callable[..., Optional[str]]
