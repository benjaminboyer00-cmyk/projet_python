"""
Types utilisés dans le projet.

Ce sont de simples alias : ils ne changent rien à l'exécution, mais ils rendent
les signatures de fonctions plus lisibles et permettent à mypy de vérifier
le code.
"""

from collections.abc import Callable
from typing import Any

# Métadonnées fixes d'une connexion : (IP, port, protocole).
# On utilise un tuple car ces informations ne doivent plus changer une fois la
# ligne lue. Un tuple est aussi hachable, on peut donc le mettre dans un set.
ConnectionMeta = tuple[str, int, str]

# Le payload est un dictionnaire si c'était du JSON, sinon une simple chaîne.
Payload = dict[str, Any] | str

# Une entrée brute, avant parsing, peut avoir trois formes :
#   - str   : ligne de texte ;
#   - dict  : objet JSON déjà décodé ;
#   - tuple : connexion (horodatage, ip, port, protocole).
RawEntry = str | dict[str, Any] | tuple[Any, ...]

# Un log après parsing est un dictionnaire avec les clés : timestamp, level,
# source, ip, user_id, payload, category, origin_format et message.
LogRecord = dict[str, Any]

# Une règle de sécurité est une fonction qui reçoit un log et des options, et
# qui renvoie un message d'alerte ou None.
SecurityRule = Callable[..., str | None]
