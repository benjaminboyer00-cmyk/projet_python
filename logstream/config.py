"""
Constantes du projet.

Toutes les valeurs fixes sont regroupées ici pour ne pas les disperser dans
le code : pour changer un réglage, il suffit de modifier ce fichier.

Les collections sont des tuples ou des frozenset car elles sont immuables :
personne ne peut les modifier par erreur pendant l'exécution.
"""

from pathlib import Path

# --- Chemins ---
# __file__ est ce fichier : son parent est logstream/ et le parent de son
# parent est la racine du projet. Ainsi les chemins restent corrects quel que
# soit le dossier depuis lequel on lance le programme.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = PROJECT_ROOT / "output"

# Fichiers analysés quand l'utilisateur n'en indique aucun.
DEFAULT_LOG_FILES = ("web_server.log", "auth_server.log", "firewall.log")
BLACKLIST_FILE = DATA_DIR / "blacklist.txt"

# --- Format des lignes de logs ---
# Exemple : 2026-10-20T08:15:32 | INFO | 192.168.1.10:51234/TCP | bob | {...}
FIELD_SEPARATOR = " | "
FIELD_COUNT = 5  # date, niveau, source, utilisateur, payload
COMMENT_PREFIX = "#"
ANONYMOUS_USER = "anonymous"  # nom affiché quand le log n'a pas d'utilisateur

# --- Niveaux de sévérité ---
SEVERITY_ORDER = ("INFO", "WARNING", "ERROR", "CRITICAL")  # du moins grave
VALID_LEVELS = frozenset(SEVERITY_ORDER)  # recherche "in" très rapide
ERROR_LEVELS = frozenset({"ERROR", "CRITICAL"})

# --- Sécurité ---
# Liste noire de secours, utilisée si le fichier blacklist.txt est absent.
DEFAULT_BLACKLIST = frozenset({
    "203.0.113.66",
    "198.51.100.23",
    "45.33.32.156",
})

# Ports souvent visés : telnet, SMB, RDP, metasploit, IRC.
SUSPICIOUS_PORTS = frozenset({23, 445, 3389, 4444, 6667})

# Morceaux de texte typiques d'une injection SQL, XSS ou d'un "path traversal"
# (tout en minuscules car on compare avec le payload passé en minuscules).
INJECTION_PATTERNS = (
    "' or 1=1",
    "<script",
    "../",
    "union select",
    "; drop table",
)

# Heures de travail : de 7h inclus à 20h exclu.
WORK_HOURS = (7, 20)

# --- Détection de force brute ---
BRUTE_FORCE_THRESHOLD = 5  # nombre d'échecs consécutifs avant l'alerte
BRUTE_FORCE_WINDOW_SECONDS = 300  # écart maximal entre deux échecs
BATCH_SIZE = 500  # nombre de logs traités à chaque cycle de détection
