"""
Configuration centrale du moteur.

Toutes les constantes "métier" sont regroupées ici pour éviter les
valeurs magiques dispersées dans le code. Les collections de référence
sont volontairement immuables (``frozenset``, ``tuple``) : elles ne
doivent jamais être modifiées pendant l'exécution.
"""

from pathlib import Path

# --- Chemins -------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = PROJECT_ROOT / "data"
OUTPUT_DIR: Path = PROJECT_ROOT / "output"

DEFAULT_LOG_FILES: tuple[str, ...] = (
    "web_server.log",
    "auth_server.log",
    "firewall.log",
)
DEFAULT_BLACKLIST_FILE: str = "blacklist.txt"

# --- Format des lignes ---------------------------------------------------
# Exemple de ligne texte :
# 2026-10-20T08:15:32 | INFO | 192.168.1.10:51234/TCP | user012 | {...}
FIELD_SEPARATOR: str = " | "
FIELD_COUNT: int = 5
CONNECTION_PREFIX: str = "CONN"
COMMENT_PREFIX: str = "#"
ANONYMOUS_USER: str = "anonymous"

# --- Niveaux de sévérité -------------------------------------------------
SEVERITY_ORDER: tuple[str, ...] = ("INFO", "WARNING", "ERROR", "CRITICAL")
VALID_LEVELS: frozenset[str] = frozenset(SEVERITY_ORDER)
ERROR_LEVELS: frozenset[str] = frozenset({"ERROR", "CRITICAL"})

# --- Sécurité ------------------------------------------------------------
# Liste noire par défaut (utilisée si aucun fichier n'est fourni).
DEFAULT_BLACKLIST: frozenset[str] = frozenset({
    "203.0.113.66",
    "198.51.100.23",
    "45.33.32.156",
})

SUSPICIOUS_PORTS: frozenset[int] = frozenset({23, 445, 3389, 4444, 6667})

INJECTION_PATTERNS: tuple[str, ...] = (
    "' or 1=1",
    "<script",
    "../",
    "union select",
    "; drop table",
)

# Plage horaire "normale" d'activité (heure de début, heure de fin).
WORK_HOURS: tuple[int, int] = (7, 20)

# --- Détection de force brute -------------------------------------------
BRUTE_FORCE_THRESHOLD: int = 5
BRUTE_FORCE_WINDOW_SECONDS: int = 300
DEFAULT_BATCH_SIZE: int = 500
