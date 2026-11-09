"""
Génération des données de test.

Tout est écrit avec des générateurs : on peut créer un fichier de plusieurs
millions de lignes en n'ayant qu'une seule ligne en mémoire à la fois.

Chaque générateur utilise son propre random.Random(seed). Avec la même graine,
on obtient toujours exactement les mêmes fichiers.

Le jeu de données contient volontairement des lignes abîmées (vides, JSON
cassé, IP invalides...) pour tester le filtrage du pipeline.
"""

import json
import random
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

from logstream.models import RawEntry

START_TIME = datetime(2026, 10, 20, 6, 0, 0)  # date de la première ligne

# --- Valeurs possibles pour les lignes générées ---
NORMAL_IPS = tuple(
    [f"192.168.1.{i}" for i in range(10, 40)]
    + [f"10.0.0.{i}" for i in range(2, 12)]
)
ATTACKER_IPS = (
    "203.0.113.66", "203.0.113.7", "198.51.100.23", "198.51.100.99",
    "185.220.101.4",
)
USERS = tuple(f"user{i:03d}" for i in range(1, 31))  # user001 à user030
TARGET_ACCOUNTS = ("admin", "root", "user001", "backup")  # comptes attaqués

HTTP_PATHS = (
    "/", "/index.html", "/login", "/api/orders", "/api/users",
    "/static/app.js", "/dashboard", "/search",
)
MALICIOUS_PATHS = (
    "/search?q=' OR 1=1 --", "/../../etc/passwd",
    "/comment?text=<script>alert(1)</script>",
    "/api/users?id=1 UNION SELECT password FROM users",
)
SYSTEM_MESSAGES = (
    ("INFO", "Service nginx redémarré"),
    ("INFO", "Sauvegarde quotidienne terminée"),
    ("WARNING", "Utilisation mémoire à 85%"),
    ("WARNING", "Certificat TLS expire dans 10 jours"),
    ("ERROR", "Connexion à la base de données perdue"),
    ("CRITICAL", "Espace disque critique sur /var (98%)"),
)
NETWORK_PORTS = (22, 80, 443, 443, 443, 8080, 3306)  # 443 plus fréquent
SUSPICIOUS_TARGET_PORTS = (23, 445, 3389, 4444)

# Lignes parasites que le pipeline doit savoir écarter.
NOISE_LINES = (
    "",
    "   ",
    "# rotation du fichier de logs",
    "ligne corrompue ### sans structure",
    "2026-13-45T99:99:99 | INFO | 10.0.0.2:80/TCP | - | date invalide",
    "2026-10-20T10:00:00 | INFO | 999.1.1.1:80/TCP | - | ip invalide",
    "2026-10-20T10:00:00 | DEBUGX | 10.0.0.3:80/TCP | - | niveau inconnu",
    '{"level": "ERROR", "message": "json sans ip"}',
)


# --- Fonctions utilitaires ---------------------------------------------------

def ticks(rng: random.Random, start: datetime,
          max_step: int) -> Iterator[datetime]:
    """Générateur infini de dates croissantes."""
    current = start
    while True:
        current += timedelta(seconds=rng.randint(1, max_step))
        yield current


def text_line(ts: datetime, level: str, ip: str, port: int, proto: str,
              user: str | None, payload: str) -> str:
    """Formate une ligne de log au format texte du projet."""
    return (f"{ts.isoformat()} | {level} | {ip}:{port}/{proto} | "
            f"{user or '-'} | {payload}")


def maybe_noise(rng: random.Random, rate: float) -> Iterator[str]:
    """Produit une ligne parasite avec la probabilité rate."""
    if rng.random() < rate:
        yield rng.choice(NOISE_LINES)


# --- Générateurs des trois fichiers de logs ----------------------------------

def generate_web_lines(count: int, seed: int = 42) -> Iterator[str]:
    """Logs d'un serveur web : requêtes HTTP et erreurs applicatives."""
    rng = random.Random(seed)
    clock = ticks(rng, START_TIME, 20)  # la date avance de 1 à 20 s
    for _ in range(count):
        yield from maybe_noise(rng, 0.02)
        ts = next(clock)
        attacker = rng.random() < 0.06  # 6 % des requêtes sont malveillantes
        ip = rng.choice(ATTACKER_IPS if attacker else NORMAL_IPS)
        user = None if attacker else rng.choice(USERS + (None,))

        if rng.random() < 0.12:
            # Erreur applicative au format JSON, venant de quelques clients.
            ip = rng.choice(ATTACKER_IPS + NORMAL_IPS[:8])
            code = rng.choice((500, 502, 503, 504))
            yield json.dumps({
                "timestamp": ts.isoformat(), "level": "ERROR",
                "code": code, "ip": ip, "port": 443, "protocol": "TCP",
                "user": user, "message": f"Erreur serveur HTTP {code}",
            })
            continue

        # Un attaquant visite une URL malveillante une fois sur deux.
        path = rng.choice(MALICIOUS_PATHS if attacker and rng.random() < .5
                          else HTTP_PATHS)
        status = rng.choices((200, 301, 404, 403), (85, 5, 7, 3))[0]
        level = "INFO" if status < 400 else "WARNING"
        payload = json.dumps({"method": rng.choice(("GET", "POST")),
                              "path": path, "status": status})
        yield text_line(ts, level, ip, rng.choice((80, 443)), "TCP",
                        user, payload)


def generate_auth_lines(count: int, seed: int = 7) -> Iterator[str]:
    """Logs d'authentification, avec des rafales de force brute."""
    rng = random.Random(seed)
    clock = ticks(rng, START_TIME, 45)
    produced = 0

    # while et pas for : une rafale produit plusieurs lignes d'un coup.
    while produced < count:
        yield from maybe_noise(rng, 0.01)
        ts = next(clock)

        # 2,5 % de chances de lancer une attaque.
        if rng.random() < 0.025:
            # Rafale : 6 à 15 échecs espacés de 1 à 4 secondes.
            ip = rng.choice(ATTACKER_IPS)
            target = rng.choice(TARGET_ACCOUNTS)
            for _ in range(rng.randint(6, 15)):
                ts += timedelta(seconds=rng.randint(1, 4))
                yield text_line(ts, "WARNING", ip, 22,
                                "SSH", target, json.dumps(
                                    {"event": "login", "status": "failed"}))
                produced += 1
            if rng.random() < 0.3:  # l'attaquant réussit dans 30 % des cas
                yield text_line(ts, "CRITICAL", ip, 22, "SSH", target,
                                json.dumps({"event": "login",
                                            "status": "success"}))
                produced += 1
            continue

        # Utilisateur normal : parfois une erreur de mot de passe, puis une
        # réussite. Avec au plus 2 échecs, on reste sous le seuil d'alerte.
        ip, user = rng.choice(NORMAL_IPS), rng.choice(USERS)
        for _ in range(rng.choices((0, 1, 2), (80, 15, 5))[0]):
            yield text_line(ts, "WARNING", ip, 22, "SSH", user, json.dumps(
                {"event": "login", "status": "failed"}))
            produced += 1
        event = rng.choices(("login", "logout"), (70, 30))[0]
        yield text_line(ts, "INFO", ip, 22, "SSH", user, json.dumps(
            {"event": event, "status": "success"}))
        produced += 1


def generate_firewall_lines(count: int, seed: int = 99) -> Iterator[str]:
    """Logs du pare-feu : connexions et messages système."""
    rng = random.Random(seed)
    clock = ticks(rng, START_TIME, 30)
    for _ in range(count):
        yield from maybe_noise(rng, 0.02)
        ts = next(clock)
        if rng.random() < 0.15:
            level, text = rng.choice(SYSTEM_MESSAGES)
            yield text_line(ts, level, "10.0.0.1", 0, "UDP", "system", text)
            continue
        if rng.random() < 0.08:
            ip = rng.choice(ATTACKER_IPS)
            port = rng.choice(SUSPICIOUS_TARGET_PORTS)
        else:
            ip, port = rng.choice(NORMAL_IPS), rng.choice(NETWORK_PORTS)
        yield f"CONN {ts.isoformat()} {ip} {port} TCP"


def simulate_stream(count: int, seed: int = 2026) -> Iterator[RawEntry]:
    """Flux simulé mélangeant les trois formats : str, dict et tuple.

    Il sert à montrer le routage du pipeline sur des objets Python.
    """
    rng = random.Random(seed)
    clock = ticks(rng, START_TIME, 10)
    for _ in range(count):
        ts = next(clock)
        ip = rng.choice(NORMAL_IPS + ATTACKER_IPS)
        match rng.randint(1, 3):  # on tire le format au hasard
            case 1:
                yield text_line(ts, rng.choice(("INFO", "WARNING")), ip,
                                22, "SSH", rng.choice(USERS), json.dumps(
                                    {"event": "login", "status": rng.choice(
                                        ("success", "failed"))}))
            case 2:
                yield {"timestamp": ts.isoformat(), "level": "ERROR",
                       "code": rng.choice((500, 503)), "ip": ip,
                       "message": "Erreur applicative simulée"}
            case _:
                yield (ts, ip, rng.choice(NETWORK_PORTS
                                          + SUSPICIOUS_TARGET_PORTS), "TCP")


# --- Écriture des fichiers ---------------------------------------------------

def write_lines(path: Path, lines: Iterator[str]) -> int:
    """Écrit les lignes une par une et renvoie leur nombre."""
    written = 0
    with path.open("w", encoding="utf-8") as file:
        for line in lines:
            file.write(line + "\n")
            written += 1
    return written


def write_dataset(directory: Path, lines_per_file: int = 5000,
                  seed: int = 42) -> dict[str, int]:
    """Crée tout le jeu de test et renvoie le nombre de lignes par fichier."""
    directory.mkdir(parents=True, exist_ok=True)
    generators = {
        "web_server.log": generate_web_lines(lines_per_file, seed),
        "auth_server.log": generate_auth_lines(lines_per_file, seed + 1),
        "firewall.log": generate_firewall_lines(lines_per_file, seed + 2),
    }
    written = {name: write_lines(directory / name, lines)
               for name, lines in generators.items()}

    blacklist = ["# Liste noire d'adresses IP (une par ligne)",
                 "203.0.113.66", "198.51.100.23", "185.220.101.4",
                 "45.33.32.156   # IP connue, inactive dans ce jeu",
                 "91.189.0.17"]
    written["blacklist.txt"] = write_lines(directory / "blacklist.txt",
                                           iter(blacklist))
    return written
