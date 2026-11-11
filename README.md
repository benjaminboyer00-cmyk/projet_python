# Moteur d'analyse de logs sécurisé

Projet final de Python, ING3.

Équipe : Benjamin Boyer, Gabriel Guery, Ismail Yacoub et Ilyan Lalmassi.

| Membre | Rôle | Fichiers |
| --- | --- | --- |
| Benjamin Boyer | Introduction et back-end Python | `README.md`, `main.py`, `logstream/` |
| Ismail Yacoub | Présentation, démonstration, données et tests | `data/`, `scripts/`, `logstream/simulator.py`, `notebooks/`, `tests/` |
| Gabriel Guery | Front-end Flutter (affichage) | `gui/lib/main.dart` (`build`), `gui/pubspec.yaml` |
| Ilyan Lalmassi | Lien entre le front et le back | `gui/lib/main.dart` (`lancer`), `logstream/reporting.py` (export JSON), `output/` |

Le détail de chaque partie est dans `PLAN_ORAL.md`.

## Présentation

Ce programme en ligne de commande lit des fichiers de logs (serveur web,
authentification, pare-feu), les nettoie, calcule des statistiques et repère des
comportements suspects, comme une attaque par force brute ou une IP présente sur
une liste noire.

La contrainte principale est de ne jamais charger un fichier entier en mémoire.
Tout le traitement repose donc sur des générateurs : les lignes sont lues et
traitées une par une.

Le moteur n'utilise que la bibliothèque standard de Python. Les bibliothèques de
`requirements.txt` servent au rapport (matplotlib, Jupyter), aux tests (pytest)
et aux vérifications du code (flake8, mypy).

## Installation

Il faut Python 3.10 ou plus récent.

```bash
git clone https://github.com/benjaminboyer00-cmyk/projet_python.git
cd projet_python
python3 -m venv .venv
source .venv/bin/activate      # Windows : .venv\Scripts\activate
pip install -r requirements.txt
```

## Utilisation

```bash
python main.py
```

Le programme analyse le dossier `data`, affiche les résultats de chaque module
et écrit deux fichiers dans `output` : `analysis_report.json` et
`audit_report.json`.

Options disponibles :

```bash
python main.py --help
python main.py -v                               # messages détaillés
python main.py --threshold 8 --window 60        # réglage de la force brute
python main.py --files data/auth_server.log     # choisir les fichiers
python main.py --rules rule_blacklisted_ip      # choisir les règles
python main.py --max-alerts 3                   # arrêter après 3 alertes
python main.py --simulate 20000                 # flux simulé (str, dict, tuple)
```

Par défaut, une IP est signalée après 5 échecs de connexion avec moins de
300 secondes entre deux échecs.

Pour tester sur un gros volume :

```bash
python scripts/generate_dataset.py --lines 1000000 --output /tmp/gros_jeu
python main.py --files /tmp/gros_jeu/*.log
```

Sans option, `scripts/generate_dataset.py` régénère le dossier `data`. Sa graine
est fixe, le résultat est donc toujours le même.

## Tests et qualité du code

```bash
pytest                      # 57 tests
flake8                      # respect de la PEP 8
mypy logstream main.py      # cohérence des types
```

## Rapport

```bash
jupyter notebook notebooks/rapport.ipynb
```

Le notebook est déjà exécuté. Pour le relancer : menu Run, puis Run All Cells.

## Interface graphique (bonus)

L'interface Flutter lance `main.py` puis affiche les fichiers JSON de `output`.
Son code tient dans `gui/lib/main.dart`.

Installation sous Ubuntu (une seule fois) :

```bash
sudo snap install flutter --classic
sudo apt install clang ninja-build libgtk-3-dev
```

Lancement :

```bash
cd gui
flutter create --platforms=linux .   # seulement la première fois
flutter run -d linux
```

Si l'appli plante au démarrage avec une erreur `antialiasing`, il faut la lancer
depuis un terminal normal plutôt que depuis celui de VS Code (version snap).

## Organisation du code

`main.py` lit les options, enchaîne les modules et affiche les résultats.

Le package `logstream` contient :

| Fichier | Rôle |
| --- | --- |
| `config.py` | constantes (niveaux, seuils, liste noire par défaut) |
| `models.py` | types de données |
| `exceptions.py` | exceptions du projet |
| `ingestion.py` | module 1 : lecture avec des générateurs |
| `parsing.py` | module 1 : conversion des lignes en dictionnaires |
| `pipeline.py` | module 2 : `map`, `filter`, lambdas et `match-case` |
| `aggregation.py` | module 3 : `set`, `frozenset` et `defaultdict` |
| `detection.py` | module 3 : détection de force brute |
| `rules.py` | module 4 : moteur de règles |
| `audit.py` | module 4 : audit avec `globals()` et `locals()` |
| `simulator.py` | génération des données de test |
| `reporting.py` | affichage et export JSON |

## Données de test

Le dossier `data` contient trois fichiers de logs et une liste noire. Les logs
mélangent trois formats :

```
2026-10-20T08:15:32 | WARNING | 203.0.113.7:22/SSH | root | {"event": "login", "status": "failed"}
{"timestamp": "2026-10-20T08:00:00", "level": "ERROR", "code": 500, "ip": "10.0.0.3"}
CONN 2026-10-20T08:00:10 203.0.113.66 23 TCP
```

Nous y avons aussi mis des lignes à problème (vides, JSON cassé, IP impossibles,
niveaux inconnus). Le programme les écarte sans s'arrêter et indique combien il
en a rejeté.

## Où trouver chaque point de l'énoncé

| Point demandé | Emplacement |
| --- | --- |
| `yield` | `read_log_file` (`ingestion.py`) |
| `yield from` | `read_log_sources` (`ingestion.py`) |
| Dictionnaires typés | `parsing.py` |
| Tuple `(IP, Port, Protocole)` | `parse_source` (`parsing.py`) |
| `map`, `filter`, lambdas, `filter(None, ...)` | `build_pipeline` (`pipeline.py`) |
| Normalisation et f-strings | `normalize_record` (`pipeline.py`) |
| `match-case` sur les trois formats | `route_entry` (`pipeline.py`) |
| `set` des IP en erreur | `TrafficStatistics` (`aggregation.py`) |
| `frozenset` et opérateurs `\|`, `&`, `-`, `^` | `compare_ip_sets` (`aggregation.py`) |
| `defaultdict` | `TrafficStatistics` (`aggregation.py`) |
| `while`, `for`, `break`, `continue`, `else` | `detect_brute_force` (`detection.py`) |
| `*args` et `**kwargs` | `apply_security_rules` (`rules.py`) |
| Fonctions passées en argument | règles `rule_*` (`rules.py`), `VALIDATORS` (`pipeline.py`) |
| `globals()` et `locals()` | `audit.py`, appelé à la fin de `main.py` |

## Nos choix

Un générateur ne se parcourt qu'une fois : chaque analyse relit donc les fichiers
depuis le début. C'est un peu plus lent, mais ne consomme presque pas de mémoire.
Mesuré avec `tracemalloc`, le pic passe d'environ 1,2 Mo pour 15 000 lignes à
2,1 Mo pour 457 000 lignes.

Le programme ne doit pas planter sur une mauvaise ligne. Une ligne illisible lève
une `LogParseError`, rattrapée dans `route_entry`, puis `filter(None, ...)` la
retire du flux. Une règle qui plante est comptée dans `rule_errors` et les autres
continuent. En cas d'erreur de fichier ou de configuration, `main.py` renvoie un
code de sortie différent de zéro.

Pour ajouter une règle de sécurité, il suffit d'écrire une fonction dont le nom
commence par `rule_` dans `rules.py` : elle est retrouvée grâce à `globals()`.
