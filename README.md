# Engine de traitement et d'analyse de flux de données sécurisé

Projet final ING3 — Python 3.10+ — trinôme : *Nom 1, Nom 2, Nom 3*

Plateforme en ligne de commande qui ingère, filtre, transforme et analyse des
journaux de logs système/réseau **sans jamais charger les fichiers entiers en
mémoire** (chaîne de générateurs paresseux).

## Installation

```bash
python3 -m venv .venv                 # environnement virtuel isolé
source .venv/bin/activate             # Windows : .venv\Scripts\activate
pip install -r requirements.txt       # environnement figé (pip freeze)
```

Le fichier `requirements.txt` a été généré par `pip freeze` dans le venv du
projet. Le cœur du moteur n'utilise **que la bibliothèque standard** ; les
dépendances listées servent au rapport (`matplotlib`, `notebook`), aux tests
(`pytest`) et au contrôle qualité (`flake8`, `mypy`).

## Utilisation

```bash
python main.py                                  # analyse le jeu de test de data/
python main.py -v                               # avec journalisation INFO
python main.py --threshold 8 --window 60        # paramètres de force brute
python main.py --rules rule_blacklisted_ip rule_injection_attempt
python main.py --files data/auth_server.log     # fichiers au choix
python main.py --simulate 20000                 # flux simulé (str/dict/tuple)
python main.py --help                           # toutes les options
```

Résultats : affichage console + `output/analysis_report.json` (statistiques,
alertes) et `output/audit_report.json` (introspection `globals()`/`locals()`).

Régénérer le jeu de données (reproductible grâce à une graine fixe) :

```bash
python scripts/generate_dataset.py              # 5000 événements par fichier
python scripts/generate_dataset.py --lines 1000000 --output /tmp/gros_jeu
```

Contrôles qualité :

```bash
pytest                    # 55 tests unitaires et d'intégration
flake8                    # conformité PEP 8
mypy logstream main.py    # vérification du typage
```

Rapport : `notebooks/rapport.ipynb` (déjà exécuté, graphiques inclus ;
relancer avec `jupyter notebook notebooks/rapport.ipynb`).

## Arborescence

```
projet_python/
├── main.py                  # point d'entrée : pilote tout le pipeline
├── requirements.txt         # pip freeze
├── setup.cfg                # configuration flake8 / mypy / pytest
├── logstream/               # package principal
│   ├── config.py            # constantes (frozenset, tuples)
│   ├── models.py            # types : LogRecord (dict), ConnectionMeta (tuple)
│   ├── exceptions.py        # exceptions personnalisées
│   ├── ingestion.py         # Module 1 : générateurs yield / yield from
│   ├── parsing.py           # Module 1 : parsing en dictionnaires typés
│   ├── pipeline.py          # Module 2 : map / filter / lambda / match-case
│   ├── aggregation.py       # Module 3 : set / frozenset / defaultdict
│   ├── detection.py         # Module 3 : force brute (while/for/break/continue/else)
│   ├── rules.py             # Module 4 : apply_security_rules(*args, **kwargs)
│   ├── audit.py             # Module 4 : introspection globals() / locals()
│   ├── simulator.py         # génération du jeu de test et du flux simulé
│   └── reporting.py         # affichage console et export JSON
├── scripts/
│   └── generate_dataset.py  # (re)génère data/
├── data/                    # jeu de données de test fourni
│   ├── web_server.log       # requêtes HTTP + erreurs JSON
│   ├── auth_server.log      # connexions SSH + rafales de force brute
│   ├── firewall.log         # événements CONN + messages système
│   └── blacklist.txt        # IP blacklistées
├── tests/                   # tests pytest
└── notebooks/
    └── rapport.ipynb        # rapport synthétique avec graphiques
```

## Format des données

Trois formats coexistent dans les fichiers (et des lignes parasites
volontaires : vides, commentaires, corrompues, IP ou niveaux invalides) :

| Format | Exemple | Devient |
|---|---|---|
| Ligne texte | `2026-10-20T08:15:32 \| WARNING \| 203.0.113.7:22/SSH \| root \| {"event": "login", "status": "failed"}` | `str` |
| JSON | `{"timestamp": "...", "level": "ERROR", "code": 500, "ip": "10.0.0.3", ...}` | `dict` |
| Connexion | `CONN 2026-10-20T08:00:10 203.0.113.66 23 TCP` | `tuple` |

Chaque entrée valide est convertie en dictionnaire `LogRecord` :

```python
{
    "timestamp": datetime(2026, 10, 20, 8, 15, 32),
    "level": "WARNING",
    "source": ("203.0.113.7", 22, "SSH"),   # tuple immuable (IP, Port, Protocole)
    "ip": "203.0.113.7",
    "user_id": "root",
    "payload": {"event": "login", "status": "failed"},   # dict ou str brute
    "category": "AUTH",
    "origin_format": "raw",
    "message": "[2026-10-20 08:15:32] WARNING  203.0.113.7:22 ...",
}
```

## Correspondance avec le cahier des charges

| Exigence | Où |
|---|---|
| Générateur `yield` ligne par ligne | `ingestion.read_log_file` |
| Sous-générateur `yield from` sur plusieurs fichiers | `ingestion.read_log_sources`, `read_streams` |
| Parsing en dictionnaires, types variés | `parsing.py`, `models.LogRecord` |
| Tuples pour les métadonnées fixes | `models.ConnectionMeta`, `parsing.parse_source` |
| `filter()` + `lambda`, `filter(None, ...)` | `pipeline.build_pipeline`, `pipeline.VALIDATORS` |
| `map()` de normalisation (casse, nettoyage, f-strings) | `pipeline.normalize_record` |
| `match-case` : chaîne brute / dict / tuple de connexion | `pipeline.route_entry` (aussi `decode_line`, `categorize`, `summarize_payload`) |
| `set` des IP ayant généré des erreurs | `aggregation.TrafficStatistics.error_ips` |
| `frozenset` blacklist + `\|`, `&`, `-`, `^` | `aggregation.compare_ip_sets` |
| `defaultdict` (pas de `KeyError`) | `aggregation.TrafficStatistics`, `count_by`, `detection` |
| Force brute : `while` + `for`, `break`, `continue`, `else` | `detection.detect_brute_force` |
| `apply_security_rules(*args, **kwargs)` | `rules.apply_security_rules` |
| Fonctions de première classe | règles passées en argument, `VALIDATORS`, `make_off_hours_rule` (closure), `chain_transforms` |
| `globals()` / `locals()` + export d'un rapport | `audit.build_audit_report`, `audit.export_audit_report`, `main.run`, `rules.available_rules` |
| Point d'entrée `main.py` | `main.py` |
| Rapport `.ipynb` | `notebooks/rapport.ipynb` |

## Choix techniques

- **Mémoire constante.** Toute la chaîne (lecture → parsing → filtrage →
  normalisation) est paresseuse. Les analyses (statistiques, force brute,
  règles) relisent chacune les fichiers via un pipeline neuf plutôt que de
  stocker les enregistrements : relire un fichier coûte du temps disque,
  stocker coûterait de la RAM proportionnelle aux données. Mesure
  (`tracemalloc`) : de 15 000 à 450 000 lignes, le pic passe de ~1,3 Mo à
  ~2 Mo seulement (ce qui reste vient de la liste des alertes).
- **Robustesse.** Une ligne invalide lève `LogParseError`, interceptée dans
  `route_entry` qui renvoie `None` ; `filter(None, ...)` l'élimine sans
  interrompre le flux. Un fichier absent est signalé et ignoré. Une règle de
  sécurité qui plante est comptabilisée dans `rule_errors` sans arrêter le
  moteur. `main.py` renvoie un code de sortie non nul en cas d'erreur.
- **Extensibilité.** Ajouter une règle = écrire une fonction `rule_xxx` dans
  `rules.py` ; elle est découverte automatiquement via `globals()`.
