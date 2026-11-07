# Moteur d'analyse de logs sécurisé

Projet final de Python, ING3.

Équipe : Benjamin Boyer, Gabriel Guery, Ismail Yacoub et Ilyan Lalmassi.

## Le projet en quelques mots

On nous a demandé de construire un outil en ligne de commande capable de lire
des fichiers de logs (serveur web, serveur d'authentification, pare-feu), de
les nettoyer, de les analyser et de repérer des comportements suspects, comme
une attaque par force brute ou une adresse IP présente sur une liste noire.

La contrainte principale était de ne jamais charger un fichier entier en
mémoire. Nous avons donc construit tout le traitement autour de générateurs :
les lignes sont lues une par une, transformées une par une, puis oubliées dès
qu'elles ont été comptées. Que le fichier fasse mille lignes ou un million, la
mémoire utilisée reste à peu près la même.

Tout le projet est écrit en Python. Le cœur du moteur n'utilise que la
bibliothèque standard. Les bibliothèques externes du fichier requirements.txt
servent uniquement au rapport (matplotlib et Jupyter), aux tests (pytest) et
aux vérifications de qualité du code (flake8 et mypy).

## Comment tester le projet

Il faut Python 3.10 ou une version plus récente. Pour vérifier :

```bash
python3 --version
```

### 1. Récupérer le projet

```bash
git clone https://github.com/benjaminboyer00-cmyk/projet_python.git
cd projet_python
```

### 2. Créer l'environnement virtuel et installer les dépendances

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Sous Windows, la deuxième commande s'écrit `.venv\Scripts\activate`.
Une fois l'environnement activé, le nom `(.venv)` apparaît au début de la
ligne de commande. Il faudra le réactiver à chaque nouveau terminal.

### 3. Lancer la démonstration

```bash
python main.py
```

Le programme analyse le jeu de test fourni dans le dossier `data` et affiche
le résultat de chaque module dans le terminal : le nombre de lignes lues et
rejetées, la répartition des logs par niveau, les adresses IP en erreur, les
attaques par force brute détectées, les alertes des règles de sécurité et la
mémoire maximale utilisée. Deux fichiers sont aussi créés dans le dossier
`output` : `analysis_report.json` avec tous les résultats, et
`audit_report.json` avec l'audit des variables du programme.

### 4. Lancer les tests

```bash
pytest
```

Les 60 tests doivent tous passer. Ils vérifient chaque module séparément, puis
le programme complet. Pour voir le détail de chaque test, ajoutez `-v`.

On peut aussi vérifier que le code respecte les conventions PEP 8 et que les
annotations de type sont cohérentes :

```bash
flake8
mypy logstream main.py
```

Aucune de ces deux commandes ne doit afficher d'erreur.

### 5. Ouvrir le rapport

```bash
jupyter notebook notebooks/rapport.ipynb
```

Le notebook est déjà exécuté, on peut donc le lire directement, y compris sur
GitHub. Pour le relancer, utilisez le menu Run puis Run All Cells.

### 6. Interface graphique (Flutter)

C'est un bonus, l'énoncé ne demande pas d'interface. Tout est calculé par
`main.py`, l'interface lit juste les fichiers JSON de `output` et affiche les
résultats de chaque module.

Installer Flutter (une fois, sous Ubuntu) :

```bash
sudo snap install flutter --classic
sudo apt install clang ninja-build libgtk-3-dev
flutter doctor
```

Lancer l'interface depuis la racine du projet :

```bash
cd gui
flutter create --platforms=linux .   # seulement la première fois
flutter run -d linux
```

Le dépôt ne contient que `pubspec.yaml` et `lib/main.dart`, la commande
`flutter create` génère le reste des fichiers dont Flutter a besoin.

On tape le chemin d'un fichier log dans la barre (par exemple
`data/auth_server.log`) puis on clique sur « Lancer l'analyse » : l'interface
exécute `main.py --files <fichier>` et affiche les résultats. Si la barre est
vide, tous les logs de `data` sont analysés.

Si l'appli plante au démarrage avec une erreur `antialiasing`, c'est le
terminal de VS Code (installé avec snap) qui pose problème : il faut la lancer
depuis un terminal normal.

### 7. Essayer d'autres réglages

Le programme accepte plusieurs options. Voici les plus utiles :

```bash
python main.py --help
python main.py -v
python main.py --threshold 8 --window 60
python main.py --files data/auth_server.log
python main.py --rules rule_blacklisted_ip rule_injection_attempt
python main.py --simulate 20000
```

L'option `-v` affiche les messages de journalisation pendant le traitement.
`--threshold` et `--window` règlent la détection de force brute : par défaut,
une IP est signalée après 5 échecs de connexion en moins de 300 secondes.
`--files` permet d'analyser ses propres fichiers. `--rules` choisit les règles
de sécurité à appliquer. `--simulate` remplace les fichiers par un flux
généré à la volée, qui mélange des chaînes, des dictionnaires et des tuples.

Pour tester sur un très gros volume et constater que la mémoire ne grimpe pas,
on peut générer un nouveau jeu de données :

```bash
python scripts/generate_dataset.py --lines 1000000 --output /tmp/gros_jeu
python main.py --files /tmp/gros_jeu/*.log
```

Sans option, `scripts/generate_dataset.py` régénère le jeu de test du dossier
`data`. Il utilise une graine fixe, donc le résultat est toujours identique.

## Organisation du code

Le point d'entrée est `main.py`. Il lit les options de la ligne de commande,
enchaîne les quatre modules et affiche les résultats.

Le code du moteur se trouve dans le package `logstream` :

- `config.py` regroupe les constantes : niveaux valides, liste noire par
  défaut, ports suspects, seuils de détection.
- `models.py` définit les types de données, notamment le dictionnaire
  `LogRecord` et le tuple `(IP, Port, Protocole)`.
- `exceptions.py` contient nos exceptions personnalisées.
- `ingestion.py` lit les fichiers ligne par ligne avec des générateurs
  (module 1).
- `parsing.py` transforme chaque ligne en dictionnaire typé (module 1).
- `pipeline.py` enchaîne le nettoyage, le filtrage et la normalisation avec
  `map`, `filter`, des lambdas et un match-case (module 2).
- `aggregation.py` calcule les statistiques avec des `set`, des `frozenset`
  et des `defaultdict` (module 3).
- `detection.py` repère les attaques par force brute (module 3).
- `rules.py` contient le moteur de règles `apply_security_rules` (module 4).
- `audit.py` inspecte les variables du programme avec `globals()` et
  `locals()` (module 4).
- `simulator.py` génère le jeu de test et le flux simulé.
- `reporting.py` s'occupe de l'affichage et de l'export JSON.

Le reste du dépôt contient le jeu de test (`data`), le script qui le génère
(`scripts`), les tests (`tests`), le rapport (`notebooks/rapport.ipynb`),
l'interface graphique Flutter (`gui`) et l'énoncé du projet.

L'interface tient dans un seul fichier, `gui/lib/main.dart`.

## Les données de test

Le dossier `data` contient trois fichiers de logs et une liste noire d'IP.
Ils mélangent volontairement trois formats de lignes, pour vérifier que le
programme sait tous les traiter.

Une ligne texte, où les champs sont séparés par des barres verticales :

```
2026-10-20T08:15:32 | WARNING | 203.0.113.7:22/SSH | root | {"event": "login", "status": "failed"}
```

Une ligne JSON complète :

```
{"timestamp": "2026-10-20T08:00:00", "level": "ERROR", "code": 500, "ip": "10.0.0.3"}
```

Une ligne de connexion du pare-feu :

```
CONN 2026-10-20T08:00:10 203.0.113.66 23 TCP
```

Nous avons aussi glissé des lignes à problème : lignes vides, commentaires,
JSON cassé, adresses IP impossibles, niveaux inconnus. Le programme doit les
écarter sans s'arrêter, et il indique combien il en a rejeté.

Chaque ligne valide devient un dictionnaire de ce genre :

```python
{
    "timestamp": datetime(2026, 10, 20, 8, 15, 32),
    "level": "WARNING",
    "source": ("203.0.113.7", 22, "SSH"),
    "ip": "203.0.113.7",
    "user_id": "root",
    "payload": {"event": "login", "status": "failed"},
    "category": "AUTH",
    "origin_format": "raw",
    "message": "[2026-10-20 08:15:32] WARNING  203.0.113.7:22 ...",
}
```

## Où trouver chaque point du cahier des charges

Module 1, ingestion. Le générateur qui lit un fichier ligne par ligne avec
`yield` est `read_log_file` dans `ingestion.py`. La lecture de plusieurs
fichiers à la suite avec `yield from` se fait dans `read_log_sources` et
`read_streams`. Le découpage des lignes en dictionnaires typés est dans
`parsing.py`, et le tuple `(IP, Port, Protocole)` est construit par
`parse_source`.

Module 2, pipeline. La chaîne de `map` et de `filter`, avec des lambdas et
`filter(None, ...)`, est construite par `build_pipeline` dans `pipeline.py`.
Les lambdas de validation sont regroupées dans `VALIDATORS`. La normalisation
du texte et la construction du message avec une f-string se font dans
`normalize_record`. Le match-case qui distingue une chaîne brute, un
dictionnaire et un tuple de connexion est dans `route_entry`. On en trouve
aussi dans `decode_line`, `categorize` et `summarize_payload`.

Module 3, agrégation. L'ensemble des IP ayant produit des erreurs est
`error_ips`, dans la classe `TrafficStatistics` de `aggregation.py`. Les
opérations entre les IP actives et la liste noire (union, intersection,
différence et différence symétrique) sont dans `compare_ip_sets`. Les
compteurs utilisent des `defaultdict`. La détection de force brute, avec une
boucle `while` qui contient une boucle `for`, et l'usage de `break`,
`continue` et `else`, se trouve dans `detect_brute_force` (`detection.py`).

Module 4, règles et introspection. La fonction
`apply_security_rules(*args, **kwargs)` est dans `rules.py`. Les règles y sont
passées comme de simples fonctions, ce qui illustre les fonctions de première
classe. On en trouve d'autres exemples avec `VALIDATORS`, la fermeture
`make_off_hours_rule` et `chain_transforms`. L'audit par `globals()` et
`locals()`, avec export du rapport, est dans `audit.py`. Il est appelé à la fin
de `main.py`. Enfin, `available_rules` utilise `globals()` pour retrouver
toutes les règles.

## Nos choix

Pour garder une mémoire constante, chaque analyse relit les fichiers depuis
le début au lieu de garder les enregistrements en mémoire. Relire un fichier
prend un peu plus de temps, mais ne consomme presque pas de mémoire. Nous
l'avons mesuré avec `tracemalloc` : en passant de 15 000 à 450 000 lignes, le
pic de mémoire passe seulement d'environ 1,3 Mo à 2 Mo, et ce qui augmente
vient surtout de la liste des alertes.

Le programme ne doit pas planter sur une mauvaise ligne. Quand une ligne est
illisible, le parsing lève une `LogParseError`. Elle est rattrapée dans
`route_entry`, qui renvoie `None`, puis `filter(None, ...)` retire la ligne
sans interrompre le flux. Un fichier introuvable est signalé puis ignoré. Une
règle de sécurité qui plante est comptée dans `rule_errors`, mais le moteur
continue avec les autres. En cas d'erreur, `main.py` renvoie un code de sortie
différent de zéro.

Ajouter une règle de sécurité est simple : il suffit d'écrire une fonction
dont le nom commence par `rule_` dans `rules.py`. Elle est retrouvée
automatiquement grâce à `globals()`.
