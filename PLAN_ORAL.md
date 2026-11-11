# Plan de l'oral

| Ordre | Qui | Sujet | Dossiers et fichiers concernés |
| --- | --- | --- | --- |
| 1 | Benjamin | Introduction et réponse au besoin | `ÉNONCÉ DU PROJET FINAL.docx`, `README.md` |
| 2 | Ismail | Présentation du projet et démonstration | `data/`, `main.py`, `output/`, `notebooks/rapport.ipynb`, `tests/` |
| 3 | Gabriel | Front-end | `gui/lib/main.dart`, `gui/pubspec.yaml` |
| 4 | Ilyan | Lien entre le front et le back | `gui/lib/main.dart` (`lancer`), `main.py`, `logstream/reporting.py`, `output/` |
| 5 | Benjamin | Back-end | `logstream/`, `main.py` |

## Les technologies

| Partie | Technologie | Où |
| --- | --- | --- |
| Front-end | Application de bureau **Flutter**, écrite en **Dart**, pour Linux | `gui/` |
| Back-end | **Python 3.10+**, uniquement la bibliothèque standard | `main.py`, `logstream/` |
| Lien front/back | `Process.run` lance `main.py`, puis échange par **fichiers JSON**. Ni serveur ni API HTTP | `output/` |
| Rapport | Jupyter et matplotlib | `notebooks/` |
| Tests et qualité | pytest, flake8 et mypy | `tests/`, `setup.cfg` |
| Environnement | venv et `pip freeze` | `.venv`, `requirements.txt` |

## Qui répond sur quel fichier

| Fichier ou dossier | Responsable |
| --- | --- |
| `ÉNONCÉ DU PROJET FINAL.docx`, `README.md` | Benjamin (introduction) |
| `requirements.txt`, `setup.cfg`, `.gitignore` | Benjamin (introduction) |
| `data/`, `scripts/generate_dataset.py`, `logstream/simulator.py` | Ismail |
| `notebooks/rapport.ipynb` | Ismail |
| `tests/` | Ismail pour le rôle des tests, Benjamin pour le détail du back |
| `gui/lib/main.dart` : affichage (`build`, widgets, `setState`) | Gabriel |
| `gui/pubspec.yaml` | Gabriel |
| `gui/lib/main.dart` : `lancer()` | Ilyan |
| `logstream/reporting.py` : `to_jsonable`, `export_json` | Ilyan |
| `output/analysis_report.json`, `output/audit_report.json` | Ilyan |
| `main.py` : options, enchaînement, codes de sortie | Benjamin (back-end), Ilyan pour les codes de sortie |
| Le reste de `logstream/` | Benjamin (back-end) |

## Ce que tout le monde doit savoir

**Le projet en une phrase :** un outil Python en ligne de commande qui lit de gros
fichiers de logs sans les charger en mémoire, les nettoie, calcule des statistiques
et détecte des comportements suspects.

**Le trajet d'une donnée :** fichier de logs → générateurs → pipeline `map`/`filter`
→ statistiques, détection et règles → rapports JSON dans `output/` → interface Flutter.

**Les chiffres du jeu de test** (`python main.py`) :

| Mesure | Valeur |
| --- | --- |
| Lignes lues | 15 225 |
| Lignes vides ou commentaires | 88 |
| Rejetées (illisibles ou invalides) | 131, dont 101 au parsing et 30 à la validation |
| Logs valides | 15 006 |
| Formats | raw 10 130, tuple 4 266, dict 610 |
| Niveaux | INFO 11 872, WARNING 2 253, ERROR 721, CRITICAL 160 |
| IP actives / IP en erreur | 46 / 14 |
| Liste noire | 5 IP, dont 3 actives |
| Attaques par force brute | 70 |
| Alertes des règles | 1 728 |
| Pic mémoire | 1,2 Mo pour 15 000 lignes, 2,1 Mo pour 457 000 lignes |
| Tests | 57, tous réussis |

---

## 1. Benjamin : introduction et réponse au besoin

**Déroulé**

1. Présenter l'équipe et annoncer qui parle de quoi.
2. Le contexte, puis le besoin de l'énoncé.
3. La contrainte principale : ne jamais charger un fichier entier en mémoire.
4. Notre réponse : un moteur Python en 4 modules et une interface Flutter en bonus.
5. Le tableau besoin → réponse.

**Ne pas traiter ici :** le détail du code (partie 5) et la démonstration (partie 2).

**À expliquer**

- Le contexte : les logs d'un système (web, authentification, pare-feu) sont
  volumineux, hétérogènes et parfois abîmés.
- Le besoin de l'énoncé : ingérer, filtrer, transformer et analyser ces données en
  ligne de commande, **sans charger les fichiers entiers en RAM**, avec une
  architecture modulaire et un environnement isolé.
- La réponse : un traitement en flux, ligne par ligne, découpé en 4 modules.

**Tableau besoin → réponse**

| Besoin de l'énoncé | Notre réponse | Barème |
| --- | --- | --- |
| Environnement isolé, `.py` séparés des `.ipynb` | `.venv`, `requirements.txt` (`pip freeze`), package `logstream`, notebook pour le rapport seulement | 2 pts |
| Ne pas saturer la RAM | Générateurs `yield` et `yield from` | 4 pts |
| Structures de données adaptées | `set`, `frozenset`, `defaultdict`, tuples, `match-case` | 4 pts |
| Programmation fonctionnelle | `map`, `filter`, lambdas, fonctions passées en argument | 4 pts |
| Moteur de règles et introspection | `apply_security_rules(*args, **kwargs)`, `globals()`, `locals()` | 3 pts |
| Qualité et robustesse | PEP 8 (flake8), typage (mypy), exceptions, `else` des boucles, tests | 3 pts |

**En plus de la demande :** l'interface Flutter (bonus), le flux simulé et les tests.

**Questions probables**

- *Pourquoi un traitement en flux ?* La mémoire ne dépend plus du nombre de lignes.
- *L'énoncé parle de temps réel, est-ce le cas ?* Le programme traite des fichiers et
  un flux simulé (`--simulate`), comme le demande le module 1. Il ne surveille pas un
  fichier en cours d'écriture.

**Transition vers Ismail :** « Voyons maintenant comment se présente l'outil et ce
qu'il produit. »

---

## 2. Ismail : présentation du projet et démonstration

**Déroulé**

1. L'organisation du dépôt, dossier par dossier.
2. Les données : les 3 formats et les lignes abîmées.
3. Lancer `python main.py` et commenter le résultat.
4. Montrer une ou deux options.
5. Le rapport et son graphique de mémoire.
6. Le rôle des tests, avec `pytest`.

**Ne pas traiter ici :** comment le code fonctionne (partie 5) et l'interface
(parties 3 et 4).

**Dossiers à connaître**

| Élément | Rôle |
| --- | --- |
| `main.py` | Point d'entrée, lance toute l'analyse |
| `logstream/` | Le moteur, un fichier par thème |
| `data/` | 3 fichiers de logs et la liste noire |
| `scripts/generate_dataset.py`, `logstream/simulator.py` | Génèrent le jeu de test, toujours identique grâce à une graine fixe |
| `tests/` | Tests pytest |
| `notebooks/rapport.ipynb` | Rapport avec les graphiques |
| `gui/` | Interface Flutter (bonus) |
| `output/` | Rapports JSON, créés à l'exécution et non versionnés |

**Les trois formats de logs** (voir aussi le README, partie « Données de test ») :
ligne texte séparée par des ` | `, objet JSON, ligne de connexion `CONN`. Le jeu de
test contient exprès des lignes abîmées pour montrer que le programme ne plante pas.

**Démonstration**

```bash
source .venv/bin/activate
python main.py                              # analyse complète
python main.py --files data/auth_server.log # un seul fichier : 5 032 lignes, 70 attaques
python main.py --threshold 8 --window 60    # autre réglage de force brute
python main.py --simulate 20000             # flux simulé : str, dict et tuple
pytest                                      # 57 tests
```

**À savoir lire dans le terminal :** le bilan des lignes, la répartition par niveau,
les opérations sur les IP, les attaques détectées, les alertes par règle et le pic
de mémoire.

**À montrer dans le rapport :** le graphique de mémoire. À 20 000 lignes, une liste
consomme environ 21 Mo contre environ 50 Kio pour le pipeline.

**Questions probables**

- *Pourquoi 1 728 alertes pour seulement 70 attaques ?* Ce ne sont pas les mêmes
  mesures. `rule_blacklisted_ip` déclenche une alerte par log (888 à elle seule),
  alors qu'une attaque regroupe toute une série d'échecs.
- *Le rapport affiche 1 956 alertes, pourquoi ?* Il ajoute une règle d'exemple,
  `rule_admin`, écrite dans le notebook.
- *À quoi servent les tests ?* Ils vérifient chaque module, puis le programme complet :
  ingestion 19, règles et audit 10, détection 8, pipeline 8, `main` 6, agrégation 4,
  export 2.

**Transition vers Gabriel :** « Pour que ces résultats soient plus lisibles, nous avons
ajouté une interface graphique. »

---

## 3. Gabriel : front-end

**Ce qu'est le front :** une application de bureau Flutter, écrite en Dart. Ce n'est
pas un site web. Elle utilise seulement Flutter et ses composants Material.

**Déroulé**

1. Ce qu'est le front et pourquoi c'est un bonus.
2. La structure de `main.dart`, du haut vers le bas.
3. Le cycle d'affichage : `setState()` provoque un nouvel appel à `build()`.
4. La démonstration, avec les 3 essais.

**Ne pas traiter ici :** comment les données arrivent jusqu'à l'interface (partie 4).

**Fichiers à connaître**

- `gui/lib/main.dart` : toute l'interface, en un seul fichier.
- `gui/pubspec.yaml` : la configuration du projet Flutter.
- Le reste est généré par `flutter create`, c'est pourquoi il n'est pas dans le dépôt.

**À expliquer dans `main.dart`**

| Élément | Rôle |
| --- | --- |
| `main()` et `MaterialApp` | Démarrent l'application |
| `Accueil` / `_AccueilState` | Widget *stateful* : la page change après l'analyse |
| `TextEditingController fichier` | Contenu du champ de saisie |
| `Map? analyse`, `Map? audit` | Résultats, `null` tant qu'aucune analyse n'a été lancée |
| `message` | Texte « Analyse en cours... » ou erreur |
| `lancer()` | Appelée par le bouton (son fonctionnement est détaillé par Ilyan) |
| `setState()` | Met à jour les données et redessine la page |
| `build()` | Construit la page : champ, bouton, puis résultats par module |
| `Scaffold`, `AppBar`, `ListView` | Structure : barre en haut et liste qui défile |

**Démonstration** (à répéter sur l'ordinateur de l'oral)

```bash
source .venv/bin/activate   # depuis la racine du projet
cd gui
flutter run -d linux
```

1. Champ vide → « Lancer l'analyse » : 15 225 lignes lues, 70 attaques, détection
   complète `true`.
2. `data/auth_server.log` : 5 032 lignes lues.
3. `data/absent.log` : le message d'erreur de Python s'affiche.

**Valeurs attendues à l'écran avec le champ vide**

| Module | Affichage |
| --- | --- |
| 1 | Lignes lues : 15225 |
| 2 | Logs valides : 15006, entrées rejetées : 131, formats raw 10130, dict 610, tuple 4266 |
| 3 | IP uniques avec erreurs : 14, union 48, intersection 3, différence 43, différence symétrique 45 |
| 3 | Catégories AUTH 5006, HTTP 5000, NETWORK 4266, SYSTEM 734 |
| 3 | Attaques force brute : 70, détection complète : true |
| 4 | `rule_blacklisted_ip` 888, `rule_suspicious_port` 347, `rule_off_hours_error` 182, `rule_critical_event` 160, `rule_injection_attempt` 151 |
| 4 | Variables globals() : 13, variables locals() : 5 |

**À savoir**

- Le front ne fait **aucun calcul**, il ne fait qu'afficher.
- Le champ accepte un seul fichier, avec un chemin relatif à la racine du projet.
- Il faut lancer l'application depuis `gui/`.
- La première fois, il faut exécuter `flutter create --platforms=linux .`.
- En cas d'erreur `antialiasing`, lancer depuis un terminal normal plutôt que VS Code.

**Questions probables**

- *Pourquoi Flutter ?* Interface bureau en un seul fichier, et elle n'est qu'un bonus :
  elle reste séparée du moteur Python. (Réponse à confirmer par Gabriel.)
- *Que comptent « Variables globals() » et « locals() » ?* Ceux d'`audit.py` et de sa
  fonction `build_audit_report`. Les variables de `main.py` sont dans le rapport JSON,
  sous `scopes`, mais l'interface ne les affiche pas.
- *Pourquoi `StatefulWidget` ?* L'affichage dépend de données qui changent.
- *Pourquoi les résultats sont en texte, sans graphique ?* Le but est d'afficher un
  résultat par module ; les graphiques sont dans le rapport.
- *Pourquoi `async` et `await` ?* Pour attendre la fin de `main.py` sans figer la page.

**Transition vers Ilyan :** « Cette interface ne calcule rien : voyons comment elle
récupère les résultats du moteur. »

---

## 4. Ilyan : lien entre le front et le back

**Idée principale :** il n'y a ni serveur ni API HTTP. Le front **lance `main.py`
comme un programme**, puis **lit les fichiers JSON** que celui-ci écrit.

**Déroulé**

1. L'idée principale : un programme lancé, puis des fichiers lus.
2. Le trajet complet, du clic jusqu'à l'affichage.
3. Les conversions de `to_jsonable`.
4. Le contrat JSON entre les deux parties.
5. La gestion des erreurs avec les codes de sortie.

**Ne pas traiter ici :** les widgets (partie 3) et les calculs du moteur (partie 5).

**Le trajet complet**

| Étape | Où | Ce qui se passe |
| --- | --- | --- |
| 1 | `main.dart`, `lancer()` | Prépare `['main.py']`, plus `--files <chemin>` si le champ est rempli |
| 2 | `main.dart` | `Process.run('python3', arguments, workingDirectory: '..')` lance Python à la racine |
| 3 | `main.py`, `main()` et `run()` | Lit les options et lance les analyses |
| 4 | `reporting.py`, `to_jsonable()` | Convertit les résultats en types acceptés par JSON |
| 5 | `reporting.py`, `export_json()` | Écrit `output/analysis_report.json` |
| 6 | `audit.py`, `export_audit_report()` | Écrit `output/audit_report.json` |
| 7 | `main.dart` | Vérifie `exitCode` : si différent de 0, affiche `stderr` |
| 8 | `main.dart` | Lit les deux fichiers et les décode avec `jsonDecode` |
| 9 | `main.dart` | `setState()` déclenche `build()`, qui affiche les résultats |

**Les conversions de `to_jsonable`** (JSON ne connaît pas ces types Python)

| Python | JSON |
| --- | --- |
| `datetime` | texte ISO |
| `set`, `frozenset` | liste triée |
| `tuple` | liste |
| objet (`TrafficStatistics`, `DetectionResult`...) | dictionnaire, via `vars()` |

C'est pour cela que le front peut écrire `ensembles['union'].length`.

**Le contrat JSON : clés utilisées par le front**

| Section | Clés | Produit par |
| --- | --- | --- |
| `pipeline` | `raw_entries`, `valid_records`, `rejected` | `build_pipeline`, `run` |
| `statistics` | `by_format`, `by_category`, `error_ips` | `TrafficStatistics` |
| `ip_sets` | `union`, `intersection`, `active_not_blacklisted`, `symmetric_difference` | `compare_ip_sets` |
| `brute_force` | `alerts`, `complete` | `detect_brute_force` |
| `rules` | `hits_by_rule` | `apply_security_rules` |
| rapport d'audit | `audit_module_globals`, `audit_function_locals` | `build_audit_report` |

**Codes de sortie de `main.py`**

| Code | Signification |
| --- | --- |
| 0 | Tout s'est bien passé |
| 1 | Erreur de fichier (absent, droits...) |
| 2 | Mauvaise configuration (par exemple une règle inconnue) |
| 130 | Interruption avec Ctrl+C |

**Questions probables**

- *Pourquoi pas une API HTTP ?* L'énoncé demande un outil en ligne de commande et
  l'interface est un bonus local pour un seul utilisateur. Un serveur compliquerait le
  projet sans rien apporter ici.
- *Le texte affiché dans le terminal est-il utilisé ?* Non, le front ne lit que le JSON
  en cas de succès, et `stderr` en cas d'erreur.
- *Que se passe-t-il si on renomme une clé du JSON ?* Le front ne la trouve plus et
  l'affichage plante : les noms des clés sont un contrat entre les deux parties.
- *Quel Python est utilisé ?* Celui nommé `python3` dans le `PATH`, donc normalement
  celui du venv s'il est activé. Avec le Python du système, le moteur fonctionne aussi,
  car il n'utilise que la bibliothèque standard.
- *Quelles sont les limites ?* Le résultat n'arrive qu'à la fin de l'analyse, chaque
  analyse écrase la précédente, et le chemin de `output/` est fixe.

**Transition vers Benjamin :** « On a vu ce que reçoit l'interface. Voyons maintenant
comment le moteur produit ces résultats. »

---

## 5. Benjamin : back-end

**Déroulé**

1. L'organisation de `logstream/` et le rôle de `main.py`.
2. Module 1 : la lecture avec les générateurs.
3. Module 2 : les 8 étapes du pipeline.
4. Module 3 : les ensembles, les compteurs et la force brute.
5. Module 4 : le moteur de règles et l'audit.
6. La mémoire et la robustesse.
7. La conclusion de l'oral.

**Ne pas traiter ici :** le format JSON et l'interface (parties 3 et 4).

**Organisation de `logstream/`**

| Module de l'énoncé | Fichier | Fonctions à connaître |
| --- | --- | --- |
| 1 | `ingestion.py` | `read_log_file`, `read_log_sources`, `load_blacklist` |
| 1 | `parsing.py` | `decode_line`, `parse_text_line`, `parse_dict_entry`, `parse_connection_tuple`, `parse_source`, `build_record` |
| 2 | `pipeline.py` | `build_pipeline`, `route_entry`, `VALIDATORS`, `normalize_record`, `count_items` |
| 3 | `aggregation.py` | `TrafficStatistics`, `collect_statistics`, `compare_ip_sets`, `analyze_error_ips` |
| 3 | `detection.py` | `detect_brute_force`, `login_status` |
| 4 | `rules.py` | `apply_security_rules`, les règles `rule_*`, `available_rules` |
| 4 | `audit.py` | `snapshot_scope`, `build_audit_report` |
| Outils | `config.py`, `models.py`, `exceptions.py`, `reporting.py` | constantes, types, erreurs, affichage dans le terminal (`print_*`) |

**Module 1 : lecture**

- `yield` met la fonction en pause : une seule ligne est en mémoire à la fois.
- `yield from` enchaîne les fichiers sans liste intermédiaire.
- Chaque ligne devient un dictionnaire. La source est un tuple `(IP, Port, Protocole)` :
  immuable, et utilisable dans un `set`.

**Module 2 : pipeline** (`build_pipeline`, à savoir réciter dans l'ordre)

1. `map(strip_entry)` enlève les espaces.
2. `filter(None, ...)` retire les entrées vides.
3. `filter(lambda ...)` retire les commentaires.
4. `map(decode_entry)` donne une chaîne, un dictionnaire ou un tuple.
5. `map(route_entry)` choisit le parseur avec un `match-case`. Illisible → `None`.
6. `filter(None, ...)` retire ces `None`.
7. `filter(is_valid_record)` applique les `VALIDATORS`.
8. `map(normalize_record)` normalise et construit le message en f-string.

`map` et `filter` sont paresseux : rien n'est calculé tant qu'on ne parcourt pas le flux.

**Module 3 : agrégation et détection**

- `set` : IP uniques automatiquement. `frozenset` : liste noire immuable.
- Opérateurs : `|` union (48), `&` intersection (3), `-` différence (43), `^` différence
  symétrique (45).
- `defaultdict(int)` : une clé inconnue vaut 0, donc pas de `KeyError`.
- Force brute : au moins 5 échecs de suite pour une IP, avec au plus 300 s **entre deux
  échecs**. Une réussite remet la série à zéro. Une seule alerte par série.

**La structure de `detect_brute_force`** (à savoir expliquer au tableau)

| Instruction | Rôle |
| --- | --- |
| `while batch := list(islice(...))` | Découpe le flux en lots de 500 : un lot = un cycle |
| `for record in batch` | Parcourt les événements du lot |
| `continue` | Passe les logs qui ne sont pas des connexions, les réussites et les séries sans nouvelle alerte |
| `break` | S'arrête quand `max_alerts` est atteint |
| `else` du `for` | Pas de `break` : le cycle est complet (31 cycles sur le jeu de test) |
| `else` du `while` | Pas de `break` : tout le flux est analysé, `complete = True` |

À montrer : `python main.py --max-alerts 3` affiche « INTERROMPUE ».

**Module 4 : règles et audit**

- `*args` reçoit les règles, qui sont des fonctions passées en argument.
- `**kwargs` reçoit `records`, `max_alerts` et les options transmises à chaque règle.
- Les 5 règles : IP blacklistée, événement critique, port sensible, injection, erreur
  hors horaires.
- `available_rules` utilise `globals()` : écrire une fonction `rule_...` suffit à
  l'ajouter au moteur.
- L'audit reçoit `globals()` et `locals()` de `main.py` et de `run()`. Il décrit le type,
  la taille et un aperçu de chaque variable (38 globales, 17 locales).

**Pourquoi la mémoire reste faible :** on ne garde que les compteurs, les ensembles d'IP,
un lot de 500 logs au maximum et des alertes. Les alertes des règles sont limitées à 1 000.

**Robustesse :** mauvaise ligne → `LogParseError` rattrapée dans `route_entry`. Fichier
illisible → signalé puis ignoré. Règle qui plante → comptée dans `rule_errors`, les autres
continuent.

**Questions probables**

- *Pourquoi relire les fichiers plusieurs fois ?* Un générateur ne se parcourt qu'une
  fois. Relire coûte du temps, garder les logs coûterait de la mémoire. `run()` ouvre
  trois fois le flux pour les analyses, et une quatrième pour l'aperçu.
- *`list(islice(...))` ne charge-t-il pas les données en mémoire ?* Seulement 500 logs
  au maximum, quelle que soit la taille du fichier.
- *Pourquoi la mémoire augmente-t-elle un peu ?* Les alertes de force brute sont toutes
  gardées : leur nombre grandit avec le nombre d'attaques.
- *Pourquoi `match-case` plutôt que `if` ?* Il vérifie la forme des données (clés d'un
  dictionnaire, longueur et types d'un tuple) en une seule ligne.
- *Pourquoi le `:=` dans le `while` ?* Sans lui, il faudrait un `break` pour sortir à la
  fin du flux, et le `else` du `while` ne s'exécuterait jamais.
- *Pourquoi `globals()` dans `audit.py` ne suffit pas ?* Il renverrait les variables
  d'`audit.py`. C'est pour cela que `main.py` transmet les siennes.
- *Pourquoi 10.0.0.1 est-elle l'IP en erreur la plus active ?* C'est la source des
  messages système du pare-feu. Une IP « à surveiller » est une piste à vérifier, pas
  une attaque prouvée.
- *Quelles sont les limites ?* Pas de tri par date entre les fichiers, seuils fixes au
  lancement, et détection d'injection limitée à des morceaux de texte connus.
  `sys.getsizeof` ne mesure que le conteneur, pas son contenu.

**Conclusion de l'oral**

- Le besoin est couvert : les 4 modules de l'énoncé sont implémentés et testés.
- La contrainte principale est tenue : 2,1 Mo de pic pour 457 000 lignes.
- Le programme résiste aux données abîmées : 131 entrées écartées sans interruption.
- Terminer en remerciant le jury et en proposant de répondre aux questions.

---

## Liste de vérification avant l'oral

**Préparer l'ordinateur de l'oral**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

sudo snap install flutter --classic
sudo apt install clang ninja-build libgtk-3-dev
flutter doctor              # doit valider la partie Linux desktop

cd gui
flutter create --platforms=linux .
```

**À cocher**

- [ ] Lancer `python main.py` et `pytest` (57 tests).
- [ ] Faire les 3 essais de la démonstration Flutter et comparer aux valeurs attendues.
- [ ] Ouvrir le rapport à l'avance dans Jupyter, sur le graphique de mémoire.
- [ ] Répéter les transitions entre les intervenants.
- [ ] Chacun relit les commentaires des fichiers de sa partie.
