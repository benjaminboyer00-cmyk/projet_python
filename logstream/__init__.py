"""
Package logstream : moteur d'analyse de logs.

Chaque fichier correspond à une partie de l'énoncé :

* ingestion.py   : module 1, lecture des fichiers avec des générateurs ;
* parsing.py     : module 1, découpage des lignes en dictionnaires ;
* pipeline.py    : module 2, map, filter, lambda et match-case ;
* aggregation.py : module 3, set, frozenset et defaultdict ;
* detection.py   : module 3, détection de force brute (while/for/else) ;
* rules.py       : module 4, moteur de règles (*args et **kwargs) ;
* audit.py       : module 4, audit avec globals() et locals().

Les autres fichiers sont des outils communs : config.py (constantes),
models.py (types), exceptions.py (erreurs), simulator.py (données de test)
et reporting.py (affichage et export JSON).
"""
