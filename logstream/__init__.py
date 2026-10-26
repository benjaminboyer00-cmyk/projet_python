"""
logstream - Moteur de traitement et d'analyse de flux de logs sécurisé.

Organisation du package (correspond aux modules du cahier des charges) :

* ``ingestion``   : Module 1 - générateurs mémoire (yield / yield from).
* ``parsing``     : Module 1 - parsing des lignes en dictionnaires.
* ``pipeline``    : Module 2 - filter / map / lambda et routage match-case.
* ``aggregation`` : Module 3 - set / frozenset / defaultdict.
* ``detection``   : Module 3 - détection de force brute (while/for/else).
* ``rules``       : Module 4 - moteur de règles ``*args`` / ``**kwargs``.
* ``audit``       : Module 4 - introspection via ``globals()`` / ``locals()``.

Modules utilitaires : ``config``, ``models``, ``exceptions``,
``simulator`` (génération de données de test) et ``reporting``.
"""

__version__ = "1.0.0"

__all__ = [
    "aggregation",
    "audit",
    "config",
    "detection",
    "exceptions",
    "ingestion",
    "models",
    "parsing",
    "pipeline",
    "reporting",
    "rules",
    "simulator",
]
