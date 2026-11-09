// Interface graphique du projet (bonus, non demandée par l'énoncé).
//
// Elle ne fait aucun calcul : elle lance main.py, attend la fin, puis lit les
// deux fichiers JSON écrits dans output/ et affiche les résultats par module.

import 'dart:convert'; // pour jsonDecode
import 'dart:io'; // pour lancer main.py et lire les fichiers

import 'package:flutter/material.dart';

// --- Styles ---
// Le bleu-vert du logo de l'ECE.
const couleurEce = Color(0xFF00737A);
const gras = TextStyle(fontWeight: FontWeight.bold);

// Point de départ de l'application.
void main() {
  runApp(const MaterialApp(
    debugShowCheckedModeBanner: false, // enlève le bandeau "debug"
    home: Accueil(),
  ));
}

// Widget "stateful" : son contenu change après l'analyse. Flutter sépare le
// widget (Accueil) de son état (_AccueilState), qui garde les données.
class Accueil extends StatefulWidget {
  const Accueil({super.key});

  @override
  State<Accueil> createState() => _AccueilState();
}

class _AccueilState extends State<Accueil> {
  // Contenu de la barre de saisie.
  TextEditingController fichier = TextEditingController();
  // Contenu des fichiers JSON. "?" : ils valent null tant qu'il n'y a pas
  // eu d'analyse.
  Map? analyse;
  Map? audit;
  String message = ''; // texte d'état : analyse en cours ou erreur

  // Appelée quand on clique sur le bouton. "async" permet d'attendre la fin
  // de main.py avec "await" sans bloquer l'interface.
  void lancer() async {
    // setState redessine la page avec les nouvelles valeurs.
    setState(() {
      analyse = null;
      message = 'Analyse en cours...';
    });

    // Si le champ est vide, main.py analyse tous les fichiers de data/.
    List<String> arguments = ['main.py'];
    if (fichier.text != '') {
      arguments.add('--files');
      arguments.add(fichier.text);
    }

    // Lance Python dans le dossier parent, car l'appli démarre depuis gui/.
    var resultat = await Process.run(
      'python3',
      arguments,
      workingDirectory: '..',
    );

    // Un code de sortie différent de 0 signifie que main.py a échoué : on
    // affiche le message d'erreur de Python.
    if (resultat.exitCode != 0) {
      setState(() {
        message = 'Erreur : ${resultat.stderr}';
      });
      return;
    }

    // main.py a écrit ses résultats dans output/.
    String texteAnalyse = File('../output/analysis_report.json').readAsStringSync();
    String texteAudit = File('../output/audit_report.json').readAsStringSync();

    // On convertit le texte JSON en Map, puis on redessine la page.
    setState(() {
      analyse = jsonDecode(texteAnalyse);
      audit = jsonDecode(texteAudit);
      message = '';
    });
  }

  // Flutter appelle build à chaque setState pour construire la page.
  @override
  Widget build(BuildContext context) {
    // Le haut de la page : le champ, le bouton et le message d'état.
    List<Widget> lignes = [
      TextField(
        controller: fichier,
        decoration: const InputDecoration(
          labelText: 'Fichier log (vide = tous les logs de data/)',
        ),
      ),
      const SizedBox(height: 10),
      ElevatedButton(
        onPressed: lancer,
        child: const Text('Lancer l\'analyse'),
      ),
      Text(message),
    ];

    // On n'ajoute les résultats qu'après une analyse. Le "!" indique à Dart
    // que la variable n'est plus null ici.
    if (analyse != null) {
      // Les différentes parties du rapport JSON.
      Map pipeline = analyse!['pipeline'];
      Map stats = analyse!['statistics'];
      Map ensembles = analyse!['ip_sets'];
      Map forceBrute = analyse!['brute_force'];
      Map regles = analyse!['rules']['hits_by_rule'];

      // Module 1 : générateurs yield / yield from.
      lignes.add(const Text('\nModule 1 : ingestion', style: gras));
      lignes.add(Text('Lignes lues : ${pipeline['raw_entries']}'));

      // Module 2 : filter, map et match-case (raw, dict, tuple).
      lignes.add(const Text('\nModule 2 : pipeline', style: gras));
      lignes.add(Text('Logs valides : ${pipeline['valid_records']}'));
      lignes.add(Text('Entrées rejetées : ${pipeline['rejected']}'));
      for (var format in stats['by_format'].keys) {
        lignes.add(Text('Format $format : ${stats['by_format'][format]}'));
      }

      // Module 3 : set / frozenset, defaultdict et force brute.
      lignes.add(const Text('\nModule 3 : agrégation', style: gras));
      lignes.add(Text('IP uniques avec erreurs : ${stats['error_ips'].length}'));
      lignes.add(Text('Union : ${ensembles['union'].length}'));
      lignes.add(Text('Intersection : ${ensembles['intersection'].length}'));
      lignes.add(Text('Différence : ${ensembles['active_not_blacklisted'].length}'));
      lignes.add(Text('Différence symétrique : ${ensembles['symmetric_difference'].length}'));
      for (var categorie in stats['by_category'].keys) {
        lignes.add(Text('Catégorie $categorie : ${stats['by_category'][categorie]}'));
      }
      // complete vaut true si le else du while a été exécuté.
      lignes.add(Text('Attaques force brute : ${forceBrute['alerts'].length}'));
      lignes.add(Text('Détection complète : ${forceBrute['complete']}'));

      // Module 4 : apply_security_rules et audit avec globals() / locals().
      lignes.add(const Text('\nModule 4 : règles et audit', style: gras));
      for (var regle in regles.keys) {
        lignes.add(Text('$regle : ${regles[regle]}'));
      }
      lignes.add(Text('Variables globals() : ${audit!['audit_module_globals'].length}'));
      lignes.add(Text('Variables locals() : ${audit!['audit_function_locals'].length}'));
    }

    // Structure de la page : une barre en haut et une liste qui défile.
    return Scaffold(
      appBar: AppBar(
        title: const Text('LogStream'),
        backgroundColor: couleurEce,
        foregroundColor: Colors.white,
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: lignes,
      ),
    );
  }
}
