import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

// couleur ece
const couleurEce = Color(0xFF00737A);

const gras = TextStyle(fontWeight: FontWeight.bold);

void main() {
  runApp(const MaterialApp(home: Accueil()));
}

class Accueil extends StatefulWidget {
  const Accueil({super.key});

  @override
  State<Accueil> createState() => _AccueilState();
}

class _AccueilState extends State<Accueil> {
  TextEditingController fichier = TextEditingController();
  Map? analyse;
  Map? audit;
  String message = '';

  void lancer() async {
    setState(() {
      analyse = null;
      message = 'Analyse en cours...';
    });

    // si le champ est vide main.py prend tout data/
    List<String> arguments = ['main.py'];
    if (fichier.text != '') {
      arguments.add('--files');
      arguments.add(fichier.text);
    }

    // .. car on lance l'appli depuis gui/
    var resultat = await Process.run(
      'python3',
      arguments,
      workingDirectory: '..',
    );

    if (resultat.exitCode != 0) {
      setState(() {
        message = 'Erreur : ${resultat.stderr}';
      });
      return;
    }

    // main.py ecrit les resultats dans output/
    String texteAnalyse = File('../output/analysis_report.json').readAsStringSync();
    String texteAudit = File('../output/audit_report.json').readAsStringSync();

    setState(() {
      analyse = jsonDecode(texteAnalyse);
      audit = jsonDecode(texteAudit);
      message = '';
    });
  }

  @override
  Widget build(BuildContext context) {
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

    if (analyse != null) {
      Map pipeline = analyse!['pipeline'];
      Map stats = analyse!['statistics'];
      Map ensembles = analyse!['ip_sets'];
      Map forceBrute = analyse!['brute_force'];
      Map regles = analyse!['rules']['hits_by_rule'];

      lignes.add(const Text('\nModule 1 : ingestion', style: gras));
      lignes.add(Text('Lignes lues : ${pipeline['raw_entries']}'));

      lignes.add(const Text('\nModule 2 : pipeline', style: gras));
      lignes.add(Text('Logs valides : ${pipeline['valid_records']}'));
      lignes.add(Text('Entrées rejetées : ${pipeline['rejected']}'));
      for (var format in stats['by_format'].keys) {
        lignes.add(Text('Format $format : ${stats['by_format'][format]}'));
      }

      lignes.add(const Text('\nModule 3 : agrégation', style: gras));
      lignes.add(Text('IP uniques avec erreurs : ${stats['error_ips'].length}'));
      lignes.add(Text('Union : ${ensembles['union'].length}'));
      lignes.add(Text('Intersection : ${ensembles['intersection'].length}'));
      lignes.add(Text('Différence : ${ensembles['active_not_blacklisted'].length}'));
      lignes.add(Text('Différence symétrique : ${ensembles['symmetric_difference'].length}'));
      for (var categorie in stats['by_category'].keys) {
        lignes.add(Text('Catégorie $categorie : ${stats['by_category'][categorie]}'));
      }
      lignes.add(Text('Attaques force brute : ${forceBrute['alerts'].length}'));
      lignes.add(Text('Détection complète : ${forceBrute['complete']}'));

      lignes.add(const Text('\nModule 4 : règles et audit', style: gras));
      for (var regle in regles.keys) {
        lignes.add(Text('$regle : ${regles[regle]}'));
      }
      lignes.add(Text('Variables globals() : ${audit!['audit_module_globals'].length}'));
      lignes.add(Text('Variables locals() : ${audit!['audit_function_locals'].length}'));
    }

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
