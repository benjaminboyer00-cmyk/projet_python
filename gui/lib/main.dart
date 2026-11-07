import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

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

    // on lance main.py depuis le dossier du projet (le parent de gui/)
    List<String> arguments = ['main.py'];
    if (fichier.text != '') {
      arguments.add('--files');
      arguments.add(fichier.text);
    }
    var res = await Process.run('python3', arguments, workingDirectory: '..');

    if (res.exitCode != 0) {
      setState(() => message = 'Erreur : ${res.stderr}');
      return;
    }

    // on lit les rapports json écrits par main.py
    setState(() {
      analyse = jsonDecode(File('../output/analysis_report.json').readAsStringSync());
      audit = jsonDecode(File('../output/audit_report.json').readAsStringSync());
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
      ElevatedButton(onPressed: lancer, child: const Text('Lancer l\'analyse')),
      Text(message),
    ];

    if (analyse != null) {
      Map p = analyse!['pipeline'];
      Map s = analyse!['statistics'];
      Map ip = analyse!['ip_sets'];
      Map bf = analyse!['brute_force'];
      Map regles = analyse!['rules']['hits_by_rule'];

      lignes.add(const Text('\nModule 1 : ingestion', style: TextStyle(fontWeight: FontWeight.bold)));
      lignes.add(Text('Lignes lues : ${p['raw_entries']}'));

      lignes.add(const Text('\nModule 2 : pipeline', style: TextStyle(fontWeight: FontWeight.bold)));
      lignes.add(Text('Logs valides : ${p['valid_records']}'));
      lignes.add(Text('Entrées rejetées : ${p['rejected']}'));
      for (var f in s['by_format'].keys) {
        lignes.add(Text('Format $f : ${s['by_format'][f]}'));
      }

      lignes.add(const Text('\nModule 3 : agrégation', style: TextStyle(fontWeight: FontWeight.bold)));
      lignes.add(Text('IP uniques avec erreurs : ${s['error_ips'].length}'));
      lignes.add(Text('Union : ${ip['union'].length}'));
      lignes.add(Text('Intersection : ${ip['intersection'].length}'));
      lignes.add(Text('Différence : ${ip['active_not_blacklisted'].length}'));
      lignes.add(Text('Différence symétrique : ${ip['symmetric_difference'].length}'));
      for (var c in s['by_category'].keys) {
        lignes.add(Text('Catégorie $c : ${s['by_category'][c]}'));
      }
      lignes.add(Text('Attaques force brute : ${bf['alerts'].length}'));
      lignes.add(Text('Détection complète : ${bf['complete']}'));

      lignes.add(const Text('\nModule 4 : règles et audit', style: TextStyle(fontWeight: FontWeight.bold)));
      for (var r in regles.keys) {
        lignes.add(Text('$r : ${regles[r]}'));
      }
      lignes.add(Text('Variables globals() : ${audit!['audit_module_globals'].length}'));
      lignes.add(Text('Variables locals() : ${audit!['audit_function_locals'].length}'));
    }

    return Scaffold(
      // couleur de l'ECE
      appBar: AppBar(title: const Text('LogStream'), backgroundColor: const Color(0xFF00737A), foregroundColor: Colors.white),
      body: ListView(padding: const EdgeInsets.all(20), children: lignes),
    );
  }
}
