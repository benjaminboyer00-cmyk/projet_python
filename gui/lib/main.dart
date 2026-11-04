import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

// couleur de l'ECE
const ece = Color(0xFF00737A);

void main() {
  runApp(const MaterialApp(
    title: 'LogStream',
    debugShowCheckedModeBanner: false,
    home: Accueil(),
  ));
}

// le projet python est le dossier au dessus de gui/
String dossierProjet() {
  if (Directory.current.path.endsWith('gui')) {
    return Directory.current.parent.path;
  }
  return Directory.current.path;
}

class Accueil extends StatefulWidget {
  const Accueil({super.key});

  @override
  State<Accueil> createState() => _AccueilState();
}

class _AccueilState extends State<Accueil> {
  String projet = dossierProjet();
  Map? analyse;
  Map? audit;
  bool enCours = false;
  String erreur = '';
  // chemin du fichier log tapé par l'utilisateur
  TextEditingController fichier = TextEditingController();

  // on lit les deux fichiers json écrits par main.py
  void lireRapports() {
    File f1 = File('$projet/output/analysis_report.json');
    File f2 = File('$projet/output/audit_report.json');
    if (f1.existsSync() && f2.existsSync()) {
      setState(() {
        analyse = jsonDecode(f1.readAsStringSync());
        audit = jsonDecode(f2.readAsStringSync());
      });
    }
  }

  void lancer() async {
    setState(() {
      enCours = true;
      erreur = '';
      analyse = null;
      audit = null;
    });

    String python = 'python3';
    if (File('$projet/.venv/bin/python').existsSync()) {
      python = '$projet/.venv/bin/python';
    }

    // si un fichier est donné on l'analyse, sinon jeu de test de data/
    List<String> arguments = ['main.py'];
    String chemin = fichier.text.trim();
    if (chemin != '') {
      if (!File(chemin).existsSync() && !File('$projet/$chemin').existsSync()) {
        setState(() {
          erreur = 'Le fichier $chemin n\'existe pas.';
          enCours = false;
        });
        return;
      }
      arguments.add('--files');
      arguments.add(chemin);
    }

    ProcessResult res =
        await Process.run(python, arguments, workingDirectory: projet);
    if (res.exitCode == 0) {
      lireRapports();
    } else {
      erreur = res.stderr.toString();
    }
    setState(() => enCours = false);
  }

  // un titre de partie
  Widget titre(String texte) {
    return Padding(
      padding: const EdgeInsets.only(top: 20, bottom: 6),
      child: Text(texte,
          style: const TextStyle(
              fontSize: 18, fontWeight: FontWeight.bold, color: ece)),
    );
  }

  // une ligne "nom : valeur"
  Widget ligne(String nom, Object valeur) {
    return Text('$nom : $valeur', style: const TextStyle(fontSize: 15));
  }

  @override
  Widget build(BuildContext context) {
    List<Widget> contenu = [
      TextField(
        controller: fichier,
        decoration: const InputDecoration(
          labelText: 'Fichier log à analyser',
          hintText: 'ex : data/auth_server.log (vide = tous les logs de data/)',
          prefixIcon: Icon(Icons.search),
          border: OutlineInputBorder(),
        ),
        onSubmitted: (texte) => lancer(),
      ),
      const SizedBox(height: 10),
      ElevatedButton(
        style: ElevatedButton.styleFrom(
            backgroundColor: ece, foregroundColor: Colors.white),
        onPressed: enCours ? null : lancer,
        child: Text(enCours ? 'Analyse en cours...' : 'Lancer l\'analyse'),
      ),
    ];

    if (erreur != '') {
      contenu.add(Text(erreur, style: const TextStyle(color: Colors.red)));
    }

    if (analyse != null && audit != null) {
      Map pipeline = analyse!['pipeline'];
      Map stats = analyse!['statistics'];
      Map ens = analyse!['ip_sets'];
      Map bf = analyse!['brute_force'];
      Map regles = analyse!['rules'];

      contenu.add(titre('Module 1 : ingestion (yield / yield from)'));
      contenu.add(ligne('Lignes lues', pipeline['raw_entries']));

      contenu.add(titre('Module 2 : pipeline (filter, map, match-case)'));
      contenu.add(ligne('Logs valides', pipeline['valid_records']));
      contenu.add(ligne('Entrées rejetées', pipeline['rejected']));
      for (var format in stats['by_format'].keys) {
        contenu.add(ligne('Format $format', stats['by_format'][format]));
      }

      contenu.add(titre('Module 3 : agrégation'));
      contenu.add(ligne('IP uniques avec erreurs (set)',
          stats['error_ips'].length));
      contenu.add(ligne('Union |', ens['union'].length));
      contenu.add(ligne('Intersection &', ens['intersection'].length));
      contenu.add(ligne('Différence -', ens['active_not_blacklisted'].length));
      contenu.add(ligne(
          'Différence symétrique ^', ens['symmetric_difference'].length));
      for (var cat in stats['by_category'].keys) {
        contenu.add(ligne('Catégorie $cat (defaultdict)',
            stats['by_category'][cat]));
      }
      contenu.add(ligne('Attaques force brute', bf['alerts'].length));
      contenu.add(ligne('Détection complète (else)', bf['complete']));

      contenu.add(titre('Module 4 : règles et audit'));
      for (var regle in regles['hits_by_rule'].keys) {
        contenu.add(ligne(regle, regles['hits_by_rule'][regle]));
      }
      contenu.add(ligne('Variables globals() auditées',
          audit!['audit_module_globals'].length));
      contenu.add(ligne('Variables locals() auditées',
          audit!['audit_function_locals'].length));
    } else if (!enCours) {
      contenu.add(const Padding(
        padding: EdgeInsets.only(top: 10),
        child: Text('Choisis un fichier et lance l\'analyse.'),
      ));
    }

    return Scaffold(
      appBar: AppBar(
        backgroundColor: ece,
        foregroundColor: Colors.white,
        title: const Text('LogStream'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: contenu,
      ),
    );
  }
}
