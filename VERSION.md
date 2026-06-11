# Perspectives & Roadmap Forensic Analyzer (v2.0)

Suite à l'évaluation en conditions réelles du pipeline d'analyse DFIR sur un vaste dataset, la version actuelle s'est avérée redoutablement efficace comme **outil de Triage de Niveau 1 (Tier 1 Triage)**.

Pour que Forensic Analyzer s'impose comme une **plateforme DFIR/SOC unifiée** majeure, capable de remplacer une grappe complète d'outils disparates, voici les axes d'amélioration prioritaires identifiés par l'industrie (SOC N2/N3) :

## 1. Moteur de Corrélation et Timeline Globale (Priorité Absolue)
* **Timeline Engine** : Convertir tous les événements isolés (fichier créé à 14:52, connexion DNS à 14:53, exfiltration à 14:55) en une seule trame chronologique lisible. C'est l'essence même de l'investigation numérique.
* **Corrélation Inter-Modules** : Fusionner les résultats. Exemple : `PDF malveillant` + `DNS Exfiltration (PCAP)` + `LNK suspect` → Déduction automatique d'une **Chaîne d'attaque globale**.

## 2. Intégration Threat Intelligence & MITRE ATT&CK
* **Mappage MITRE ATT&CK** : Ne plus se contenter de signaler "DNS Exfiltration", mais catégoriser en `T1048 - Exfiltration Over Alternative Protocol`.
* **API Threat Intel** : Connecteurs automatiques vers AbuseIPDB, AlienVault OTX, et MISP pour enrichir les IPs, Domaines et Hashes avec du contexte.
* **Cache & Rate-Limiting VirusTotal** : Optimisation de l'interrogation de l'API externe.

## 3. Sandboxing Dynamique & Analyse Avancée (Malware)
* **Sandboxing Asynchrone** : Envoi automatique des binaires hautement critiques (Overlay massifs, Entropie élevée) vers des plateformes d'analyse dynamique comme **Cuckoo Sandbox** ou **CAPEv2**.
* **Détection Avancée de Packers** : Remplacer l'approche actuelle de scan de strings par une logique de détection profonde de packer type PEiD ou Detect It Easy (DIE).
* **OLE/VBA/Macros** : Intégrer un parseur et dé-obfuscateur direct de code VBA pour analyser en profondeur la menace des maldocs.

## 4. Enrichissement Réseau & Système (Zeek, Sigma, Volatility)
* **Volatility 3 Intégral** : Passer de la simple extraction mémoire au "Memory Forensics" complet (détection des processus cachés, DLL injectées, etc.).
* **Moteur Sigma** : Appliquer les règles de détection comportementales Sigma directement sur les Windows Event Logs, Sysmon et Linux Logs extraits par le pipeline.
* **Intégration Zeek** : Ingérer et croiser des logs réseaux générés par le NIDS Zeek.

## 5. Cas Management & SOC Dashboard
* **Dashboard Web Temps Réel** : Créer une interface permettant à l'analyste de voir d'un seul coup d'œil les IOCs majeurs avec un score global de criticité (ex: Score de 92/100, Critique).
* **Case Management** : Regrouper les analyses sous des ID de cas (`Case #2026-001`) pour structurer la réponse à incident d'une équipe.
