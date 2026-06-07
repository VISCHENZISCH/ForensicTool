# Forensic Analyzer

[![License](https://img.shields.io/github/license/VISCHENZISCH/ForensicTool?style=flat-squared&color=00d4ff)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue?style=flat-squared)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey?style=flat-squared)](#)
[![Tests](https://img.shields.io/badge/tests-18%2F18%20passed-success?style=flat-squared)](test.py)

**Forensic Analyzer** est une suite d'outils forensiques (DFIR) unifiée, modulaire et hautement performante écrite en Python. Conçue pour les analystes SOC, les chasseurs de menaces (Threat Hunters) et les experts en réponse aux incidents, elle permet d'extraire, analyser et corréler des preuves numériques à travers 5 niveaux de profondeur technique.

Le projet propose une interface terminal interactive et colorée pur ANSI (style *TheFatRat*) sans dépendance lourde, ainsi qu'un mode ligne de commande scriptable pour l'automatisation en pipeline.

---

##Menu Interactif & Aperçu Visuel

Lancé sans argument, **Forensic Analyzer** ouvre son menu interactif principal :

```text
    ___ ___  ___  ___ _  _ ___ ___ ___
   | __/ _ \| _ \| __| \| / __|_ _/ __|
   | _| (_) |   / _|| .` \__ \| | (__
   |_| \___/|_|_\___|_|\_/___\___/___|
          A N A L Y Z E R  v1.0
     Digital Forensics Investigation Suite

 ─────────────────────────────────────────────────────────────

   ANALYSE FICHIERS                   ANALYSE SYSTEME
   ────────────────                   ───────────────
    [01] PDF - Metadonnees             [10] Windows Event Logs
    [02] Image / EXIF                  [11] Registre Windows
    [03] Coordonnees GPS               [12] Artefacts Linux
    [04] Extraction Strings            [13] Analyse Memoire
    [05] Historique Firefox            [14] Forensique Disque
    [06] Cookies Firefox
                                      THREAT HUNTING
   ANALYSE AVANCEE                    ──────────────
   ───────────────                     [15] Scan YARA
    [07] Steganographie                [16] Extraction IOC
    [08] File Carving                  [17] Timeline DFIR
    [09] Analyse PCAP
 ─────────────────────────────────────────────────────────────

   OUTILS
   ──────
    [88] Scan Automatique
    [99] Exporter Rapport
    [00] Quitter

forensic~# _
```

---

##  Architecture Multi-Niveaux (L1 - L5)

La suite est structurée en 5 niveaux d'investigation progressive :

### L1 : Tri initial & Métadonnées de base
* **PDF Analyzer** : Informations sur le document, version, chiffrement, permissions, créateur, etc.
* **Image/EXIF & GPS Analyzer** : Extraction des métadonnées géographiques avec liens automatiques vers Google Maps et OpenStreetMap.
* **Strings Analyzer** : Extraction optimisée des chaînes ASCII/Unicode depuis les exécutables et fichiers binaires.
* **Firefox Artifacts** : Extraction de l'historique et des cookies depuis les bases SQLite de profil.

### L2 : Analyse Secrète & Carving
* **Stego Analyzer** : Détection de stéganographie LSB (Least Significant Bit), analyse de distribution DCT (JPEG) et détection des canaux Alpha masqués.
* **File Carving Analyzer** : Extraction par Magic Bytes de fichiers imbriqués (PNG, ZIP, ELF, PDF) et détection des fichiers polyglotes.

### L3 : Réseau & Mémoire Vive (RAM)
* **PCAP Analyzer** : Reconstruction de sessions, extraction de credentials (FTP, HTTP Basic, etc.), détection de patterns C2 (beacons) et de requêtes d'exfiltration DNS.
* **Memory Analyzer** : Wrapper d'intégration avec **Volatility3** permettant d'exécuter des plugins d'analyse RAM (Windows/Linux) et d'extraire les chaînes de caractères sensibles.

### L4 : Forensique Système & Disque
* **Disk/MFT Analyzer** : Analyse de bas niveau de la Master File Table (MFT) NTFS, recherche de flux ADS (Alternate Data Streams) et d'inodes Ext4.
* **EVTX Analyzer** : Parsing ultra-rapide des Windows Event Logs avec détection des tentatives de brute-force SSH/SMB et de suppression des journaux d'audit.
* **Registry Analyzer** : Analyse des ruches Windows (SAM, SYSTEM, NTUSER.DAT) avec extraction des mécanismes de persistance (Autorun/Services) et informations d'utilisateurs.

### L5 : Threat Hunting & Corrélation
* **YARA Scanner** : Scan multi-threadé basé sur des règles YARA pour détecter des empreintes de malwares et payloads.
* **IOC Extractor** : Extraction regex haute fidélité d'adresses IPv4/IPv6, d'URLs, de clés de registre, de hashes (MD5, SHA-1, SHA-256) et d'emails.
* **Timeline Generator** : Corrélateur temporel générant une chronologie DFIR unifiée et chronologique de tous les événements découverts au cours de l'investigation.

---

## Rapports & Exports Professionnels

* **HTML Interactif** : Génération d'un tableau de bord de réponse aux incidents responsive incluant des graphiques de distribution analytique (Chart.js), des boîtes d'alerte contextuelles, et des filtres dynamiques par type de preuve.
* **JSON Structuré** : Format d'échange brut standardisé pour intégration avec des plateformes SOAR ou SIEM.
* **CSV Timeline** : Format tabulaire chronologique compatible avec **Plaso (Log2Timeline)**.
* **PDF Exporter** : Export de rapports imprimables et soignés via WeasyPrint.

---

##  Installation & Configuration

### Prérequis Système (Optionnels)
Pour exploiter pleinement tous les modules :
* **YARA** : `libyara` (installé par défaut sur la plupart des distributions de sécurité comme Kali Linux).
* **Volatility3** : Nécessaire uniquement pour l'analyse de dumps RAM complexes.

### Lancement rapide

```bash
# 1. Cloner le dépôt
git clone https://github.com/VISCHENZISCH/ForensicTool.git
cd "ForensicTool"

# 2. Configurer l'environnement virtuel et installer les dépendances
./run.sh    # Sous Linux / macOS
# ou run.ps1 sous Windows
```

---

## Exemples d'Utilisation en Ligne de Commande (CLI)

Forensic Analyzer est entièrement scriptable pour s'intégrer dans vos outils ou scripts de tri :

```bash
# Scan automatique de tout un dossier de preuves et génération de rapports HTML & JSON
python main.py --scan ./preuves --export-html rapport.html --export-json rapport.json

# Analyse réseau PCAP à la recherche de credentials et d'anomalies
python main.py --pcap capture.pcap --export-csv timeline.csv

# Scan YARA d'un répertoire suspect avec des règles personnalisées
python main.py --yara /path/to/rules.yar --scan ./fichiers_suspects

# Extraction des données GPS d'une photo de scène d'incident
python main.py --gps image.jpg
```

---

## Validation & Tests

La suite de tests unitaires valide l'intégralité des fonctionnalités en mockant les entrées physiques :

```bash
python test.py
```

---

## Licence

Ce projet est distribué sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.
