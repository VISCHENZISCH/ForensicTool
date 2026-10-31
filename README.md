<p align="center">
  Triage DFIR de bout en bout : disques, mémoire, réseau, journaux et binaires,<br>
  corrélés dans une chronologie unique.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/Linux-support%C3%A9-FCC624?logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/Windows-support%C3%A9-0078D6" alt="Windows">
  <img src="https://img.shields.io/badge/R%C3%A9seau-hors%20ligne%20par%20d%C3%A9faut-0d9488" alt="Hors ligne par défaut">
  <img src="https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest&logoColor=white" alt="pytest">
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-22c55e" alt="Licence MIT"></a>
</p>

---

## Ce qui est analysé

| Source            | Points clés                                                                          |
| ----------------- | ------------------------------------------------------------------------------------ |
| **Images disque** | GPT/MBR, NTFS et ext4 lus avec pytsk3, sans montage ; triage Linux et Windows        |
| **Mémoire**       | Volatility 3 : processus cachés, injections, appels système détournés, connexions    |
| **Réseau**        | PCAP : identifiants, balises C2, exfiltration DNS/HTTP, empreintes JA3               |
| **Windows**       | EVTX, registre, Prefetch, LNK                                                        |
| **Linux**         | systemd, cron, SSH, `auth.log`, auditd, intégrité des paquets (`dpkg -V` hors ligne) |
| **Journaux**      | nginx/Apache, syslog, auth, WordPress : brute-force, webshell, exfiltration, sudo    |
| **Web**           | Webshells PHP, rapports nmap (`-oX`)                                                 |
| **Binaires**      | PE et ELF : désassemblage des appels sensibles, YARA, capa                           |
| **Documents**     | PDF (déclencheurs suivis jusqu'au JavaScript), Office : macros, DDE, modèles distants |
| **Fichiers**      | EXIF/GPS, stéganographie, carving, navigateurs Chrome/Edge/Firefox                   |

Les résultats sont **corrélés** (un même indicateur vu sur le disque, en mémoire et dans un binaire) et fusionnés dans une **chronologie** avec un niveau de confiance. Un décalage d'horloge entre capture réseau et journaux est détecté et recalé, l'heure d'origine restant conservée.

## Installation

```bash
git clone https://github.com/VISCHENZISCH/ForensicTool && cd ForensicTool
./run.sh --install
```

## Utilisation

```bash
./run.sh                                          # menu interactif
./run.sh --scan ./preuves --export-html rapport.html
./run.sh --pe ./preuves                           # uniquement les exécutables PE du dossier
./run.sh --logs /var/log/nginx                    # journaux web et système
```

Chaque option d'analyse accepte un fichier ou un dossier. Dans un dossier, seuls les fichiers du type choisi sont analysés.

| Export                           | Contenu                                                   |
| -------------------------------- | --------------------------------------------------------- |
| `--export-html` / `--export-pdf` | Rapport complet                                           |
| `--export-csv`                   | Chronologie (Timeline Explorer, Excel)                    |
| `--export-graph`                 | Graphe interactif de la chaîne de compromission           |
| `--export-rules`                 | Règles YARA, Suricata, Sigma et bundle STIX 2.1           |
| `--verify-hashes MANIFESTE`      | Contrôle d'intégrité des preuves avant et après l'analyse |
| `--evidence-dir DOSSIER`         | Dossier de référence des chemins relatifs du manifeste    |

Chaque analyse écrit dans son propre dossier, `export/FT-AAAAMMJJ-HHMMSS-<PREUVES>/` (FT : Forensic Tool) (ou `--export-dir`), jamais dans le dossier des preuves.

Extrait de la conclusion affichée en fin de scan :

```text
CONCLUSION DE L'ANALYSE
  Gravité critique     : 1 : Détection Webshell (x.php)
  Gravité élevée       : 10 : Journaux Web / Système (nginx-access.log), Analyse réseau PCAP (traffic.pcap), ...
  Corroboré : 203.0.113.42 (ipv4) : IDS, Artefacts Linux, Journaux, Réseau (PCAP)
  Horloge              : 5 j 7 h 20 min entre le PCAP et les journaux hôtes (PCAP en avance)
  Empreintes           : 49 preuve(s) hachée(s) à la collecte (SHA-256, UTC), inchangées après analyse
Chaîne d'attaque (faits confirmés par plusieurs sources)
  2026-10-25 06:48:00  pcap + web_access + web_error
    Début du brute-force web depuis 203.0.113.42 (2401 tentatives)
```

## Codes de sortie

| Code | Signification                                                                  |
| ---- | ------------------------------------------------------------------------------ |
| `0`  | Rien à signaler : tout a été analysé et vérifié                                |
| `1`  | Analyse incomplète : preuve introuvable, fichier chiffré, module ou export en échec |
| `2`  | Preuve altérée : empreinte différente du manifeste, ou modifiée pendant l'analyse |
| `3`  | Menace de gravité élevée ou critique                                           |

## Limites connues

| Cas                                  | Comportement                                                          |
| ------------------------------------ | --------------------------------------------------------------------- |
| PCAP de plus de 512 Mo               | Signalé « non analysé » (chargé en mémoire) : utiliser tshark ou Zeek, ou `FORENSIC_PCAP_MAX_MB` |
| PDF ou document Office chiffré       | Signalé « analyse partielle » ; relu si le mot de passe utilisateur est vide |
| Archives (`.zip`, `.tar.*`)          | Un seul niveau extrait ; au-delà de 200 Mo ou 10 000 fichiers, non extraites ; images de conteneur ignorées |
| Mémoire                              | Requiert les symboles Volatility du noyau analysé                     |
| Failles de format (exploit Word, PDF) | Non détectées sans règle YARA dédiée                                 |

## Hors ligne par défaut

Aucun service tiers n'est contacté sans `--online` (MalwareBazaar, VirusTotal, géocodage OSM), car une requête divulguerait des éléments de l'enquête.

```bash
export ABUSECH_AUTH_KEY=...  VT_API_KEY=...
./run.sh --scan ./preuves --online          # menu : FORENSIC_ONLINE=1 ./run.sh
```

## Version

`./run.sh --version` affiche la version et le commit, aussi inscrits dans chaque rapport : un rapport dit toujours avec quel code il a été produit. Installation en paquet : `pip install .` (commande `forensic-analyzer`).

## Tests

```bash
pip install -r requirements-dev.txt && pytest
```

## Cadre d'utilisation

Outil de **tri** : il oriente l'analyste, il ne produit pas de preuve. Chaque alerte doit être vérifiée, et les empreintes d'acquisition prises avec un outil dédié. À exécuter dans une machine d'analyse isolée, preuves montées en lecture seule.

À utiliser uniquement dans un cadre légal : réponse à incident, laboratoire SOC, CTF. Vulnérabilité dans l'outil : voir [SECURITY.md](SECURITY.md). Licence [MIT](LICENSE).
