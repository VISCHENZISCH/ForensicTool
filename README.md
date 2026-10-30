<p align="center">
  <img src="assets/logo.svg" alt="Forensic Analyzer" width="560">
</p>

<p align="center">
  Triage DFIR de bout en bout : disques, mémoire, réseau, journaux et binaires,<br>
  corrélés dans une chronologie unique.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white" alt="Python 3.13+">
  <img src="https://img.shields.io/badge/Linux-support%C3%A9-FCC624?logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/Windows-support%C3%A9-0078D6" alt="Windows">
  <img src="https://img.shields.io/badge/R%C3%A9seau-hors%20ligne%20par%20d%C3%A9faut-0d9488" alt="Hors ligne par défaut">
  <img src="https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest&logoColor=white" alt="pytest">
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-22c55e" alt="Licence MIT"></a>
</p>

---

## Ce qui est analysé

| Source | Points clés |
|---|---|
| **Images disque** | GPT/MBR, NTFS et ext4 lus avec pytsk3, sans montage ; triage Linux et Windows |
| **Mémoire** | Volatility 3 : processus cachés, injections, appels système détournés, connexions |
| **Réseau** | PCAP : identifiants, balises C2, exfiltration DNS/HTTP, empreintes JA3 |
| **Windows** | EVTX, registre, Prefetch, LNK |
| **Linux** | systemd, cron, SSH, `auth.log`, auditd, intégrité des paquets (`dpkg -V` hors ligne) |
| **Binaires** | PE et ELF : désassemblage des appels sensibles, YARA, capa |
| **Fichiers** | PDF, EXIF/GPS, stéganographie, carving, navigateurs Chrome/Edge/Firefox |

Les résultats sont **corrélés** (un même indicateur vu sur le disque, en mémoire et dans un binaire) et fusionnés dans une **chronologie** avec un niveau de confiance.

## Installation

```bash
git clone https://github.com/VISCHENZISCH/ForensicTool && cd ForensicTool
./run.sh --install          # Windows : .\run.ps1 --install
```

## Utilisation

```bash
./run.sh                                          # menu interactif
./run.sh --scan ./preuves --export-html rapport.html
./run.sh --pe ./preuves                           # uniquement les exécutables PE du dossier
```

Chaque option d'analyse accepte un fichier ou un dossier. Dans un dossier, seuls les fichiers du type choisi sont analysés.

| Export | Contenu |
|---|---|
| `--export-html` / `--export-pdf` | Rapport complet |
| `--export-csv` | Chronologie (Timeline Explorer, Excel) |
| `--export-graph` | Graphe interactif de la chaîne de compromission |
| `--export-rules` | Règles YARA, Suricata, Sigma et bundle STIX 2.1 |
| `--verify-hashes MANIFESTE` | Contrôle d'intégrité des preuves avant et après l'analyse |

Tout est écrit dans `export/`, jamais dans le dossier des preuves.

## Hors ligne par défaut

Aucun service tiers n'est contacté sans `--online` (MalwareBazaar, VirusTotal, géocodage OSM), car une requête divulguerait des éléments de l'enquête.

```bash
export ABUSECH_AUTH_KEY=...  VT_API_KEY=...
./run.sh --scan ./preuves --online          # menu : FORENSIC_ONLINE=1 ./run.sh
```

## Tests

```bash
pip install -r requirements-dev.txt && pytest
```

## Cadre d'utilisation

À utiliser uniquement dans un cadre légal : réponse à incident, laboratoire SOC, CTF. Licence [MIT](LICENSE).
