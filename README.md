# Forensic Analyzer

Une plateforme d'investigation numérique. Elle collecte, parse, corrèle et génère une timeline de bout-en-bout à partir de disques, mémoire, journaux systèmes et captures réseau.

---

## Installation (Linux)

Le script principal fait également office d'installeur interactif pour résoudre les dépendances systèmes (comme `tshark` pour les PCAP et `ssdeep` pour les hashes).

```bash
git clone https://github.com/VISCHENZISCH/ForensicTool
cd ForensicTool
chmod +x run.sh
./run.sh --install
```


### Lancement Interactif
```bash
./run.sh
```

### Scan Automatisé (Triage rapide)
Idéal pour ingérer directement un dump disque, un dossier réseau ou une collection d'artefacts KAPE/Triage.
```bash
./run.sh --scan /chemin/vers/dossier_evidence --export-html rapport_forensic.html
```

### Réponse à incident complète en une commande
Placez les preuves dans un dossier (image disque, dump mémoire, manifeste `.sha256`, dossier `symbols/` pour Volatility) :
```bash
./run.sh --scan ./preuves --export-html rapport.html --export-csv timeline.csv \
         --export-graph chaine.html --export-rules
```
- **Intégrité** : le manifeste d'empreintes est vérifié automatiquement (`--verify-hashes` le refait avant et après l'analyse).
- **Image disque lue directement** (pytsk3, sans montage ni `tsk_recover`) : partitions GPT/MBR, systèmes de fichiers, métadonnées d'origine (propriétaires, liens, dates de création), puis triage des artefacts dans `export/extractions/` (jamais dans le dossier des preuves) :
  - *Linux* : unités systemd suspectes, `ld.so.preload`, cron, clés SSH, intégrité des paquets (`dpkg -V` hors ligne, hachage dans l'image), fichiers hors paquet, hors root ou cachés, `audit.log`, `wtmp`/`lastlog`, journald, puis analyse des binaires suspects ;
  - *Windows* : journaux EVTX, ruches du registre, Prefetch, LNK, historiques Chrome/Edge/Brave/Firefox.
- **Mémoire** : OS détecté automatiquement (bannière du noyau), symboles ISF du dossier `symbols/` voisin ; processus cachés (pslist/psscan), processus lancés depuis un répertoire caché, connexions distantes, appels système détournés, modules cachés, injections.
- **Binaires ELF et PE** : désassemblage (capstone) des appels sensibles — destination de `connect()` (IP et port), intervalle de `sleep()`, fichiers ouverts, commandes exécutées — et capacités [capa](https://github.com/mandiant/capa) si l'outil est installé.
- **Corrélation** : indicateurs partagés entre sources (ex : un chemin vu sur le disque, dans un processus en mémoire et dans un binaire), graphe interactif de la chaîne de compromission (`--export-graph`).
- **Chronologie consolidée** : événements concordants fusionnés, confiance *élevée* (≥ 2 sources), *moyenne* (1 source) ou *faible* (horodatage falsifiable).
- **Détection et partage** (`--export-rules`, dans `export/rules/`) : règles YARA (par binaire suspect + empreintes), Suricata (IP/port, domaines, URL, JA3), Sigma (Linux et Windows) et bundle STIX 2.1 (indicateurs, malware, techniques ATT&CK).

Analyses ciblées : `--disk`, `--mem` (`--mem-os`, `--mem-symbols`), `--elf`, `--pe`, `--linux RACINE --bodyfile FICHIER` pour une copie déjà extraite.

### Services en ligne (désactivés par défaut)
Interroger un service tiers divulgue des éléments de l'enquête (hashes, coordonnées GPS). Le graphe de corrélation embarque son JavaScript et ne contacte aucun CDN. L'outil fonctionne donc hors-ligne par défaut. Pour activer MalwareBazaar, VirusTotal et le géocodage OpenStreetMap :
```bash
export ABUSECH_AUTH_KEY=...   # MalwareBazaar
export VT_API_KEY=...         # VirusTotal
./run.sh --scan ./evidence_dir/ --online
```
En mode interactif, utiliser `FORENSIC_ONLINE=1 ./run.sh`.

### Tests
```bash
pip install -r requirements-dev.txt
pytest
```

---

## Scénarios Pratiques de Test

### 1. Triage d'un Malware
Soumettez un exécutable potentiellement malveillant au moteur :
```bash
./run.sh --scan malware_sample.exe
```


### 2. Investigation Système & Timeline
Placez un fichier `NTUSER.DAT`, un fichier `.evtx` et un fichier `.pf` dans un dossier `evidence_dir`.
```bash
./run.sh --scan ./evidence_dir/ --export-csv timeline.csv
```
*Ouvrez le fichier `timeline.csv` généré avec **Timeline Explorer** : vous verrez les accès fichiers croisés avec l'historique de lancement Prefetch et les logs d'authentification.*



## Avertissement Légal
Cet outil automatise des procédures extrêmement poussées d'investigation. À utiliser strictement dans un cadre légal (Réponse à Incident, CTF, Lab SOC).
