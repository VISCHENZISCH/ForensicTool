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

### Réponse à incident Linux (image disque + mémoire)
Les métadonnées d'origine (propriétaires, liens symboliques, dates de création) sont perdues par une copie `tsk_recover` : on les fournit via un bodyfile TSK.
```bash
OFF=262144   # secteur de début de la partition Linux (mmls)
fls -r -m / -o $OFF disk.raw > bodyfile.txt
tsk_recover -a -o $OFF disk.raw ./extracted/root

./run.sh --verify-hashes preuves.sha256 \
         --linux ./extracted/root --bodyfile bodyfile.txt \
         --mem memory.raw --mem-os linux --mem-symbols ./symbols \
         --export-html rapport.html
```
- `--verify-hashes` : contrôle des empreintes avant et après l'analyse.
- `--linux` + `--bodyfile` : unités systemd suspectes, `ld.so.preload`, cron, clés SSH, intégrité des paquets (`dpkg -V` hors ligne), fichiers hors paquet, fichiers système hors root ou cachés, `audit.log`, `wtmp`/`lastlog`, journald, chronologie consolidée et correspondance MITRE ATT&CK.
- `--mem-os linux --mem-symbols` : processus cachés (pslist/psscan), processus lancés depuis un répertoire caché, connexions distantes, appels système détournés, modules cachés, injections.
- Les binaires ELF sont analysés automatiquement par `--scan`, ou directement avec `--elf`.

### Services en ligne (désactivés par défaut)
Interroger un service tiers divulgue des éléments de l'enquête (hashes, coordonnées GPS). L'outil fonctionne donc hors-ligne par défaut. Pour activer MalwareBazaar, VirusTotal et le géocodage OpenStreetMap :
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
