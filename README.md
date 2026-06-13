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
