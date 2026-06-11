# Forensic Analyzer

Une plateforme d'investigation numérique de classe militaire (DFIR) entièrement automatisée. Elle collecte, parse, corrèle et génère une timeline de bout-en-bout à partir de disques, mémoire, journaux systèmes et captures réseau.

## Fonctionnalités Clés (20 Modules)
- **Analyse Fichier & Stegano** : Outils complets pour PDF, Images (EXIF, LSB, Carving), extraction de strings.
- **Investigation Navigateur** : Extraction des historiques, cookies, favoris, et téléchargements (Chromium & Firefox).
- **Triage Réseau (PCAP)** : Extraction de flux TCP/UDP, détection de scans, extraction de credentials en clair et fingerprinting TLS (JA3).
- **Analyse Malware (PE)** : Moteur d'analyse statique des exécutables, détection de packers, imports d'APIs suspectes, hashes multiples (SSDEEP), IOCs et macro OLE.
- **Scan YARA & Threat Hunting** : Moteur de scan YARA compatible avec les processus mémoires et les fichiers (Webshells, CobaltStrike, Mineurs).
- **Forensique Système (Windows & Linux)** : Parseurs robustes pour MFT NTFS, Event Logs EVTX, Registres (BAM, UserAssist, AmCache), Prefetch, LNK, Bash History, Auth.log et fichiers SUID.
- **Analyse Mémoire RAM** : Intégration de Volatility 3 pour le scan de processus injectés (Process Hollowing), DLLs cachées et Rootkits (Hooks SSDT).
- **Super-Timeline DFIR** : Fusion de tous les artefacts en une chronologie universelle (UTC) avec détection de périodes d'anti-forensics et export CSV.

---

## Installation (Linux)

Le script principal fait également office d'installeur interactif pour résoudre les dépendances systèmes (comme `tshark` pour les PCAP et `ssdeep` pour les hashes).

```bash
chmod +x run.sh
./run.sh --install
```

*(Si vous êtes sous Windows, installez Python 3.11+ et exécutez `pip install -r requirements.txt` manuellement).*

---

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
*Le moteur PE extraira l'entropie (pour détecter s'il est chiffré), les ressources cachées, le packer (UPX, etc.), et les règles YARA intégrées vous diront s'il s'agit d'un Stealer ou d'un Webshell.*

### 2. Investigation Système & Timeline
Placez un fichier `NTUSER.DAT`, un fichier `.evtx` et un fichier `.pf` dans un dossier `evidence_dir`.
```bash
./run.sh --scan ./evidence_dir/ --export-csv timeline.csv
```
*Ouvrez le fichier `timeline.csv` généré avec **Timeline Explorer** : vous verrez les accès fichiers croisés avec l'historique de lancement Prefetch et les logs d'authentification.*

### 3. Extraction d'un Rootkit en Mémoire
```bash
./run.sh --scan infected_dump.raw --plugins malfind,ssdt,netscan
```
*Le module mémoire appellera Volatility 3, ciblera les hooks dans la table de dispatch système (SSDT) et listera toutes les connexions réseau figées au moment du dump.*


## Avertissement Légal
Cet outil automatise des procédures extrêmement poussées d'investigation. À utiliser strictement dans un cadre légal (Réponse à Incident, CTF, Lab SOC).
