# Advanced Forensic Analysis Suite

Une suite d'outils performante pour l'analyse forensique de fichiers PDF et d'images, conçue pour l'extraction rapide de métadonnées et la visualisation  dans le terminal.

## Fonctionnalités

- **Analyse PDF** :
  - Extraction des métadonnées standards (Auteur, Créateur, Producteur).
  - Détection de la version du PDF.
  - Vérification de l'état du chiffrement (Encryption).
  - Comptage des pages.
- **Analyse d'Images** :
  - Extraction complète des données **EXIF**.
  - Identification du format, des dimensions et du mode de couleur.
  - Détection du modèle d'appareil photo et des paramètres de prise de vue.

## Installation

Il est recommandé d'utiliser un environnement virtuel :

```bash
# Création et activation de l'environnement virtuel
python3 -m venv env
source env/bin/activate

# Installation des dépendances
pip install -r requirements.txt
```

## Utilisation

Placez simplement vos fichiers PDF ou images (`.jpg`, `.png`, `.tiff`) dans le dossier du projet et lancez l'outil :

```bash
python main.py
```

L'outil scannera automatiquement le répertoire courant et générera un rapport détaillé pour chaque fichier trouvé.

##  Dépendances

- `pypdf` : Pour le traitement robuste des fichiers PDF.
- `Pillow` : Pour la manipulation et l'analyse des images.
- `rich` : Pour l'interface utilisateur terminal améliorée.
- `exif` : Pour l'extraction précise des métadonnées d'image.

---
*Optimisé pour l'analyse forensique et la performance.*
