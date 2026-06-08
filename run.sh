#!/usr/bin/env bash
# Script d'automatisation Forensic Analyzer - Linux/macOS

# Arrêter le script en cas d'erreur
set -e

# Définition du chemin du script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Nom du dossier d'environnement virtuel
VENV_DIR="venv"

# 1. Vérification et création de l'environnement virtuel
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Création de l'environnement virtuel Python..."
    python3 -m venv "$VENV_DIR"
fi

# 2. Activation de l'environnement virtuel
source "$VENV_DIR/bin/activate"

# 3. Installation des dépendances si nécessaire
# On vérifie la date de modification pour éviter de relancer pip install inutilement si requirements.txt n'a pas changé,
# ou on le lance en mode rapide.
pip install --upgrade pip -q || true
pip install -r requirements.txt -q || true

# 4. Lancement de l'application avec les arguments fournis
python main.py "$@"
