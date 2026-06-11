#!/usr/bin/env bash
# Script d'automatisation Forensic Analyzer - Linux/macOS

# Arrêter le script en cas d'erreur
set -e

# Définition du chemin du script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ "$1" == "--install" ]; then
    echo -e "\033[38;5;46m[*] Mise à jour des dépôts système...\033[0m"
    sudo apt-get update -y

    echo -e "\033[38;5;46m[*] Installation des paquets système essentiels (Tshark, SSDEEP, Volatility3)...\033[0m"
    sudo apt-get install -y python3-pip python3-dev python3-venv build-essential libffi-dev libssl-dev ssdeep libfuzzy-dev tshark volatility3
    
    echo -e "\033[38;5;220m[+] Prérequis système installés !\033[0m"
fi

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
if [ "$1" == "--install" ]; then
    echo -e "\033[38;5;46m[*] Installation des dépendances Python...\033[0m"
    pip install --upgrade pip
    pip install -r requirements.txt
    echo -e "\033[38;5;220m[+] Installation complète réussie ! Vous pouvez maintenant lancer la plateforme avec ./run.sh\033[0m"
    exit 0
else
    # Vérification furtive au lancement
    pip install --disable-pip-version-check --upgrade pip -q >/dev/null 2>&1 || true
    pip install --disable-pip-version-check -r requirements.txt -q >/dev/null 2>&1 || true
fi

# 4. Lancement de l'application avec les arguments fournis
python3 main.py "$@"
