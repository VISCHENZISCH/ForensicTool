#!/usr/bin/env bash
# Script d'automatisation Forensic Analyzer - Linux/macOS

# Arrêter le script en cas d'erreur
set -e

# Définition du chemin du script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ "$1" == "--install" ]; then
    declare -a INSTALLED_APT=()
    declare -a FAILED_APT=()
    declare -a INSTALLED_PIP=()
    declare -a FAILED_PIP=()

    echo -e "\033[38;5;46m[*] Mise à jour des dépôts système...\033[0m"
    sudo apt-get update -y || true

    echo -e "\033[38;5;46m[*] Installation des paquets système essentiels...\033[0m"
    APT_PACKAGES="python3-pip python3-dev python3-venv build-essential libffi-dev libssl-dev ssdeep libfuzzy-dev tshark"
    sudo apt-get install -y $APT_PACKAGES || true
    
    for pkg in $APT_PACKAGES; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            INSTALLED_APT+=("$pkg")
        else
            FAILED_APT+=("$pkg")
        fi
    done
    
    echo -e "\033[38;5;220m[+] Phase système terminée !\033[0m"
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
    python3 -m pip install --upgrade pip
    
    while read requirement; do
        # Ignore empty lines and comments
        if [[ -n "$requirement" ]] && [[ "$requirement" != \#* ]]; then
            pkg_clean=$(echo "$requirement" | sed -E 's/[=><].*//')
            if python3 -m pip install "$requirement"; then
                INSTALLED_PIP+=("$pkg_clean")
            else
                FAILED_PIP+=("$pkg_clean")
                echo -e "\033[38;5;208m[!] Impossible d'installer $requirement, ignoré.\033[0m"
            fi
        fi
    done < requirements.txt

    # --- Résumé de fin ---
    echo -e "\n\033[1m=== RÉSUMÉ DE L'INSTALLATION ===\033[0m\n"
    
    echo -e "\033[1m[Paquets Système (APT)]\033[0m"
    for pkg in "${INSTALLED_APT[@]}"; do
        echo -e "\033[38;5;46m[✓] $pkg (installé via apt)\033[0m"
    done
    for pkg in "${FAILED_APT[@]}"; do
        echo -e "\033[38;5;196m[✗] $pkg (non installé)\033[0m"
    done

    echo -e "\n\033[1m[Modules Python (PIP)]\033[0m"
    for pkg in "${INSTALLED_PIP[@]}"; do
        echo -e "\033[38;5;46m[✓] $pkg (installé via pip)\033[0m"
    done
    for pkg in "${FAILED_PIP[@]}"; do
        echo -e "\033[38;5;196m[✗] $pkg (non installé)\033[0m"
    done

    echo -e "\n\033[38;5;220m[+] Installation complète terminée ! Vous pouvez maintenant lancer la plateforme avec ./run.sh\033[0m"
    exit 0
else
    # Vérification au lancement
    python3 -m pip install --disable-pip-version-check --upgrade pip -q
    
    while read requirement; do
        if [[ -n "$requirement" ]] && [[ "$requirement" != \#* ]]; then
            python3 -m pip install --disable-pip-version-check "$requirement" -q || true
        fi
    done < requirements.txt
fi

# 4. Lancement de l'application avec les arguments fournis
python3 main.py "$@"
