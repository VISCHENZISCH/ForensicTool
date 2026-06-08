# Script d'automatisation Forensic Analyzer - Windows PowerShell

# Stop en cas d'erreur
$ErrorActionPreference = "Stop"

# Aller dans le dossier du script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($ScriptDir) {
    Set-Location $ScriptDir
}

$VenvDir = "venv"

# 1. Vérification et création de l'environnement virtuel
if (-not (Test-Path $VenvDir)) {
    Write-Host "[*] Création de l'environnement virtuel Python..." -ForegroundColor Cyan
    python -m venv $VenvDir
}

# 2. Activation de l'environnement virtuel
. .\$VenvDir\Scripts\Activate.ps1

# 3. Installation/mise à jour des dépendances
python -m pip install --upgrade pip -q
pip install -r requirements.txt -q

# 4. Lancement de l'application
python main.py $args
