# Script d'automatisation Forensic Analyzer - Windows PowerShell

# Stop en cas d'erreur
$ErrorActionPreference = "Stop"

# Aller dans le dossier du script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($ScriptDir) {
    Set-Location $ScriptDir
}

$IsInstall = $args -contains "--install"

if ($IsInstall) {
    Write-Host "[*] Mode Installation déclenché." -ForegroundColor Green
    Write-Host "[!] Note: Sous Windows, vous devez installer manuellement Wireshark/Tshark pour l'analyse réseau." -ForegroundColor Yellow
}

$VenvDir = "venv"

# 1. Vérification et création de l'environnement virtuel
if (-not (Test-Path $VenvDir)) {
    if (-not $IsInstall) {
        Write-Host "[!] Environnement absent : lancez d'abord .\run.ps1 --install" -ForegroundColor Red
        exit 1
    }
    Write-Host "[*] Création de l'environnement virtuel Python..." -ForegroundColor Cyan
    python -m venv $VenvDir
}

# 2. Activation de l'environnement virtuel
. .\$VenvDir\Scripts\Activate.ps1

# 3. Installation/mise à jour des dépendances
if ($IsInstall) {
    Write-Host "[*] Installation des dépendances Python..." -ForegroundColor Green
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    Write-Host "[+] Installation complète réussie ! Vous pouvez maintenant lancer la plateforme avec .\run.ps1" -ForegroundColor Yellow
    exit 0
}
# Pas d'installation au lancement : aucun accès réseau hors --install.

# 4. Nettoyage des arguments et lancement de l'application
$scriptArgs = $args | Where-Object { $_ -ne "--install" }
python main.py @scriptArgs
