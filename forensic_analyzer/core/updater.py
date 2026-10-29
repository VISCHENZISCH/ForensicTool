"""
Module de mise à jour (Updater) pour Forensic Analyzer.
"""
import os
import subprocess

from forensic_analyzer.output import ui

# Dépôt de l'outil. Jamais le dossier courant : lancé depuis un dossier de preuves contenant
# un dépôt git, sa configuration (core.fsmonitor, alias...) ferait exécuter du code à git.
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class Updater:
    """Gère les mises à jour de l'application via git."""
    
    def check_and_update(self) -> None:
        """Vérifie et récupère les dernières mises à jour depuis le dépôt distant."""
        ui.info("Recherche de mises à jour en cours...")
        if not os.path.isdir(os.path.join(_REPO, ".git")):
            ui.error(f"Pas de dépôt git dans {_REPO} : mise à jour impossible.")
            return
        try:
            # On fetch les dernières modifs
            fetch_res = subprocess.run(["git", "fetch"], capture_output=True, text=True, cwd=_REPO)
            if fetch_res.returncode != 0:
                ui.error("Erreur lors de la vérification des mises à jour (git fetch a échoué).")
                print(fetch_res.stderr)
                return
            
            # On vérifie s'il y a des changements
            status_res = subprocess.run(["git", "status", "-uno"], capture_output=True, text=True, cwd=_REPO)
            if "Your branch is up to date" in status_res.stdout or "Votre branche est" in status_res.stdout:
                ui.success("Forensic Analyzer est déjà à jour.")
                return
                
            ui.info("Mise à jour disponible. Téléchargement en cours...")
            pull_res = subprocess.run(["git", "pull"], capture_output=True, text=True, cwd=_REPO)
            if pull_res.returncode == 0:
                ui.success("Mise à jour terminée avec succès !")
                ui.warning("Il est recommandé de redémarrer l'application pour appliquer les changements.")
            else:
                ui.error("Erreur lors de la mise à jour (git pull a échoué).")
                print(pull_res.stderr)
        except FileNotFoundError:
            ui.error("La commande 'git' n'est pas installée ou non reconnue.")
        except Exception as e:
            ui.error(f"Erreur inattendue lors de la mise à jour : {e}")
