"""
Module de mise a jour (Updater) pour Forensic Analyzer.
"""
import subprocess
from forensic_analyzer.output import ui

class Updater:
    """Gere les mises a jour de l'application via git."""
    
    def check_and_update(self) -> None:
        """Verifie et recupere les dernieres mises a jour depuis le depot distant."""
        ui.info("Recherche de mises a jour en cours...")
        try:
            # On fetch les dernieres modifs
            fetch_res = subprocess.run(["git", "fetch"], capture_output=True, text=True)
            if fetch_res.returncode != 0:
                ui.error("Erreur lors de la verification des mises a jour (git fetch a echoue).")
                return
            
            # On verifie s'il y a des changements
            status_res = subprocess.run(["git", "status", "-uno"], capture_output=True, text=True)
            if "Your branch is up to date" in status_res.stdout or "Votre branche est" in status_res.stdout:
                ui.success("Forensic Analyzer est deja a jour.")
                return
                
            ui.info("Mise a jour disponible. Telechargement en cours...")
            pull_res = subprocess.run(["git", "pull"], capture_output=True, text=True)
            if pull_res.returncode == 0:
                ui.success("Mise a jour terminee avec succes !")
                ui.warning("Il est recommande de redemarrer l'application pour appliquer les changements.")
            else:
                ui.error("Erreur lors de la mise a jour (git pull a echoue).")
                print(pull_res.stderr)
        except FileNotFoundError:
            ui.error("La commande 'git' n'est pas installee ou non reconnue.")
        except Exception as e:
            ui.error(f"Erreur inattendue lors de la mise a jour : {e}")
