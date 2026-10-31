"""
Module de mise à jour (Updater) pour Forensic Analyzer.
"""
import os
import subprocess

from forensic_analyzer.output import ui

# Dépôt de l'outil. Jamais le dossier courant : lancé depuis un dossier de preuves contenant
# un dépôt git, sa configuration (core.fsmonitor, alias...) ferait exécuter du code à git.
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Commits non signés acceptés seulement sur demande explicite (dépôt de développement, fork)
_ALLOW_UNSIGNED = "FORENSIC_UPDATE_ALLOW_UNSIGNED"


def _git(*args: str) -> subprocess.CompletedProcess:
    # GIT_TERMINAL_PROMPT=0 : un dépôt qui demande un identifiant échoue au lieu d'attendre une saisie invisible
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    return subprocess.run(["git", *args], capture_output=True, text=True, cwd=_REPO, env=env, timeout=60)


class Updater:
    """Gère les mises à jour de l'application via git."""

    def check_and_update(self) -> None:
        """
        Récupère les commits distants, en avance rapide seulement. La décision se fonde sur
        `git rev-list` (jamais sur le texte traduit de `git status`), et la mise à jour est
        refusée si le dépôt local a des modifications ou a divergé, ou si un commit à récupérer
        n'a pas de signature valide (sauf FORENSIC_UPDATE_ALLOW_UNSIGNED=1).
        """
        ui.info("Recherche de mises à jour en cours...")
        if not os.path.isdir(os.path.join(_REPO, ".git")):
            ui.error(f"Pas de dépôt git dans {_REPO} : mise à jour impossible.")
            return
        try:
            fetch = _git("fetch", "--quiet")
            if fetch.returncode != 0:
                ui.error(f"git fetch a échoué : {fetch.stderr.strip()}")
                return
            counts = _git("rev-list", "--left-right", "--count", "HEAD...@{u}")
            if counts.returncode != 0:
                ui.error("Aucune branche distante suivie : mise à jour impossible.")
                return
            ahead, behind = map(int, counts.stdout.split())
            if behind == 0:
                ui.success("Forensic Analyzer est déjà à jour.")
                return
            if ahead:
                ui.error(f"Le dépôt local a {ahead} commit(s) absent(s) du dépôt distant : "
                         "mise à jour refusée (à fusionner à la main).")
                return
            if _git("status", "--porcelain", "--untracked-files=no").stdout.strip():
                ui.error("Le dépôt local a des modifications non validées : mise à jour refusée.")
                return
            log = _git("log", "--oneline", "HEAD..@{u}").stdout.strip()
            ui.info(f"{behind} commit(s) à récupérer :\n{log}")
            signed = os.environ.get(_ALLOW_UNSIGNED) != "1"
            if signed:
                states = _git("log", "--format=%G?", "HEAD..@{u}").stdout.split()
                if any(s != "G" for s in states):
                    ui.error(f"{sum(s != 'G' for s in states)} commit(s) sans signature valide : mise à jour refusée "
                             f"({_ALLOW_UNSIGNED}=1 pour l'accepter en connaissance de cause).")
                    return
            pull = _git("merge", "--ff-only", *(["--verify-signatures"] if signed else []), "@{u}")
            if pull.returncode == 0:
                ui.success("Mise à jour terminée avec succès !")
                ui.warning("Il est recommandé de redémarrer l'application pour appliquer les changements.")
            else:
                ui.error(f"Erreur lors de la mise à jour : {pull.stderr.strip()}")
        except FileNotFoundError:
            ui.error("La commande 'git' n'est pas installée ou non reconnue.")
        except subprocess.TimeoutExpired as exc:
            ui.error(f"git ne répond pas (plus de {exc.timeout:.0f} s) : mise à jour abandonnée.")
        except ValueError:
            ui.error("Réponse inattendue de git rev-list : mise à jour abandonnée.")
