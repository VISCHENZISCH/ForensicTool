"""Logique de collecte des fichiers cibles et d'auto-scan."""
from __future__ import annotations

import os

from forensic_analyzer.core.pipeline import AnalyzerRegistry, run_pipeline
from forensic_analyzer.models.finding import ReportModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("scanner")


def collect_targets(path: str) -> list[str]:
    """
    Collecte les fichiers à analyser depuis un chemin (fichier ou dossier).

    Args:
        path: Chemin vers un fichier unique ou un répertoire.
    Returns:
        Liste triée de chemins absolus de fichiers existants.
    """
    if os.path.isfile(path):
        return [os.path.abspath(path)]

    if os.path.isdir(path):
        targets = []
        for root, _, files in os.walk(path):
            for file in files:
                targets.append(os.path.abspath(os.path.join(root, file)))
        return sorted(targets)

    log.warning("Chemin introuvable : %s", path)
    return []


def auto_scan(path: str, registry: AnalyzerRegistry) -> ReportModel:
    """
    Scanne un fichier ou répertoire et exécute le pipeline sur les cibles.

    Args:
        path:     Chemin vers un fichier ou répertoire.
        registry: Registre des analyzers à utiliser.
    Returns:
        ReportModel avec tous les résultats de la session.
    """
    targets = collect_targets(path)
    if not targets:
        log.info("Aucune cible trouvée dans : %s", path)
        return ReportModel(total=0, findings=[])

    log.info("%d fichier(s) collecté(s) depuis '%s'", len(targets), path)
    return run_pipeline(targets, registry)
