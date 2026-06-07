"""AnalyzerRegistry et run_pipeline - orchestration centrale du pipeline."""
from __future__ import annotations
import os
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("pipeline")


class AnalyzerRegistry:
    """
    Registre dynamique de tous les analyzers disponibles.

    Supporte l'enregistrement à la volée de nouveaux modules :
    tout analyzer héritant de BaseAnalyzer peut être ajouté
    sans modifier le code existant (pattern Plugin).
    """

    def __init__(self) -> None:
        self._analyzers: list[BaseAnalyzer] = []

    def register(self, analyzer: BaseAnalyzer) -> "AnalyzerRegistry":
        """Enregistre un analyzer. Retourne self pour le chaînage."""
        self._analyzers.append(analyzer)
        log.debug("Analyzer enregistré : %s", analyzer.name)
        return self

    def register_all(self, *analyzers: BaseAnalyzer) -> "AnalyzerRegistry":
        """Enregistre plusieurs analyzers en une seule ligne."""
        for a in analyzers:
            self.register(a)
        return self

    def get_for(self, path: str) -> BaseAnalyzer | None:
        """Retourne le premier analyzer capable de traiter `path`, ou None."""
        for a in self._analyzers:
            if a.can_handle(path):
                return a
        return None

    @property
    def analyzers(self) -> list[BaseAnalyzer]:
        return list(self._analyzers)

    def __repr__(self) -> str:
        return f"AnalyzerRegistry([{', '.join(a.name for a in self._analyzers)}])"


def run_pipeline(paths: list[str], registry: AnalyzerRegistry) -> ReportModel:
    """
    Exécute le pipeline d'analyse sur une liste de fichiers.

    Args:
        paths:    Liste de chemins absolus à analyser.
        registry: Registre des analyzers disponibles.
    Returns:
        ReportModel consolidé avec tous les résultats.
    """
    findings: list[FindingModel] = []

    for path in paths:
        if not os.path.isfile(path):
            log.warning("Fichier introuvable, ignoré : %s", path)
            continue

        analyzer = registry.get_for(path)
        if analyzer is None:
            log.debug("Aucun analyzer pour : %s", os.path.basename(path))
            continue

        log.info("[%s] → %s", analyzer.name.upper(), os.path.basename(path))
        try:
            result = analyzer.analyze(path)
            if result:
                findings.append(result)
        except Exception as exc:
            log.error("Erreur dans %s sur '%s' : %s", analyzer.name, path, exc)

    return ReportModel.from_findings(findings)
