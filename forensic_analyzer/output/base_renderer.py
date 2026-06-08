"""Classe de base abstraite pour tous les renderers de sortie."""
from __future__ import annotations

from abc import ABC, abstractmethod

from forensic_analyzer.models.finding import FindingModel, ReportModel


class BaseRenderer(ABC):
    """Interface commune pour les renderers (Rich, Plain, etc.)."""

    @abstractmethod
    def render_finding(self, finding: FindingModel) -> None:
        """Affiche un résultat individuel."""

    @abstractmethod
    def render_banner(self) -> None:
        """Affiche le bandeau de l'outil."""

    def render_report(self, report: ReportModel) -> None:
        """Affiche tous les résultats d'un rapport."""
        self.render_banner()
        for finding in report.findings:
            self.render_finding(finding)
