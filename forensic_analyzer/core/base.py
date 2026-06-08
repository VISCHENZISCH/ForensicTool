"""Classe de base abstraite pour tous les analyzers."""
from __future__ import annotations

from abc import ABC, abstractmethod

from forensic_analyzer.models.finding import FindingModel


class BaseAnalyzer(ABC):
    """
    Interface commune pour tous les modules d'analyse.

    Pour créer un nouvel analyzer :
      1. Hériter de BaseAnalyzer
      2. Définir les attributs `name` et `supported_extensions`
      3. Implémenter la méthode `analyze(path)`

    Le module sera automatiquement utilisé par AnalyzerRegistry
    dès son enregistrement.
    """

    name: str = "base"
    supported_extensions: tuple[str, ...] = ()

    def can_handle(self, path: str) -> bool:
        """Retourne True si ce module peut traiter le fichier `path`."""
        return path.lower().endswith(self.supported_extensions)

    @abstractmethod
    def analyze(self, path: str) -> FindingModel | None:
        """
        Analyse le fichier et retourne un FindingModel, ou None si échec.

        Args:
            path: Chemin absolu vers le fichier à analyser.
        Returns:
            FindingModel avec les résultats, ou None en cas d'échec.
        """
