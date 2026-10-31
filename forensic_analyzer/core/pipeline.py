"""AnalyzerRegistry et run_pipeline - orchestration centrale du pipeline."""
from __future__ import annotations

import concurrent.futures
import os
import threading

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import AnalysisError, FindingModel, ReportModel, fingerprint, recheck
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

    def get_all_for(self, path: str) -> list[BaseAnalyzer]:
        """
        Retourne tous les analyzers capables de traiter `path`.

        Un même artefact peut intéresser plusieurs modules
        (ex: un JPEG → EXIF, GPS et stéganographie).
        """
        return [a for a in self._analyzers if a.can_handle(path)]

    @property
    def analyzers(self) -> list[BaseAnalyzer]:
        return list(self._analyzers)

    def __repr__(self) -> str:
        return f"AnalyzerRegistry([{', '.join(a.name for a in self._analyzers)}])"


def run_pipeline(paths: list[str], registry: AnalyzerRegistry, **analyze_kwargs) -> ReportModel:
    """
    Exécute le pipeline d'analyse sur une liste de fichiers.
    Optimisé pour le parallélisme via ThreadPoolExecutor.

    Args:
        paths (list[str]): Liste de chemins absolus à analyser.
        registry (AnalyzerRegistry): Registre des analyzers disponibles.
        
    Returns:
        ReportModel: Modèle consolidé avec tous les résultats.
    """
    # Plusieurs Volatility ou pytsk3 en parallèle saturent la RAM
    heavy_lock = threading.Lock()

    errors: list[AnalysisError] = []

    def process_path(path: str) -> list[FindingModel]:
        if not os.path.isfile(path):
            log.warning("Fichier introuvable, ignoré : %s", path)
            return []

        fname = os.path.basename(path)
        if len(fname) > 50:
            fname = fname[:40] + "..." + fname[-7:]

        results: list[FindingModel] = []
        for analyzer in registry.get_all_for(path):
            log.info("[%s] → %s", analyzer.name.upper(), fname)
            try:
                if analyzer.heavy:
                    with heavy_lock:
                        res = analyzer.analyze(path, **analyze_kwargs)
                else:
                    res = analyzer.analyze(path, **analyze_kwargs)
            except Exception as exc:   # un module en échec ne doit ni arrêter le scan ni disparaître du rapport
                log.error("Erreur dans %s sur '%s' : %s", analyzer.name, fname, exc)
                errors.append(AnalysisError.of(analyzer.name, path, exc))
                continue
            if isinstance(res, list):
                results.extend(r for r in res if r is not None)
            elif res is not None:
                results.append(res)
        return results

    # Identifier les fichiers pris en charge vs ignorés
    skipped: list[str] = []
    supported_paths: list[str] = []
    for path in paths:
        if not os.path.isfile(path):
            log.warning("Fichier introuvable, ignoré : %s", path)
            skipped.append(path)
            continue
        analyzers = registry.get_all_for(path)
        if not analyzers:
            log.debug("Fichier ignoré (aucun module adapté) : %s", os.path.basename(path))
            skipped.append(path)
        else:
            supported_paths.append(path)

    if skipped:
        log.warning("%d fichier(s) ignoré(s) (aucun module adapté) : %s",
                    len(skipped), ", ".join(os.path.basename(f) for f in skipped[:15]))

    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        # Empreinte de chaque preuve collectée AVANT toute analyse (traçabilité), analysée ou non
        existing = [p for p in paths if os.path.isfile(p)]
        evidence = [r for r in executor.map(fingerprint, existing) if r]
        results = list(executor.map(process_path, supported_paths))

    findings = [res for per_path in results for res in per_path]
    for record in recheck(evidence):
        if record.changed_during_analysis:
            log.error("Preuve modifiée pendant l'analyse : %s", record.file)
    return ReportModel.from_findings(findings, skipped_files=skipped, analysis_errors=errors, evidence=evidence)
