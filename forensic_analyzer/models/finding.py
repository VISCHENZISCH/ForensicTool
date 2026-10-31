"""Modèles de données Pydantic pour les résultats forensiques."""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from pydantic import BaseModel, Field, model_validator

from forensic_analyzer.utils.logger import get_logger

log = get_logger("finding")


def compute_hashes(filepath: str) -> dict[str, str]:
    """
    Calcule les hashes MD5 et SHA-256 d'un fichier.
    Cache par (chemin, taille, mtime) : un fichier modifié en cours de session est rehaché.
    """
    try:
        st = os.stat(filepath)
    except OSError:
        return {}
    if not os.path.isfile(filepath):
        return {}
    return dict(_hash_file(filepath, st.st_size, st.st_mtime_ns))


@lru_cache(maxsize=1024)
def _hash_file(filepath: str, _size: int, _mtime_ns: int) -> tuple[tuple[str, str], ...]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    try:
        # Lecture par chunks de 1 Mo : images disque et dumps de plusieurs Go
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                sha256.update(chunk)
                md5.update(chunk)
        return (("MD5", md5.hexdigest()), ("SHA-256", sha256.hexdigest()))
    except OSError as exc:
        log.warning("Impossible de hasher '%s' : %s", filepath, exc)
        return ()


SEVERITIES = ("info", "faible", "moyen", "élevé", "critique")


class FindingModel(BaseModel):
    """Résultat d'une analyse forensique sur un fichier."""
    type: str
    file: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    extra: dict[str, Any] = Field(default_factory=dict)
    # Données de décision, indépendantes des libellés affichés (code de sortie, synthèse)
    severity: str | None = None                            # une valeur de SEVERITIES ; None : non évaluée
    incomplete: list[str] = Field(default_factory=list)    # ce que l'analyse n'a pas pu examiner

    model_config = {"extra": "allow"}

    @model_validator(mode='after')
    def inject_hashes(self) -> "FindingModel":
        if self.file and os.path.isfile(self.file):
            if "SHA-256" not in self.metadata:
                hashes = compute_hashes(self.file)
                new_meta = {}
                for k, v in hashes.items():
                    new_meta[k] = v
                new_meta.update(self.metadata)
                self.metadata = new_meta
        return self


class AnalysisError(BaseModel):
    """Module en échec sur un fichier : à dire dans le rapport, pas seulement dans le journal."""
    module: str
    file: str
    error: str
    message: str

    def __str__(self) -> str:
        return f"{self.module} sur {self.file} : {self.error} : {self.message}"

    @classmethod
    def of(cls, module: str, file: str, exc: BaseException) -> "AnalysisError":
        return cls(module=module, file=file, error=type(exc).__name__, message=str(exc))


class ReportModel(BaseModel):
    """Rapport global d'une session d'analyse complète."""
    tool: str = "Forensic Analyzer v1.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    total: int = 0
    findings: list[FindingModel] = Field(default_factory=list)
    skipped_files: list[str] = Field(default_factory=list)
    scan_notes: list[str] = Field(default_factory=list)  # archives extraites ou refusées, etc.
    analysis_errors: list[AnalysisError] = Field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: list[FindingModel], skipped_files: list[str] | None = None,
                      scan_notes: list[str] | None = None,
                      analysis_errors: list[AnalysisError] | None = None) -> "ReportModel":
        return cls(total=len(findings), findings=findings, skipped_files=skipped_files or [],
                   scan_notes=scan_notes or [], analysis_errors=analysis_errors or [])
