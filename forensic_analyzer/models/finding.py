"""Modèles de données Pydantic pour les résultats forensiques."""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from pydantic import BaseModel, Field, model_validator

from forensic_analyzer.utils.logger import get_logger
from forensic_analyzer.utils.version import tool_identity

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


def severity_if_alerts(metadata: dict, level: str) -> str:
    """
    Pour un module dont toutes les alertes ont le même poids : `level` s'il a posé au moins une
    clé [ALERTE] (préfixe posé par le module à ses propres points de décision), sinon « info ».
    """
    return level if any(str(k).startswith("[ALERTE]") for k in metadata) else "info"


def max_severity(*levels: str | None) -> str | None:
    known = [lvl for lvl in levels if lvl in SEVERITIES]
    return max(known, key=SEVERITIES.index) if known else None


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


class EvidenceRecord(BaseModel):
    """Empreinte d'une preuve prise à la collecte, avant toute analyse, puis revérifiée après."""
    file: str
    size: int
    sha256: str
    md5: str
    hashed_at: str                              # UTC
    origin: str | None = None                   # archive d'où le fichier a été extrait
    changed_during_analysis: bool = False


def fingerprint(path: str, origin: str | None = None) -> EvidenceRecord | None:
    hashes = compute_hashes(path)
    if not hashes:
        return None
    return EvidenceRecord(file=os.path.abspath(path), size=os.path.getsize(path), sha256=hashes["SHA-256"],
                          md5=hashes["MD5"], hashed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                          origin=origin)


def recheck(records: list[EvidenceRecord]) -> list[EvidenceRecord]:
    """Recalcule l'empreinte après analyse (gratuit si taille et date sont inchangées : cache)."""
    for r in records:
        after = compute_hashes(r.file).get("SHA-256")
        r.changed_during_analysis = after != r.sha256
    return records


class ReportModel(BaseModel):
    """Rapport global d'une session d'analyse complète."""
    tool: str = Field(default_factory=tool_identity)   # version et commit exacts de l'outil
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    total: int = 0
    findings: list[FindingModel] = Field(default_factory=list)
    skipped_files: list[str] = Field(default_factory=list)
    scan_notes: list[str] = Field(default_factory=list)  # archives extraites ou refusées, etc.
    analysis_errors: list[AnalysisError] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: list[FindingModel], skipped_files: list[str] | None = None,
                      scan_notes: list[str] | None = None,
                      analysis_errors: list[AnalysisError] | None = None,
                      evidence: list[EvidenceRecord] | None = None) -> "ReportModel":
        return cls(total=len(findings), findings=findings, skipped_files=skipped_files or [],
                   scan_notes=scan_notes or [], analysis_errors=analysis_errors or [], evidence=evidence or [])
