"""Modèles de données Pydantic pour les résultats forensiques."""
from __future__ import annotations

import hashlib
import os
from datetime import datetime
from functools import lru_cache
from typing import Any

from pydantic import BaseModel, Field, model_validator


@lru_cache(maxsize=1024)
def compute_hashes(filepath: str) -> dict[str, str]:
    """
    Calcule les hashes MD5 et SHA-256 d'un fichier.
    Optimisation: Cache LRU pour éviter de relire le même fichier plusieurs fois.
    """
    if not os.path.isfile(filepath):
        return {}
    
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    
    try:
        # Optimisation : Lecture par chunks de 64KB (au lieu de 4KB) pour réduire l'overhead I/O
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
                md5.update(chunk)
        return {
            "MD5": md5.hexdigest(),
            "SHA-256": sha256.hexdigest()
        }
    except Exception as exc:
        pass  # TODO: log.debug(exc)
        return {}


class FindingModel(BaseModel):
    """Résultat d'une analyse forensique sur un fichier."""
    type: str
    file: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    extra: dict[str, Any] = Field(default_factory=dict)

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


class ReportModel(BaseModel):
    """Rapport global d'une session d'analyse complète."""
    tool: str = "Forensic Analyzer v1.0"
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    total: int = 0
    findings: list[FindingModel] = Field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: list[FindingModel]) -> "ReportModel":
        return cls(total=len(findings), findings=findings)
