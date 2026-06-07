"""Modèles de données Pydantic pour les résultats forensiques."""
from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class FindingModel(BaseModel):
    """Résultat d'une analyse forensique sur un fichier."""
    type: str
    file: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    extra: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class ReportModel(BaseModel):
    """Rapport global d'une session d'analyse complète."""
    tool: str = "Forensic Analyzer v1.0"
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    total: int = 0
    findings: list[FindingModel] = Field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: list[FindingModel]) -> "ReportModel":
        return cls(total=len(findings), findings=findings)
