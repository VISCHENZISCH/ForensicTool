"""Exporteur JSON — rapport structuré et horodaté."""
from __future__ import annotations

import json

from forensic_analyzer.models.finding import ReportModel
from forensic_analyzer.utils.logger import get_logger
from forensic_analyzer.utils.exports import export_root

log = get_logger("json_exporter")


class JSONExporter:
    """Exporte un ReportModel en fichier JSON indenté."""

    def export(self, report: ReportModel, output_path: str) -> None:
        """
        Sérialise le rapport en JSON et l'écrit sur le disque.

        Args:
            report:      ReportModel à exporter.
            output_path: Chemin de destination du fichier .json.
        """
        import os
        filename = os.path.basename(output_path)
        os.makedirs(export_root(), exist_ok=True)
        target_path = os.path.join(export_root(), filename)
        data = report.model_dump()
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        log.info("Rapport JSON exporté → %s (%d résultat(s))", target_path, report.total)
