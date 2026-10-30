"""Exporteur CSV - timeline Plaso-compatible."""
from __future__ import annotations

import csv

from forensic_analyzer.analyzers.timeline import build_timeline
from forensic_analyzer.core.timeline import consolidate
from forensic_analyzer.models.finding import ReportModel
from forensic_analyzer.utils.logger import get_logger
from forensic_analyzer.utils.exports import export_root
from forensic_analyzer.utils.spreadsheet import neutralize_formula

log = get_logger("csv_exporter")

_FIELDNAMES = ["timestamp", "source", "event_type", "description", "file", "details",
               "confidence", "corroborating_sources"]


class CSVExporter:
    """Exporte la timeline en CSV compatible Plaso/DFIR."""

    def export(self, report: ReportModel, output_path: str) -> None:
        import os
        target_dir = os.path.dirname(output_path)
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)
            target_path = output_path
        else:
            os.makedirs(export_root(), exist_ok=True)
            target_path = os.path.join(export_root(), output_path)
        events = build_timeline(report)
        # Confiance du fait consolide auquel appartient chaque événement
        for fact in consolidate(events):
            for e in fact["events"]:
                e["confidence"] = fact["confidence"]
                e["corroborating_sources"] = "+".join(fact["sources"])
        with open(target_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=_FIELDNAMES, extrasaction="ignore")
            writer.writeheader()
            writer.writerows({k: neutralize_formula(v) for k, v in e.items()} for e in events)
        log.info("Timeline CSV exportée -> %s (%d événements)", target_path, len(events))
