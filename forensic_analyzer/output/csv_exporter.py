"""Exporteur CSV - timeline Plaso-compatible."""
from __future__ import annotations
import csv
from forensic_analyzer.models.finding import ReportModel
from forensic_analyzer.analyzers.timeline_analyzer import build_timeline
from forensic_analyzer.utils.logger import get_logger

log = get_logger("csv_exporter")

_FIELDNAMES = ["timestamp", "source", "event_type", "description", "file", "details"]


class CSVExporter:
    """Exporte la timeline en CSV compatible Plaso/DFIR."""

    def export(self, report: ReportModel, output_path: str) -> None:
        events = build_timeline(report)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
            writer.writeheader()
            writer.writerows(events)
        log.info("Timeline CSV exportee -> %s (%d evenements)", output_path, len(events))
