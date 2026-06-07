"""Exporteur PDF - export de rapports de qualite DFIR via weasyprint."""
from __future__ import annotations
import os
from forensic_analyzer.models.finding import ReportModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("pdf_exporter")

try:
    import weasyprint
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


class PDFExporter:
    """Exporte un rapport au format PDF via WeasyPrint."""

    def export(self, report: ReportModel, output_path: str) -> None:
        if not HAS_WEASYPRINT:
            log.error(
                "weasyprint n'est pas installe. L'export PDF requiert cette bibliotheque.\n"
                "Installez-la avec : pip install weasyprint\n"
                "(Note: requiert egalement les librairies systemes Pango et GTK+)"
            )
            return

        try:
            from forensic_analyzer.output.html_exporter import build_interactive_html
            html_content = build_interactive_html(report)
            
            # Generer le PDF directement a partir du contenu HTML
            weasyprint.HTML(string=html_content).write_pdf(output_path)
            log.info("Rapport PDF exporte -> %s", output_path)
        except Exception as exc:
            log.error("Erreur d'export PDF via WeasyPrint : %s", exc)
