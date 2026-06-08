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
            filename = os.path.basename(output_path)
            os.makedirs("export", exist_ok=True)
            target_path = os.path.join("export", filename)
            from forensic_analyzer.output.html_exporter import \
                build_interactive_html
            html_content = build_interactive_html(report)
            
            # Remove remote fonts to prevent WeasyPrint network hang
            font_link = '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">'
            html_content = html_content.replace(font_link, '')
            
            # Generer le PDF directement a partir du contenu HTML
            weasyprint.HTML(string=html_content).write_pdf(target_path)
            log.info("Rapport PDF exporte -> %s", target_path)
        except Exception as exc:
            log.error("Erreur d'export PDF via WeasyPrint : %s", exc)
