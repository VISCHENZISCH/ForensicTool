"""Exporteur PDF - export de rapports de qualité DFIR via weasyprint."""
from __future__ import annotations

import os

from forensic_analyzer.models.finding import ReportModel
from forensic_analyzer.utils.logger import get_logger
from forensic_analyzer.utils.exports import export_root

log = get_logger("pdf_exporter")

class PDFExporter:
    """Exporte un rapport au format PDF via WeasyPrint (chargé à l'export : ~0,3 s d'import)."""

    def export(self, report: ReportModel, output_path: str) -> None:
        try:
            import weasyprint
        except (ImportError, OSError):
            log.error(
                "weasyprint n'est pas installé. L'export PDF requiert cette bibliothèque.\n"
                "Installez-la avec : pip install weasyprint\n"
                "(Note: requiert également les librairies systèmes Pango et GTK+)"
            )
            return

        try:
            filename = os.path.basename(output_path)
            os.makedirs(export_root(), exist_ok=True)
            target_path = os.path.join(export_root(), filename)
            from forensic_analyzer.output.html_exporter import \
                build_interactive_html
            html_content = build_interactive_html(report)

            # Générer le PDF directement à partir du contenu HTML
            weasyprint.HTML(string=html_content).write_pdf(target_path)
            log.info("Rapport PDF exporté -> %s", target_path)
        except Exception as exc:
            log.error("Erreur d'export PDF via WeasyPrint : %s", exc)
