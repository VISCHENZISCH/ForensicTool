"""Exporteur PDF - export de rapports de qualité DFIR via weasyprint."""
from __future__ import annotations

from forensic_analyzer.models.finding import ReportModel
from forensic_analyzer.utils.logger import get_logger
from forensic_analyzer.utils.exports import output_path as resolve_output

log = get_logger("pdf_exporter")

class PDFExporter:
    """Exporte un rapport au format PDF via WeasyPrint (chargé à l'export : ~0,3 s d'import)."""

    def export(self, report: ReportModel, output_path: str) -> str:
        """Écrit le PDF et retourne son chemin ; lève RuntimeError si WeasyPrint manque."""
        try:
            import weasyprint
        except (ImportError, OSError) as exc:
            raise RuntimeError("weasyprint absent (pip install weasyprint ; requiert Pango) : "
                               "export PDF impossible") from exc

        from forensic_analyzer.output.html_exporter import build_interactive_html
        target_path = resolve_output(output_path)

        # Aucune ressource chargée (ni réseau ni fichier local) : seules les polices embarquées
        # dans le rapport (data:) sont lues
        def refuse(url, *args, **kwargs):
            if url.startswith("data:"):
                return weasyprint.default_url_fetcher(url, *args, **kwargs)
            raise ValueError(f"ressource externe refusée : {url}")

        weasyprint.HTML(string=build_interactive_html(report), url_fetcher=refuse).write_pdf(target_path)
        log.info("Rapport PDF exporté -> %s", target_path)
        return target_path
