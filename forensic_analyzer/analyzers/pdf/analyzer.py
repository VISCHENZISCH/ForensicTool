"""Analyseur pour fichiers PDF."""
from __future__ import annotations

import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

from .parser import PDFParser, Ok, Err

log = get_logger("pdf")

class PDFAnalyzer(BaseAnalyzer):
    """Analyseur de fichiers PDF."""
    name = "pdf"
    supported_extensions = ('.pdf',)

    def analyze(self, path: str) -> FindingModel | None:
        if not self.can_handle(path):
            return None

        log.debug(f"Analyse PDF sur {path}...")
        parser = PDFParser(path)
        metadata = {}
        extra = {}
        
        match parser.parse():
            case Ok(value=meta):
                metadata = meta
            case Err(error=msg):
                short_msg = msg.split(':')[-1].strip() if ':' in msg else msg
                log.warning("↳ Fichier corrompu ou illisible (%s)", short_msg)
                
        # Analyse heuristique (Malware PDF)
        from forensic_analyzer.analyzers.malware.pdf_parser import extract_pdf_artifacts
        pdf_info = extract_pdf_artifacts(path)
        
        if "error" not in pdf_info:
            if pdf_info["has_js"] or pdf_info["has_openaction"]:
                metadata["PDF Actions"] = "JavaScript / OpenAction détectés (Critique)"
            if pdf_info["has_embedded_files"]:
                metadata["Fichiers Embarqués"] = "Dropper détecté (EmbeddedFiles)"
            if pdf_info["high_entropy_streams"] > 0:
                metadata["Streams Obfusqués"] = f"{pdf_info['high_entropy_streams']} objet(s) à forte entropie (>7.5)"
            if pdf_info.get("is_linearized"):
                metadata["Linéarisation"] = "OUI (Fast Web View)"
            if pdf_info.get("shellcode_detected"):
                metadata["Shellcode"] = "DÉTECTÉ (NOP Sleds / Heap Spray) (CRITIQUE)"
                
            score = 0
            if pdf_info.get("shellcode_detected"): score += 50
            if pdf_info.get("has_js"): score += 30
            if pdf_info.get("has_openaction"): score += 30
            if pdf_info.get("has_embedded_files"): score += 20
            if pdf_info.get("high_entropy_streams", 0) > 0: score += 10
            
            if score >= 50: level = "Critique"
            elif score >= 30: level = "Élevé"
            elif score > 0: level = "Moyen"
            else: level = "Faible"
            metadata["Niveau de Menace (Scoring PDF)"] = f"{score}/100 ({level})"
                
            if pdf_info["urls"]:
                url_str = "\n".join(pdf_info["urls"])
                metadata["URLs Embedées"] = url_str[:1000] + ("..." if len(url_str) > 1000 else "")
                extra["pdf_urls"] = pdf_info["urls"]
                
            if pdf_info["suspicious_tags"]:
                metadata["Tags PDF Suspects"] = ", ".join(pdf_info["suspicious_tags"])
                
            if pdf_info["javascript_extracted"]:
                js_str = "\n".join(pdf_info["javascript_extracted"])
                metadata["JS Code Extrait"] = js_str[:1000] + ("..." if len(js_str) > 1000 else "")
                extra["pdf_javascript"] = pdf_info["javascript_extracted"]
                
        if not metadata:
            return None

        return FindingModel(
            type="pdf_analysis",
            file=os.path.abspath(path),
            metadata=metadata,
            extra=extra
        )
