"""Analyzer pour les fichiers PDF — extraction de métadonnées via pypdf."""
from __future__ import annotations
import os
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.deps import PdfReader, HAS_PYPDF
from forensic_analyzer.utils.logger import get_logger

import warnings
import logging
warnings.filterwarnings("ignore", category=UserWarning, module="pypdf")
logging.getLogger("pypdf").setLevel(logging.ERROR)

log = get_logger("pdf")



class PDFAnalyzer(BaseAnalyzer):
    name = "pdf"
    supported_extensions = ('.pdf',)

    def analyze(self, path: str) -> FindingModel | None:
        if not HAS_PYPDF:
            log.warning("Bibliotheque 'pypdf' manquante. Mode degradation actif.")
            # Fallback regex extraction of metadata if pypdf is missing
            metadata = {}
            try:
                with open(path, "rb") as f:
                    header = f.readline().decode("utf-8", errors="ignore").strip()
                    if header.startswith("%PDF-"):
                        metadata["Version PDF"] = header
                    # Read first 100KB for metadata keys
                    content = f.read(102400).decode("utf-8", errors="ignore")
                    import re
                    for key in ["Title", "Author", "Creator", "Producer", "CreationDate"]:
                        match = re.search(r"/" + key + r"\s*\(([^)]+)\)", content)
                        if match:
                            metadata[key] = match.group(1)
                metadata["Nombre de pages"] = "Inconnu (pypdf manquant)"
                metadata["Chiffrement"] = "Inconnu (pypdf manquant)"
                return FindingModel(type="pdf", file=os.path.abspath(path), metadata=metadata)
            except Exception as exc:
                log.error("Erreur PDF fallback '%s' : %s", os.path.basename(path), exc)
                return None
        try:
            reader = PdfReader(path)
            meta   = reader.metadata or {}
            data: dict = {k.lstrip("/"): str(v) for k, v in meta.items()}
            data["Nombre de pages"] = str(len(reader.pages))
            data["Chiffrement"]     = "Chiffré" if reader.is_encrypted else "Non chiffré"
            data["Version PDF"]     = str(reader.pdf_header)
            return FindingModel(type="pdf", file=os.path.abspath(path), metadata=data)
        except Exception as exc:
            log.error("Erreur PDF '%s' : %s", os.path.basename(path), exc)
            return None

