"""Logique d'extraction avancée (pypdf et fallback) pour les fichiers PDF."""
from __future__ import annotations

import logging
import warnings
import re
from dataclasses import dataclass
from typing import Generic, TypeVar

from forensic_analyzer.utils.deps import HAS_PYPDF, PdfReader
from forensic_analyzer.utils.logger import get_logger

warnings.filterwarnings("ignore", category=UserWarning, module="pypdf")
logging.getLogger("pypdf").setLevel(logging.ERROR)

log = get_logger("pdf")

T = TypeVar('T')
E = TypeVar('E')

@dataclass(frozen=True)
class Ok(Generic[T]):
    value: T
    ok: bool = True

@dataclass(frozen=True)
class Err(Generic[E]):
    error: E
    ok: bool = False

Result = Ok[T] | Err[E]

class PDFParser:
    """Extracteur de métadonnées PDF avec gestion d'erreurs avancée."""
    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> Result[dict[str, str], str]:
        if not HAS_PYPDF:
            log.warning("Bibliothèque 'pypdf' manquante. Mode dégradation actif.")
            return self._fallback_parse()
            
        try:
            reader = PdfReader(self.filepath)
            meta = reader.metadata or {}
            
            data: dict[str, str] = {k.lstrip("/"): str(v) for k, v in meta.items()}
            data["Nombre de pages"] = str(len(reader.pages))
            data["Chiffrement"] = "Chiffré" if reader.is_encrypted else "Non chiffré"
            if reader.pdf_header:
                data["Version PDF"] = str(reader.pdf_header)
                
            return Ok(data)
        except Exception as exc:
            return Err(f"Echec du parsing PyPDF: {exc}")

    def _fallback_parse(self) -> Result[dict[str, str], str]:
        """Méthode de secours utilisant les expressions régulières."""
        metadata: dict[str, str] = {}
        try:
            with open(self.filepath, "rb") as f:
                header = f.readline().decode("utf-8", errors="ignore").strip()
                if header.startswith("%PDF-"):
                    metadata["Version PDF"] = header
                
                # Lire les 100 premiers Ko
                content = f.read(102400).decode("utf-8", errors="ignore")
                for key in ["Title", "Author", "Creator", "Producer", "CreationDate"]:
                    match = re.search(r"/" + key + r"\s*\(([^)]+)\)", content)
                    if match:
                        metadata[key] = match.group(1)
                        
            metadata["Nombre de pages"] = "Inconnu (pypdf manquant)"
            metadata["Chiffrement"] = "Inconnu (pypdf manquant)"
            return Ok(metadata)
        except Exception as exc:
            return Err(f"Echec du fallback regex: {exc}")
