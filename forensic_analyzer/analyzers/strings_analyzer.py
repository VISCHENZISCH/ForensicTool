"""Analyzer pour l'extraction de chaînes imprimables depuis des fichiers binaires."""
from __future__ import annotations

import os
import re

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("strings")

_PATTERN = re.compile(rb"[\x20-\x7E]{4,}")


class StringsAnalyzer(BaseAnalyzer):
    """
    Extrait les séquences de caractères ASCII imprimables (≥ 4 chars)
    depuis n'importe quel fichier binaire.
    Activé uniquement via --strings (aucune extension requise).
    """
    name = "strings"
    supported_extensions = ()   # Géré manuellement via CLI, pas en auto-scan

    def can_handle(self, path: str) -> bool:
        return False  # Désactivé en auto-scan

    def analyze(self, path: str, max_results: int = 300) -> FindingModel | None:
        try:
            strings = []
            chunk_size = 1024 * 1024
            overlap = 8
            
            with open(path, "rb") as f:
                f.seek(0, 2)
                file_size = f.tell()
                f.seek(0)
                
                if file_size == 0:
                    return FindingModel(
                        type="strings",
                        file=os.path.abspath(path),
                        metadata={
                            "total_trouvées": 0,
                            "max_affichées":  max_results,
                        },
                        extra={"strings": []},
                    )
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    for m in _PATTERN.finditer(chunk):
                        strings.append(m.group().decode("ascii", "ignore"))
                        if len(strings) >= 5000:  # Cap size for safety
                            break
                    
                    if len(strings) >= 5000:
                        break
                    
                    # Advance safely with overlap to prevent cut-off strings
                    current_pos = f.tell()
                    if current_pos < file_size:
                        f.seek(max(0, current_pos - overlap))
                    else:
                        break
                        
            return FindingModel(
                type="strings",
                file=os.path.abspath(path),
                metadata={
                    "total_trouvées": len(strings),
                    "max_affichées":  max_results,
                },
                extra={"strings": strings[:max_results]},
            )
        except Exception as exc:
            log.error("Erreur Strings '%s' : %s", os.path.basename(path), exc)
            return None

