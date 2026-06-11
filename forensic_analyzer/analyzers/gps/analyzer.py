"""Analyseur pour coordonnées GPS."""
from __future__ import annotations

import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

from .parser import GPSParser, Ok, Err

log = get_logger("gps")

class GPSAnalyzer(BaseAnalyzer):
    """Analyzer dédié à l'extraction GPS."""
    name = "gps"
    supported_extensions = ('.jpg', '.jpeg', '.tiff')

    def analyze(self, path: str) -> FindingModel | None:
        if not self.can_handle(path):
            return None

        log.debug(f"Analyse GPS sur {path}...")
        parser = GPSParser(path)
        
        match parser.parse():
            case Ok(value=metadata):
                return FindingModel(
                    type="gps",
                    file=os.path.abspath(path),
                    metadata=metadata,
                    extra={}
                )
            case Err(error=msg):
                if "Aucune coordonnée" not in msg:
                    log.error("Erreur GPS '%s' : %s", os.path.basename(path), msg)
                return None
