"""Analyseur pour fichiers images."""
from __future__ import annotations

import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

from .parser import ImageExifParser, Ok, Err

log = get_logger("image")

class ImageAnalyzer(BaseAnalyzer):
    """Analyseur d'images avec extraction EXIF avancée."""
    name = "image"
    supported_extensions = ('.jpg', '.jpeg', '.png', '.tiff', '.bmp', '.webp')

    def analyze(self, path: str) -> FindingModel | None:
        if not self.can_handle(path):
            return None

        log.debug(f"Analyse Image sur {path}...")
        parser = ImageExifParser(path)
        
        match parser.parse():
            case Ok(value=metadata):
                return FindingModel(
                    type="image",
                    file=os.path.abspath(path),
                    metadata=metadata,
                    extra={}
                )
            case Err(error=msg):
                short_msg = msg.split(':')[-1].strip() if ':' in msg else msg
                log.warning("↳ Image corrompue ou illisible (%s)", short_msg)
                return None
