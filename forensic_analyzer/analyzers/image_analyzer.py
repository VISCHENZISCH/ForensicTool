"""Analyzer pour les images — extraction EXIF via Pillow."""
from __future__ import annotations

import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.deps import HAS_PIL, PIL_TAGS, PILImage
from forensic_analyzer.utils.logger import get_logger

log = get_logger("image")


class ImageAnalyzer(BaseAnalyzer):
    name = "image"
    supported_extensions = ('.jpg', '.jpeg', '.png', '.tiff', '.bmp', '.webp')

    def analyze(self, path: str) -> FindingModel | None:
        if not HAS_PIL:
            log.error("Bibliothèque 'Pillow' manquante — pip install Pillow")
            return None
        try:
            with PILImage.open(path) as img:
                exif_raw = img.getexif()
                data: dict = {
                    "Format":     str(img.format),
                    "Dimensions": f"{img.size[0]}x{img.size[1]} px",
                    "Mode":       str(img.mode),
                }
                if exif_raw:
                    for tag_id, value in exif_raw.items():
                        tag = PIL_TAGS.get(tag_id, str(tag_id))
                        val = str(value)
                        data[tag] = val[:77] + "..." if len(val) > 80 else val
                else:
                    data["EXIF"] = "Aucune métadonnée EXIF trouvée"
            return FindingModel(type="image", file=os.path.abspath(path), metadata=data)
        except Exception as exc:
            log.error("Erreur Image '%s' : %s", os.path.basename(path), exc)
            return None
