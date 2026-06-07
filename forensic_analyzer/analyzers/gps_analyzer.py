"""Analyzer GPS — extraction et conversion de coordonnées EXIF via exifread."""
from __future__ import annotations
import os
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.deps import exifread, HAS_EXIFREAD
from forensic_analyzer.utils.logger import get_logger

log = get_logger("gps")


def _to_degrees(value) -> float:
    """Convertit un tag GPS EXIF (rationnel) en degrés décimaux."""
    d = float(value.values[0].num) / float(value.values[0].den)
    m = float(value.values[1].num) / float(value.values[1].den)
    s = float(value.values[2].num) / float(value.values[2].den)
    return d + (m / 60.0) + (s / 3600.0)


class GPSAnalyzer(BaseAnalyzer):
    """
    Analyzer dédié à l'extraction GPS.
    Ne s'active que si explicitement demandé via --gps (non utilisé en auto-scan).
    """
    name = "gps"
    supported_extensions = ('.jpg', '.jpeg', '.tiff')

    def analyze(self, path: str) -> FindingModel | None:
        if not HAS_EXIFREAD:
            log.error("Bibliothèque 'exifread' manquante — pip install exifread")
            return None
        try:
            with open(path, "rb") as f:
                tags = exifread.process_file(f, details=False)

            lat_t = tags.get("GPS GPSLatitude")
            lat_r = tags.get("GPS GPSLatitudeRef")
            lon_t = tags.get("GPS GPSLongitude")
            lon_r = tags.get("GPS GPSLongitudeRef")

            if not (lat_t and lon_t and lat_r and lon_r):
                log.info("Aucune coordonnée GPS dans '%s'", os.path.basename(path))
                return None

            lat = _to_degrees(lat_t)
            lon = _to_degrees(lon_t)
            if str(lat_r) != "N": lat = -lat
            if str(lon_r) != "E": lon = -lon

            meta: dict = {
                "Latitude":    round(lat, 6),
                "Longitude":   round(lon, 6),
                "Google Maps": f"http://maps.google.com/maps?q=loc:{lat},{lon}",
            }

            alt_t = tags.get("GPS GPSAltitude")
            alt_r = tags.get("GPS GPSAltitudeRef")
            if alt_t and alt_r:
                av  = alt_t.values[0]
                alt = av.num / av.den
                if alt_r.values[0] == 1: alt = -alt
                meta["Altitude (m)"] = round(alt, 2)

            return FindingModel(type="gps", file=os.path.abspath(path), metadata=meta)
        except Exception as exc:
            log.error("Erreur GPS '%s' : %s", os.path.basename(path), exc)
            return None
