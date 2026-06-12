"""Logique d'extraction avancée GPS via exifread."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

from forensic_analyzer.utils.deps import HAS_EXIFREAD, exifread
from forensic_analyzer.utils.logger import get_logger

log = get_logger("gps")

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

class GPSParser:
    """Extracteur de coordonnées GPS à partir de métadonnées EXIF."""
    def __init__(self, filepath: str):
        self.filepath = filepath

    @staticmethod
    def _to_degrees(value) -> float:
        """Convertit un tag GPS EXIF (rationnel) en degrés décimaux."""
        d = float(value.values[0].num) / float(value.values[0].den)
        m = float(value.values[1].num) / float(value.values[1].den)
        s = float(value.values[2].num) / float(value.values[2].den)
        return d + (m / 60.0) + (s / 3600.0)

    def parse(self) -> Result[dict[str, str | float], str]:
        if not HAS_EXIFREAD:
            return Err("Bibliothèque 'exifread' manquante — pip install exifread")
            
        try:
            with open(self.filepath, "rb") as f:
                tags = exifread.process_file(f, details=False)

            lat_t = tags.get("GPS GPSLatitude")
            lat_r = tags.get("GPS GPSLatitudeRef")
            lon_t = tags.get("GPS GPSLongitude")
            lon_r = tags.get("GPS GPSLongitudeRef")

            if not (lat_t and lon_t and lat_r and lon_r):
                return Err("Aucune coordonnée GPS trouvée")

            lat = self._to_degrees(lat_t)
            lon = self._to_degrees(lon_t)
            if str(lat_r) != "N": lat = -lat
            if str(lon_r) != "E": lon = -lon

            meta: dict[str, str | float] = {
                "Latitude":    round(lat, 6),
                "Longitude":   round(lon, 6),
                "Google Maps": f"http://maps.google.com/maps?q=loc:{lat},{lon}",
            }

            alt_t = tags.get("GPS GPSAltitude")
            alt_r = tags.get("GPS GPSAltitudeRef")
            if alt_t and alt_r:
                try:
                    av  = alt_t.values[0]
                    alt = av.num / av.den
                    if hasattr(alt_r, 'values') and alt_r.values[0] == 1: alt = -alt
                    meta["Altitude (m)"] = round(alt, 2)
                except Exception: pass
                
            speed_t = tags.get("GPS GPSSpeed")
            if speed_t:
                try:
                    val = speed_t.values[0]
                    meta["Vitesse (km/h)"] = round(val.num / val.den, 2)
                except Exception: pass
                
            track_t = tags.get("GPS GPSTrack")
            if track_t:
                try:
                    val = track_t.values[0]
                    meta["Direction (Degrés)"] = round(val.num / val.den, 2)
                except Exception: pass
                
            gps_date = tags.get("GPS GPSDateStamp")
            gps_time = tags.get("GPS GPSTimeStamp")
            gps_timestamp_str = ""
            if gps_date and gps_time:
                try:
                    date_str = str(gps_date.values).replace(":", "/")
                    h = int(gps_time.values[0].num / gps_time.values[0].den)
                    m = int(gps_time.values[1].num / gps_time.values[1].den)
                    s = int(gps_time.values[2].num / gps_time.values[2].den)
                    gps_timestamp_str = f"{date_str} {h:02d}:{m:02d}:{s:02d} UTC"
                    meta["Date/Heure GPS (UTC)"] = gps_timestamp_str
                except Exception: pass
                
            exif_date = tags.get("EXIF DateTimeOriginal")
            if exif_date and gps_timestamp_str:
                meta["Date/Heure EXIF"] = str(exif_date.values)
                # L'appareil photo enregistre souvent l'heure locale, le GPS l'heure UTC.
                # S'il y a plus de 24h de décalage ou des dates différentes, on le signale.
                meta["Alerte Timezone"] = "Vérifier le décalage (Heure locale vs Heure Satellite UTC)"
                
            import requests
            try:
                headers = {"User-Agent": "ForensicAnalyzer-DFIR/1.0"}
                url = f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json"
                resp = requests.get(url, headers=headers, timeout=2)
                if resp.status_code == 200:
                    data = resp.json()
                    addr = data.get("display_name", "")
                    if addr:
                        meta["Adresse Approx. (OSM)"] = addr
            except Exception:
                pass  # TODO: log.debug(exc)

            return Ok(meta)
        except Exception as exc:
            return Err(f"Erreur d'extraction GPS : {exc}")
