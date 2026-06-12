"""Logique avancée d'extraction de métadonnées d'images."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

from forensic_analyzer.utils.deps import HAS_PIL, PIL_TAGS, PILImage
from forensic_analyzer.utils.logger import get_logger
import os
from forensic_analyzer.utils.magic import get_file_magic_extension

log = get_logger("image")

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

class ImageExifParser:
    """Extracteur de données EXIF pour les images."""
    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> Result[dict[str, str], str]:
        if not HAS_PIL:
            return Err("Bibliothèque 'Pillow' manquante — pip install Pillow")
            
        try:
            with PILImage.open(self.filepath) as img:
                exif_raw = img.getexif()
                info = img.info
                
                data: dict[str, str] = {
                    "Format":     str(img.format),
                    "Dimensions": f"{img.size[0]}x{img.size[1]} px",
                    "Mode":       str(img.mode),
                }
                
                # Mismatch format (Extension spoofing)
                magic_ext = get_file_magic_extension(self.filepath)
                real_ext = os.path.splitext(self.filepath)[1].lower()
                if magic_ext and magic_ext != real_ext:
                    data["Alerte Format (Spoof)"] = f"CRITIQUE: Extension={real_ext} mais Magic Bytes={magic_ext}"
                
                # Commentaires JPEG / PNG
                if "comment" in info:
                    val = info["comment"]
                    if isinstance(val, bytes): val = val.decode('utf-8', 'ignore')
                    data["Commentaire (Metadata)"] = str(val)[:1000]
                    
                # XMP / IPTC
                if "XML:com.adobe.xmp" in info or "xmp" in info or "photoshop" in info:
                    data["IPTC / XMP"] = "Présent (Métadonnées Adobe/Presse)"
                    
                # EXIF & Thumbnail
                if exif_raw:
                    # Detection Thumbnail (IFD 1 ou tag 513 JpegIFOffset)
                    if 513 in exif_raw or 514 in exif_raw or exif_raw.get_ifd(0x014A):
                        data["Thumbnail Embedé"] = "OUI (Peut différer de l'image principale)"
                        
                    for tag_id, value in exif_raw.items():
                        # Eviter de crasher sur les donnees binaires massives
                        if isinstance(value, bytes) and len(value) > 200:
                            continue
                        tag = PIL_TAGS.get(tag_id, str(tag_id))
                        val = str(value)
                        data[f"EXIF: {tag}"] = val[:1000] + ("..." if len(val) > 1000 else "")
                else:
                    data["EXIF"] = "Aucune métadonnée EXIF trouvée"
                    
                # Appended Data (Données après l'EOF de l'image)
                # Très complexe via PIL, mais on peut vérifier si taille de fichier >> taille pixels brute
                # Plus simple: lire la fin du fichier chercher des chaines en clair
                try:
                    with open(self.filepath, "rb") as bf:
                        bf.seek(0, 2)
                        fsize = bf.tell()
                        if fsize > 1024:
                            bf.seek(fsize - 512)
                            tail = bf.read()
                            import re
                            strs = re.findall(rb'[\x20-\x7E]{10,}', tail)
                            if strs:
                                data["Données Suspectes (EOF)"] = "Chaînes trouvées à la toute fin du fichier"
                except Exception:
                    pass
                    
                return Ok(data)
        except Exception as exc:
            return Err(f"Erreur d'extraction d'image : {exc}")
