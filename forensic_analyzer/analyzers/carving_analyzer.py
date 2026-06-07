"""Analyzer file carving - magic bytes, fichiers embarques, polyglot detection."""
from __future__ import annotations
import os
import struct
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("carving")

# Signatures magic bytes (offset, magic, extension, description)
SIGNATURES: list[tuple[int, bytes, str, str]] = [
    # Images
    (0, b'\xFF\xD8\xFF',           "jpg",  "JPEG Image"),
    (0, b'\x89PNG\r\n\x1A\n',     "png",  "PNG Image"),
    (0, b'GIF87a',                 "gif",  "GIF87a Image"),
    (0, b'GIF89a',                 "gif",  "GIF89a Image"),
    (0, b'BM',                     "bmp",  "BMP Image"),
    (0, b'RIFF',                   "webp", "RIFF/WEBP"),
    (0, b'\x00\x00\x01\x00',      "ico",  "ICO Icon"),
    (0, b'\x49\x49\x2A\x00',      "tiff", "TIFF (little-endian)"),
    (0, b'\x4D\x4D\x00\x2A',      "tiff", "TIFF (big-endian)"),
    # Archives
    (0, b'PK\x03\x04',            "zip",  "ZIP Archive"),
    (0, b'PK\x05\x06',            "zip",  "ZIP Archive (empty)"),
    (0, b'\x1F\x8B\x08',          "gz",   "GZIP Archive"),
    (0, b'BZh',                    "bz2",  "BZIP2 Archive"),
    (0, b'\xFD7zXZ\x00',          "xz",   "XZ Archive"),
    (0, b'7z\xBC\xAF\x27\x1C',   "7z",   "7-Zip Archive"),
    (0, b'\x52\x61\x72\x21\x1A\x07', "rar", "RAR Archive"),
    (0, b'ustar',                  "tar",  "TAR Archive (POSIX)"),
    # Documents
    (0, b'%PDF',                   "pdf",  "PDF Document"),
    (0, b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', "doc", "OLE2 (DOC/XLS/PPT)"),
    # Executables
    (0, b'\x7FELF',               "elf",  "ELF Executable"),
    (0, b'MZ',                     "exe",  "PE/DOS Executable"),
    (0, b'\xFE\xED\xFA\xCE',     "macho", "Mach-O 32-bit"),
    (0, b'\xFE\xED\xFA\xCF',     "macho", "Mach-O 64-bit"),
    (0, b'\xCF\xFA\xED\xFE',     "macho", "Mach-O 64-bit (reverse)"),
    (0, b'\xCA\xFE\xBA\xBE',     "class", "Java Class / Mach-O Fat"),
    # Multimedia
    (0, b'\x00\x00\x00\x1CftypM', "mp4",  "MP4 Video (ftyp)"),
    (0, b'\x00\x00\x00\x18ftyp', "mp4",   "MP4 Video (ftyp)"),
    (0, b'\x00\x00\x00\x20ftyp', "mp4",   "MP4 Video (ftyp)"),
    (4, b'ftyp',                   "mp4",  "MP4/M4A (generic ftyp)"),
    (0, b'\x1A\x45\xDF\xA3',     "mkv",  "MKV/WEBM Video"),
    (0, b'OggS',                   "ogg",  "OGG Audio/Video"),
    (0, b'fLaC',                   "flac", "FLAC Audio"),
    (0, b'ID3',                    "mp3",  "MP3 Audio (ID3)"),
    (0, b'\xFF\xFB',              "mp3",  "MP3 Audio (sync)"),
    # Bases de donnees
    (0, b'SQLite format 3\x00',   "sqlite","SQLite Database"),
    # Crypto / certs
    (0, b'-----BEGIN',             "pem",  "PEM Certificate/Key"),
    # Disk images
    (0, b'\xEB\x3C\x90',         "fat",  "FAT Boot Sector"),
    (0, b'\xEB\x58\x90',         "ntfs", "NTFS Boot Sector"),
    (0x8001, b'CD001',             "iso",  "ISO 9660"),
    # Scripts
    (0, b'#!/',                    "script","Unix Script (shebang)"),
    (0, b'<?xml',                  "xml",  "XML Document"),
    (0, b'<!DOCTYPE html',        "html", "HTML Document"),
    (0, b'<html',                  "html", "HTML Document"),
    # Firmware / divers
    (0, b'\x27\x05\x19\x56',     "uimage","U-Boot Image"),
]

# Terminateurs connus pour carving
_TERMINATORS = {
    "jpg": b'\xFF\xD9',
    "png": b'\x00\x00\x00\x00IEND\xAE\x42\x60\x82',
    "zip": b'PK\x05\x06',
    "pdf": b'%%EOF',
}


def scan_magic_bytes(data: bytes, offset_base: int = 0) -> list[dict]:
    """Scanne les magic bytes dans un buffer de donnees."""
    found = []
    data_len = len(data)

    for sig_offset, magic, ext, desc in SIGNATURES:
        # Recherche a partir du debut
        search_start = 0
        while search_start < data_len:
            pos = data.find(magic, search_start + sig_offset)
            if pos == -1:
                break
            # Verifier que l'offset relatif correspond
            actual_offset = pos - sig_offset
            if actual_offset >= 0:
                found.append({
                    "offset": offset_base + actual_offset,
                    "offset_hex": hex(offset_base + actual_offset),
                    "magic": magic[:16].hex(),
                    "extension": ext,
                    "description": desc,
                })
            search_start = pos + 1
            # Limiter pour eviter les boucles infinies sur de gros fichiers
            if len(found) > 500:
                break
        if len(found) > 500:
            break

    # Trier par offset
    found.sort(key=lambda x: x["offset"])
    return found


def detect_embedded_files(data: bytes) -> list[dict]:
    """Detecte les fichiers embarques dans un fichier hote."""
    embedded = []

    # Chercher ZIP dans un fichier
    zip_magic = b'PK\x03\x04'
    idx = 0
    while True:
        pos = data.find(zip_magic, idx)
        if pos == -1 or pos == 0:  # On ignore l'offset 0 (c'est le fichier lui-meme)
            break
        # Essayer de trouver la fin du ZIP
        end_central = data.find(b'PK\x05\x06', pos + 4)
        if end_central != -1:
            # La taille du ZIP est environ end_central + 22 - pos
            zip_size = end_central + 22 - pos
            embedded.append({
                "type": "ZIP",
                "offset": pos,
                "offset_hex": hex(pos),
                "estimated_size": zip_size,
                "detail": f"Archive ZIP embarquee a l'offset {hex(pos)}",
            })
        idx = pos + 4

    # Chercher PNG embarque
    png_magic = b'\x89PNG\r\n\x1A\n'
    idx = 0
    while True:
        pos = data.find(png_magic, idx)
        if pos == -1 or pos == 0:
            break
        iend = data.find(b'IEND', pos + 8)
        if iend != -1:
            png_size = iend + 8 - pos
            embedded.append({
                "type": "PNG",
                "offset": pos,
                "offset_hex": hex(pos),
                "estimated_size": png_size,
                "detail": f"Image PNG embarquee a l'offset {hex(pos)}",
            })
        idx = pos + 8

    # Chercher ELF embarque
    elf_magic = b'\x7FELF'
    idx = 0
    while True:
        pos = data.find(elf_magic, idx)
        if pos == -1 or pos == 0:
            break
        embedded.append({
            "type": "ELF",
            "offset": pos,
            "offset_hex": hex(pos),
            "estimated_size": -1,
            "detail": f"Binaire ELF embarque a l'offset {hex(pos)}",
        })
        idx = pos + 4

    # Chercher PDF embarque
    pdf_magic = b'%PDF'
    idx = 0
    while True:
        pos = data.find(pdf_magic, idx)
        if pos == -1 or pos == 0:
            break
        eof = data.find(b'%%EOF', pos + 4)
        pdf_size = (eof + 5 - pos) if eof != -1 else -1
        embedded.append({
            "type": "PDF",
            "offset": pos,
            "offset_hex": hex(pos),
            "estimated_size": pdf_size,
            "detail": f"Document PDF embarque a l'offset {hex(pos)}",
        })
        idx = pos + 4

    embedded.sort(key=lambda x: x["offset"])
    return embedded


def detect_polyglot(data: bytes, path: str) -> list[str]:
    """Detecte si un fichier est un polyglot (valide dans plusieurs formats)."""
    ext = os.path.splitext(path)[1].lower()
    polyglots = []

    # JPEG + ZIP
    if data[:2] == b'\xFF\xD8' and b'PK\x03\x04' in data:
        polyglots.append("JPEG+ZIP polyglot")

    # PDF + ZIP
    if data[:4] == b'%PDF' and b'PK\x03\x04' in data:
        polyglots.append("PDF+ZIP polyglot")

    # PNG + ZIP (apres IEND)
    if data[:8] == b'\x89PNG\r\n\x1A\n':
        iend_pos = data.find(b'IEND')
        if iend_pos != -1 and data.find(b'PK\x03\x04', iend_pos) != -1:
            polyglots.append("PNG+ZIP polyglot")

    # HTML + script
    if data[:1] == b'<' and b'#!/' in data:
        polyglots.append("HTML+Script polyglot")

    # ELF + ZIP
    if data[:4] == b'\x7FELF' and b'PK\x03\x04' in data:
        polyglots.append("ELF+ZIP polyglot")

    return polyglots


def _try_repair_zip(data: bytes, zip_start: int) -> dict:
    """Tente de verifier/reparer un ZIP corrompu."""
    zip_data = data[zip_start:]
    result = {
        "valid_local_headers": 0,
        "corrupted_headers": 0,
        "files_found": [],
    }

    pos = 0
    while pos < len(zip_data) - 4:
        if zip_data[pos:pos+4] == b'PK\x03\x04':
            result["valid_local_headers"] += 1
            try:
                fname_len = struct.unpack_from('<H', zip_data, pos + 26)[0]
                extra_len = struct.unpack_from('<H', zip_data, pos + 28)[0]
                fname = zip_data[pos+30:pos+30+fname_len].decode('utf-8', 'replace')
                result["files_found"].append(fname)
                comp_size = struct.unpack_from('<I', zip_data, pos + 18)[0]
                pos += 30 + fname_len + extra_len + comp_size
            except (struct.error, IndexError):
                result["corrupted_headers"] += 1
                pos += 4
        else:
            pos += 1

    return result


class CarvingAnalyzer(BaseAnalyzer):
    """File carving - detecte et extrait les fichiers embarques via magic bytes."""
    name = "carving"
    supported_extensions = ()  # Fonctionne sur tout type de fichier

    def can_handle(self, path: str) -> bool:
        return False  # Active uniquement via CLI --carve

    def analyze(self, path: str) -> FindingModel | None:
        try:
            file_size = os.path.getsize(path)
            # Limiter la lecture a 100 Mo
            max_read = min(file_size, 100 * 1024 * 1024)

            with open(path, "rb") as f:
                data = f.read(max_read)

            # 1. Scanner les magic bytes
            magic_hits = scan_magic_bytes(data)

            # 2. Detecter les fichiers embarques
            embedded = detect_embedded_files(data)

            # 3. Detecter les polyglots
            polyglots = detect_polyglot(data, path)

            # 4. Tenter de reparer les ZIP corrompus si trouves
            zip_repairs = []
            for emb in embedded:
                if emb["type"] == "ZIP":
                    repair = _try_repair_zip(data, emb["offset"])
                    zip_repairs.append({
                        "offset": emb["offset"],
                        "repair_info": repair,
                    })

            # Construire metadata plate
            meta: dict = {
                "Taille fichier": f"{file_size:,} octets",
                "Taille analysee": f"{max_read:,} octets",
                "Signatures trouvees": str(len(magic_hits)),
                "Fichiers embarques": str(len(embedded)),
                "Polyglots detectes": ", ".join(polyglots) if polyglots else "Aucun",
            }

            # Ajouter les signatures les plus importantes
            for i, hit in enumerate(magic_hits[:20]):
                meta[f"Sig #{i+1}"] = (
                    f"[{hit['extension'].upper()}] {hit['description']} "
                    f"@ offset {hit['offset_hex']}"
                )

            for i, emb in enumerate(embedded[:10]):
                size_str = (f"{emb['estimated_size']:,} octets"
                           if emb["estimated_size"] > 0 else "taille inconnue")
                meta[f"Embedded #{i+1}"] = (
                    f"[{emb['type']}] @ {emb['offset_hex']} ({size_str})"
                )

            return FindingModel(
                type="carving",
                file=os.path.abspath(path),
                metadata=meta,
                extra={
                    "magic_hits": magic_hits[:100],
                    "embedded": embedded,
                    "polyglots": polyglots,
                    "zip_repairs": zip_repairs,
                },
            )
        except Exception as exc:
            log.error("Erreur carving '%s' : %s", os.path.basename(path), exc)
            return None
