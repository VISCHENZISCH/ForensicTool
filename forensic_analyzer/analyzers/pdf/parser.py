"""Métadonnées d'un PDF via pypdf (dictionnaire /Info, pages, chiffrement)."""
from __future__ import annotations

import logging
import re

from forensic_analyzer.utils.deps import HAS_PYPDF, PdfReader

# pypdf journalise chaque défaut de structure ; l'analyse de menace les traite elle-même
logging.getLogger("pypdf").setLevel(logging.ERROR)

_PDF_DATE = re.compile(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(Z|[+-]\d{2}'?\d{2}'?)?")


def read_metadata(path: str) -> tuple[dict[str, str], object | None, str | None]:
    """
    Retourne (champs, lecteur pypdf lisible ou None, erreur ou None).
    Un PDF chiffré n'est lisible que si le mot de passe utilisateur est vide (cas courant :
    seul le mot de passe propriétaire, qui restreint l'impression ou la copie, est posé).
    """
    if not HAS_PYPDF:
        return {}, None, "pypdf absent"
    try:
        reader = PdfReader(path)
        data: dict[str, str] = {}
        if reader.is_encrypted:
            if not reader.decrypt(""):
                return {"Chiffrement": "Chiffré, mot de passe requis (contenu illisible)"}, None, None
            data["Chiffrement"] = "Chiffré, mot de passe utilisateur vide (contenu lisible)"
        else:
            data["Chiffrement"] = "Non chiffré"
        for key, value in (reader.metadata or {}).items():
            data[key.lstrip("/")] = str(value)
        data["Nombre de pages"] = str(len(reader.pages))
        data["Version PDF"] = reader.pdf_header
        return data, reader, None
    except Exception as exc:
        return {}, None, f"structure illisible par pypdf ({exc})"


def format_pdf_date(value: str) -> str:
    """D:20230102101500+01'00' -> 2023-01-02 10:15:00 +01:00 (D:20230102101500+01'00')."""
    m = _PDF_DATE.match(value.strip())
    if not m:
        return value
    y, mo, d, h, mi, s, tz = m.groups()
    out = f"{y}-{mo or '01'}-{d or '01'} {h or '00'}:{mi or '00'}:{s or '00'}"
    if tz:
        out += " UTC" if tz == "Z" else f" {tz[:3]}:{tz.replace(chr(39), '')[3:5] or '00'}"
    return f"{out} ({value.strip()})"
