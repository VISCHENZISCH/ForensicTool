"""Dossier de sortie de l'analyse en cours : une affaire = un sous-dossier de export/.

Sans cela, rapports et extractions de plusieurs enquêtes se mélangent dans export/.
Le dossier n'est créé qu'à la première écriture.
"""
from __future__ import annotations

import datetime
import os
import re
import unicodedata

_root = "export"


def export_root() -> str:
    return _root


def set_export_root(path: str) -> str:
    global _root
    _root = path
    return _root


def output_path(path: str) -> str:
    """Chemin d'un export : un nom seul va dans le dossier de l'affaire, un chemin est respecté."""
    target = path if os.path.dirname(path) else os.path.join(_root, path)
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    return target


def new_case_dir(label: str) -> str:
    """export/FT-AAAAMMJJ-HHMMSS-LIBELLÉ pour une nouvelle analyse (FT : Forensic Tool)."""
    name = unicodedata.normalize("NFKD", os.path.basename(os.path.normpath(label or "analyse")))
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name.encode("ascii", "ignore").decode()).strip("-").upper()
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return set_export_root(os.path.join("export", f"FT-{stamp}-{slug or 'ANALYSE'}"))
