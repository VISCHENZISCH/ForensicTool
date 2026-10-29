"""Neutralisation des caractères de contrôle venant des preuves avant affichage terminal.

Un nom de fichier ou une métadonnée piégée peut contenir des séquences ESC : effacer des
lignes déjà affichées (masquer une alerte), changer le titre ou écrire dans le
presse-papiers (OSC 52). Elles sont rendues visibles (\\x1b) au lieu d'être interprétées.
"""
from __future__ import annotations

import re

# C0 sauf tabulation et saut de ligne, DEL et C1
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def neutralize(text: str) -> str:
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def neutralize_data(value):
    """Applique neutralize aux chaînes d'une structure (dict, list, tuple), clés comprises."""
    if isinstance(value, str):
        return neutralize(value)
    if isinstance(value, dict):
        return {neutralize_data(k): neutralize_data(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(neutralize_data(v) for v in value)
    return value
