"""Cellules CSV sans formule : les exports s'ouvrent dans Excel, LibreOffice ou Timeline Explorer.

Une commande, une URL ou un nom de fichier venant des preuves qui commence par = + - @
serait évalué comme formule (CWE-1236) : l'apostrophe en tête le garde en texte.
"""
from __future__ import annotations

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def neutralize_formula(value):
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value
