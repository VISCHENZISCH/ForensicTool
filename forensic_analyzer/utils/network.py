"""Politique d'accès réseau (OPSEC) partagée par tous les analyzers."""
import os

# Toute requête vers un service tiers (MalwareBazaar, VirusTotal, OpenStreetMap...)
# divulgue un élément de l'investigation : hash, coordonnées GPS, etc.
# Désactivé par défaut ; activé via --online ou FORENSIC_ONLINE=1.
_online = os.environ.get("FORENSIC_ONLINE") == "1"


def online_enabled() -> bool:
    return _online


def set_online(enabled: bool) -> None:
    global _online
    _online = enabled
