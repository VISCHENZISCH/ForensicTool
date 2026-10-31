"""Politique d'accès réseau (OPSEC) partagée par tous les analyzers."""
import os

_online = os.environ.get("FORENSIC_ONLINE") == "1"


def online_enabled() -> bool:
    return _online


def set_online(enabled: bool) -> None:
    global _online
    _online = enabled
