"""Configuration d'entreprise (TOML) : valeurs par défaut communes à un SOC ou un CERT.

Le fichier ne fixe que des valeurs par défaut : toute option donnée en ligne de commande
l'emporte. Seules les clés de la liste blanche sont acceptées ; --online en est exclu
exprès : l'accès réseau reste une décision explicite de l'analyste, à chaque lancement.

Exemple (forensic-analyzer.toml) :

    [defaults]
    organization = "CERT Exemple"
    examiner = "j.dupont"
    export_dir = "/srv/dfir/exports"
    log_json = "/var/log/forensic-analyzer/run.jsonl"
    quiet = true
"""

from __future__ import annotations

import os
import tomllib
from typing import Any

ENV_VAR = "FORENSIC_ANALYZER_CONFIG"  # chemin du fichier si --config est absent
MAX_CONFIG_BYTES = 1 << 20  # un fichier de configuration n'a aucune raison d'être plus gros

# Clé -> type attendu (noms des options, tirets ou soulignés acceptés)
ALLOWED: dict[str, type] = {
    "case_id": str,
    "examiner": str,
    "organization": str,
    "export_dir": str,
    "log_json": str,
    "quiet": bool,
    "yara": str,
    "mem_symbols": str,
    "evidence_dir": str,
}


class ConfigError(ValueError):
    """Fichier de configuration illisible ou invalide (message destiné à l'analyste)."""


def config_path(cli_value: str | None) -> str | None:
    return cli_value or os.environ.get(ENV_VAR) or None


def load_config(path: str) -> dict[str, Any]:
    """Valeurs par défaut de la section [defaults], validées ; ConfigError sinon."""
    try:
        if os.path.getsize(path) > MAX_CONFIG_BYTES:
            raise ConfigError(f"{path} : fichier de configuration trop volumineux")
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"{path} : lecture impossible ({exc.strerror or exc})") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} : TOML invalide ({exc})") from exc
    section = data.get("defaults", {})
    if not isinstance(section, dict):
        raise ConfigError(f"{path} : [defaults] doit être une table")
    return _validate(path, section)


def _validate(path: str, section: dict[str, Any]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for raw_key, value in section.items():
        key = raw_key.replace("-", "_")
        expected = ALLOWED.get(key)
        if expected is None:
            raise ConfigError(f"{path} : clé inconnue ou non autorisée « {raw_key} » (autorisées : {', '.join(sorted(ALLOWED))})")
        if not isinstance(value, expected):
            raise ConfigError(f"{path} : « {raw_key} » doit être de type {expected.__name__}")
        values[key] = value
    return values
