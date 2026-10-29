"""Intégration optionnelle de capa (Mandiant) : capacités d'un binaire et techniques ATT&CK."""
from __future__ import annotations

import json
import re
import shutil
import subprocess

from forensic_analyzer.utils.logger import get_logger

log = get_logger("capa")

_ATTACK_ID = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]")


def run_capa(path: str, timeout: int = 300) -> dict | None:
    """Capacités détectées par capa ({"capabilities": [...], "attack": [...]}), ou None si capa est absent."""
    capa = shutil.which("capa")
    if not capa:
        return None
    try:
        proc = subprocess.run([capa, "-j", "-q", path], capture_output=True, text=True, timeout=timeout)
        report = json.loads(proc.stdout)
    except subprocess.TimeoutExpired:
        log.warning("capa trop long sur '%s'", path)
        return None
    except json.JSONDecodeError:
        log.warning("Sortie capa illisible : %s", proc.stderr.strip()[:200])
        return None

    capabilities, attack = [], set()
    for name, rule in report.get("rules", {}).items():
        meta = rule.get("meta", {})
        if meta.get("lib") or meta.get("is_subscope_rule"):
            continue
        capabilities.append(name)
        for entry in meta.get("attack", []):
            ident = entry.get("id") or next(iter(_ATTACK_ID.findall(str(entry))), "")
            if ident:
                attack.add(ident)
    return {"capabilities": sorted(capabilities), "attack": sorted(attack)}
