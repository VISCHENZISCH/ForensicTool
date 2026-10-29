"""Vérification d'un manifeste d'empreintes (équivalent de `sha256sum -c`)."""
from __future__ import annotations

import datetime
import hashlib
import os
import re

_LINE = re.compile(r"^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})\s+\*?(.+)$")
_ALGOS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


def _digest(path: str, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def verify_manifest(manifest: str, confined: bool = False) -> dict:
    """
    Vérifie chaque ligne « empreinte  fichier » du manifeste.

    Les chemins relatifs sont résolus depuis le dossier du manifeste ; l'algorithme
    est déduit de la longueur de l'empreinte. `confined` : manifeste trouvé parmi les
    preuves (donc non fiable), limité aux fichiers de son dossier ; sinon il pourrait faire
    hacher n'importe quel fichier de l'analyste (~/.ssh/id_rsa...) et en révéler l'empreinte.
    """
    base = os.path.dirname(os.path.abspath(manifest))
    real_base = os.path.realpath(base)
    results = []
    with open(manifest, errors="replace") as f:
        for line in f:
            m = _LINE.match(line.strip())
            if not m:
                continue
            expected, name = m.group(1).lower(), m.group(2)
            algo = _ALGOS[len(expected)]
            path = name if os.path.isabs(name) else os.path.join(base, name)
            if confined and not os.path.realpath(path).startswith(real_base + os.sep):
                results.append({"file": name, "algo": algo, "expected": expected, "actual": "",
                                "status": "HORS PÉRIMÈTRE"})
                continue
            if not os.path.isfile(path):
                results.append({"file": name, "algo": algo, "expected": expected, "actual": "", "status": "ABSENT"})
                continue
            actual = _digest(path, algo)
            results.append({"file": name, "algo": algo, "expected": expected, "actual": actual,
                            "size": os.path.getsize(path),
                            "status": "OK" if actual == expected else "DIFFÉRENT"})
    return {
        "manifest": os.path.abspath(manifest),
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "results": results,
        "all_ok": bool(results) and all(r["status"] == "OK" for r in results),
    }
