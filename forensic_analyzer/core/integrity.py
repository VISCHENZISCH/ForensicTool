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


def verify_manifest(manifest: str, confined: bool = False, evidence_dir: str | None = None) -> dict:
    """
    Vérifie chaque ligne « empreinte  fichier » du manifeste.

    Un chemin relatif se résout depuis `evidence_dir`, sinon depuis le dossier du manifeste, et
    nulle part ailleurs : vérifier un homonyme trouvé ailleurs attesterait l'intégrité d'un autre
    fichier. Un homonyme est seulement signalé comme piste. `confined` (manifeste trouvé parmi
    les preuves) refuse en plus les chemins qui sortent du dossier.
    """
    manifest_dir = os.path.dirname(os.path.abspath(manifest))
    base = os.path.abspath(evidence_dir) if evidence_dir else manifest_dir
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
            entry = {"file": name, "path": os.path.abspath(path), "algo": algo, "expected": expected, "actual": ""}

            if confined and not os.path.realpath(path).startswith(real_base + os.sep):
                results.append({**entry, "status": "HORS PÉRIMÈTRE"})
                continue
            if not os.path.isfile(path):
                lookalike = _lookalike(name, base, manifest_dir)
                results.append({**entry, "status": "ABSENT", **({"lookalike": lookalike} if lookalike else {})})
                continue
            actual = _digest(path, algo)
            results.append({**entry, "actual": actual, "size": os.path.getsize(path),
                            "status": "OK" if actual == expected else "DIFFÉRENT"})
    return {
        "manifest": os.path.abspath(manifest),
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "results": results,
        "all_ok": bool(results) and all(r["status"] == "OK" for r in results),
    }


def _lookalike(name: str, base: str, manifest_dir: str) -> str | None:
    """Fichier du même nom ailleurs : piste pour l'analyste, jamais vérifié à la place de la preuve."""
    for folder in (manifest_dir, os.path.dirname(base), os.getcwd(), base):
        for candidate in (os.path.join(folder, name), os.path.join(folder, os.path.basename(name))):
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
    return None
