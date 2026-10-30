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

            if os.path.isabs(name):
                path = name
            else:
                candidate = os.path.join(base, name)
                if os.path.isfile(candidate):
                    path = candidate
                elif not confined:
                    cwd_candidate = os.path.join(os.getcwd(), name)
                    man_candidate = os.path.join(manifest_dir, name)
                    parent_candidate = os.path.join(os.path.dirname(base), name)
                    basename_candidate = os.path.join(base, os.path.basename(name))

                    if os.path.isfile(cwd_candidate):
                        path = cwd_candidate
                    elif os.path.isfile(man_candidate):
                        path = man_candidate
                    elif os.path.isfile(parent_candidate):
                        path = parent_candidate
                    elif os.path.isfile(basename_candidate):
                        path = basename_candidate
                    else:
                        path = candidate
                else:
                    path = candidate

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
