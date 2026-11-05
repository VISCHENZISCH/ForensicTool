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
    les preuves) refuse en plus les chemins qui sortent du dossier. `locate_in_evidence` traite
    ensuite, pour un scan, le manifeste rangé à l'écart des fichiers qu'il décrit.
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
            results.append(
                {**entry, "actual": actual, "size": os.path.getsize(path), "status": "OK" if actual == expected else "DIFFÉRENT"}
            )
    return {
        "manifest": os.path.abspath(manifest),
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "results": results,
        "all_ok": bool(results) and all(r["status"] == "OK" for r in results),
    }


def locate_in_evidence(res: dict, files: list[str], labels: dict[str, str] | None = None) -> bool:
    """
    Retrouve parmi les preuves du scan la racine d'un manifeste dont les chemins ne partent pas de son dossier.

    Une racine n'est retenue que si au moins une empreinte y correspond : une empreinte identique
    prouve le contenu, où qu'il soit. Sans cela, un homonyme reste une simple piste et l'entrée
    reste absente, sinon un fichier sans rapport passerait pour une preuve altérée.
    """
    absent = [r for r in res["results"] if r["status"] == "ABSENT" and not os.path.isabs(r["file"])]
    trees = _candidate_trees(absent, files, res["manifest"])
    if not trees:
        return False
    expected = {r["file"]: r["expected"] for r in absent}

    def matches(root: str) -> int:
        return sum(digest == expected[name] for name, (_f, digest) in trees[root].items())

    root = max(sorted(trees), key=matches)
    if not matches(root):
        for entry in absent:
            found = next((t[entry["file"]][0] for t in trees.values() if entry["file"] in t), None)
            if found:
                entry["lookalike"] = found
        return False
    _apply_tree(absent, trees[root])
    _describe_root(res, root, files, labels or {})
    return True


def _candidate_trees(absent: list[dict], files: list[str], manifest: str) -> dict[str, dict[str, tuple[str, str]]]:
    """Racines possibles → {entrée du manifeste : (fichier au même chemin relatif, son empreinte)}."""
    trees: dict[str, dict[str, tuple[str, str]]] = {}
    for entry in absent:
        tail = os.sep + os.path.normpath(entry["file"])
        for f in files:
            if f.endswith(tail) and f != manifest:
                trees.setdefault(f[: -len(tail)], {})[entry["file"]] = (f, _digest(f, entry["algo"]))
    return trees


def _apply_tree(absent: list[dict], tree: dict[str, tuple[str, str]]) -> None:
    for entry in absent:
        if entry["file"] in tree:
            found, digest = tree[entry["file"]]
            entry.pop("lookalike", None)
            status = "OK" if digest == entry["expected"] else "DIFFÉRENT"
            entry.update(path=found, actual=digest, size=os.path.getsize(found), status=status)


def _describe_root(res: dict, root: str, files: list[str], labels: dict[str, str]) -> None:
    listed = {r["path"] for r in res["results"]} | {res["manifest"]}
    prefix = root + os.sep
    res["base"] = root
    res["base_label"] = _label(root, files, labels)
    res["uncovered"] = sorted(labels.get(f, f) for f in files if f.startswith(prefix) and f not in listed)
    res["all_ok"] = all(r["status"] == "OK" for r in res["results"])


def _label(root: str, files: list[str], labels: dict[str, str]) -> str:
    """Racine exprimée comme dans le reste du rapport (relative à l'archive ou au dossier scanné)."""
    for f in files:
        if f.startswith(root + os.sep) and f in labels:
            inner = f[len(root) + 1 :]
            return labels[f].removesuffix(inner).rstrip("/" + os.sep) or "."
    return root


def _lookalike(name: str, base: str, manifest_dir: str) -> str | None:
    """Fichier du même nom ailleurs : piste pour l'analyste, jamais vérifié à la place de la preuve."""
    for folder in (manifest_dir, os.path.dirname(base), os.getcwd(), base):
        for candidate in (os.path.join(folder, name), os.path.join(folder, os.path.basename(name))):
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
    return None
