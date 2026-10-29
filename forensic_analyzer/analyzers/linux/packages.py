"""Intégrité des paquets Debian hors ligne (équivalent de `dpkg -V`) et fichiers hors paquet.

Travaille sur une copie extraite (tsk_recover). Les chemins /bin, /sbin, /lib* sont
lus sous /usr (Debian 12 « merged-usr » : liens que tsk_recover ne restaure pas).
"""
from __future__ import annotations

import glob
import hashlib
import os
import re
from collections.abc import Callable

from forensic_analyzer.analyzers.linux.bodyfile import BodyEntry

_MERGED = ("bin/", "sbin/", "lib/", "lib32/", "lib64/", "libx32/")
_EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"

# Fichiers générés à l'installation, légitimement absents des listes dpkg
_GENERATED = re.compile(
    r"__pycache__|\.pyc$|^/usr/lib/modules/[^/]+/modules\.|^/etc/pam\.d/common-"
    r"|/hwdb\.bin$|^/usr/share/info/dir$"
)


def normalize(path: str) -> str:
    """Chemin merged-usr : /bin/ls → /usr/bin/ls."""
    stripped = path.lstrip("/")
    return "/usr/" + stripped if stripped.startswith(_MERGED) else "/" + stripped


def is_debian_root(root: str) -> bool:
    return os.path.isdir(os.path.join(root, "var/lib/dpkg/info"))


def _diversions(root: str) -> dict[str, tuple[str, str]]:
    """chemin détourné → (destination, paquet qui détourne)."""
    path = os.path.join(root, "var/lib/dpkg/diversions")
    if not os.path.isfile(path):
        return {}
    with open(path, errors="replace") as f:
        lines = f.read().split("\n")
    return {lines[i]: (lines[i + 1], lines[i + 2]) for i in range(0, len(lines) - 2, 3)}


def owned_paths(root: str) -> set[str]:
    """Tous les chemins déclarés par les paquets installés (normalisés merged-usr)."""
    owned: set[str] = set()
    for lst in glob.glob(os.path.join(root, "var/lib/dpkg/info/*.list")):
        with open(lst, errors="replace") as f:
            owned.update(normalize(line.rstrip("\n")) for line in f if line.startswith("/"))
    for src, (dest, _pkg) in _diversions(root).items():
        owned.update((normalize(src), normalize(dest)))
    return owned


def _md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _expected_hashes(root: str) -> list[tuple[str, str, str, bool]]:
    """(paquet, chemin, md5 attendu, conffile) depuis *.md5sums et les Conffiles de status."""
    entries = []
    for md5sums in glob.glob(os.path.join(root, "var/lib/dpkg/info/*.md5sums")):
        pkg = os.path.basename(md5sums)[:-len(".md5sums")]
        with open(md5sums, errors="replace") as f:
            for line in f:
                if "  " in line:
                    digest, p = line.rstrip("\n").split("  ", 1)
                    entries.append((pkg, "/" + p, digest, False))
    status = os.path.join(root, "var/lib/dpkg/status")
    if os.path.isfile(status):
        pkg = ""
        with open(status, errors="replace") as f:
            for line in f:
                if line.startswith("Package: "):
                    pkg = line.split()[1]
                m = re.match(r"^ (/\S+) ([0-9a-f]{32})( obsolete)?$", line)
                if m:
                    entries.append((pkg, m.group(1), m.group(2), True))
    return entries


def verify_dpkg(root: str, body_index: dict[str, BodyEntry] | None = None,
                hasher: Callable[[str], str | None] | None = None) -> dict:
    """
    Compare les MD5 des paquets aux fichiers de la copie.

    tsk_recover n'extrait pas les fichiers vides : un fichier absent de la copie mais
    de taille 0 dans le bodyfile est compté conforme si son MD5 attendu est celui du vide.
    `hasher(chemin)` permet de hacher directement dans l'image disque (None si absent).
    """
    diversions = _diversions(root)
    expected = _expected_hashes(root)
    modified, missing = [], []
    ok = 0
    for pkg, path, digest, conffile in expected:
        if path in diversions and diversions[path][1] != pkg.split(":")[0]:
            path = diversions[path][0]
        rel = normalize(path)
        if hasher is not None:
            actual = hasher(rel)
            if actual is None:
                body = body_index.get(rel) if body_index else None
                if digest == _EMPTY_MD5 and body is not None and body.size == 0:
                    ok += 1
                else:
                    missing.append({"path": path, "package": pkg, "conffile": conffile})
            elif actual == digest:
                ok += 1
            else:
                modified.append({"path": path, "package": pkg, "conffile": conffile})
            continue
        real = os.path.join(root, rel.lstrip("/"))
        if not os.path.isfile(real):
            body = body_index.get(rel) if body_index else None
            if digest == _EMPTY_MD5 and body is not None and body.size == 0:
                ok += 1
            else:
                missing.append({"path": path, "package": pkg, "conffile": conffile})
        elif (os.path.getsize(real) == 0 and digest == _EMPTY_MD5) or _md5(real) == digest:
            ok += 1
        else:
            modified.append({"path": path, "package": pkg, "conffile": conffile})
    return {
        "checked": len(expected),
        "conffiles": sum(1 for e in expected if e[3]),
        "ok": ok,
        "modified": modified,
        "missing": missing,
    }


def files_outside_packages(root: str, entries: list[BodyEntry],
                           prefixes: tuple[str, ...]) -> list[BodyEntry]:
    """Fichiers réguliers sous `prefixes` qu'aucun paquet ne déclare (hors fichiers générés)."""
    owned = owned_paths(root)
    return [e for e in entries
            if e.is_file and not e.deleted and e.path.startswith(prefixes)
            and normalize(e.path) not in owned and not _GENERATED.search(e.path)]
