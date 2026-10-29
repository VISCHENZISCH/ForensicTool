"""Lecture d'un bodyfile TSK (`fls -r -m / -o OFFSET image`).

Une copie extraite par tsk_recover perd les propriétaires, transforme les liens
symboliques en fichiers ordinaires et prend les horodatages de l'extraction.
Le bodyfile conserve ces métadonnées telles qu'elles sont dans l'image.
"""
from __future__ import annotations

import datetime
import re
from dataclasses import dataclass

_DELETED_MARK = re.compile(r" \((?:deleted(?:-realloc)?|realloc)\)$")

# Répertoires système où un fichier n'appartenant pas à root est une anomalie
SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/boot/",
                   "/etc/systemd/", "/etc/cron", "/etc/init.d/", "/etc/profile.d/",
                   "/etc/sudoers", "/etc/pam.d/", "/etc/ld.so")
TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
# Emplacements où un fichier non déclaré par un paquet est suspect (hors fichiers générés : /boot, ld.so.cache...)
PACKAGE_PREFIXES = ("/usr/", "/etc/systemd/", "/etc/cron", "/etc/profile.d/", "/etc/pam.d/", "/etc/sudoers.d/")

# Fichiers cachés légitimes dans les répertoires système d'une Debian standard
_BENIGN_HIDDEN = (".placeholder", ".keep", ".gitkeep", ".build-id", ".hmac",
                  ".X11-unix", ".ICE-unix", ".XIM-unix", ".font-unix", ".Test-unix")


@dataclass(frozen=True)
class BodyEntry:
    path: str
    inode: str
    mode: str          # ex : r/rrw-r--r--, d/drwxr-xr-x, l/lrwxrwxrwx
    uid: int
    gid: int
    size: int
    atime: int
    mtime: int
    ctime: int
    crtime: int
    link_target: str = ""
    deleted: bool = False

    @property
    def kind(self) -> str:
        return self.mode[:1]

    @property
    def is_file(self) -> bool:
        return self.kind == "r"

    @property
    def is_link(self) -> bool:
        return self.kind == "l"


def utc(ts: int) -> str:
    """Horodatage epoch → ISO 8601 UTC ('' si absent)."""
    if not ts:
        return ""
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()


def parse_bodyfile(path: str) -> list[BodyEntry]:
    """Parse un fichier bodyfile TSK 3.x."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return parse_bodyfile_lines(f)


def parse_bodyfile_lines(lines) -> list[BodyEntry]:
    """Parse des lignes bodyfile : MD5|nom|inode|mode|UID|GID|taille|atime|mtime|ctime|crtime."""
    entries: list[BodyEntry] = []
    for line in lines:
        parts = line.rstrip("\n").split("|")
        if len(parts) < 11:
            continue
        # Le nom peut lui-même contenir '|' : tout ce qui précède les 9 derniers champs
        name = "|".join(parts[1:-9])
        inode, mode, uid, gid, size, at, mt, ct, cr = parts[-9:]
        # TSK marque les entrées supprimées : « (deleted) », « (deleted-realloc) », « (realloc) »
        name, n = _DELETED_MARK.subn("", name)
        deleted = n > 0
        target = ""
        if " -> " in name:
            name, target = name.split(" -> ", 1)
        try:
            entries.append(BodyEntry(
                path=name, inode=inode, mode=mode, uid=int(uid), gid=int(gid),
                size=int(size), atime=int(at), mtime=int(mt), ctime=int(ct),
                crtime=int(cr), link_target=target, deleted=deleted,
            ))
        except ValueError:
            continue
    return entries


def index_by_path(entries: list[BodyEntry]) -> dict[str, BodyEntry]:
    """Index chemin → entrée (les entrées allouées priment sur les supprimées)."""
    idx: dict[str, BodyEntry] = {}
    for e in entries:
        if e.path not in idx or idx[e.path].deleted:
            idx[e.path] = e
    return idx


def ownership_anomalies(entries: list[BodyEntry],
                        prefixes: tuple[str, ...] = SYSTEM_PREFIXES) -> list[BodyEntry]:
    """Fichiers système n'appartenant pas à root (certains répertoires, ex. polkit, sont légitimement délégués)."""
    return [e for e in entries
            if not e.deleted and e.is_file and e.uid != 0 and e.path.startswith(prefixes)]


def hidden_entries(entries: list[BodyEntry],
                   prefixes: tuple[str, ...] = SYSTEM_PREFIXES + TEMP_PREFIXES) -> list[BodyEntry]:
    """Fichiers dont le chemin contient un composant caché ('.xxx') sous un répertoire système ou temporaire."""
    found = []
    for e in entries:
        if e.deleted or not e.is_file or not e.path.startswith(prefixes):
            continue
        hidden = [c for c in e.path.split("/") if c.startswith(".") and c not in (".", "..")]
        if hidden and not all(c in _BENIGN_HIDDEN for c in hidden):
            found.append(e)
    return found
