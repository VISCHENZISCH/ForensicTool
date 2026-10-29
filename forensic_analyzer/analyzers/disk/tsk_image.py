"""Lecture directe d'une image disque via pytsk3 (The Sleuth Kit), sans montage ni tsk_recover.

Permet de parcourir les métadonnées (équivalent de `fls -m`), de hacher un fichier
dans l'image et d'extraire uniquement les artefacts utiles (triage) vers un dossier
de travail situé hors du dossier des preuves.
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import stat

from forensic_analyzer.analyzers.linux.bodyfile import BodyEntry
from forensic_analyzer.utils.logger import get_logger

log = get_logger("tsk_image")

try:
    import pytsk3
    HAS_PYTSK3 = True
except ImportError:
    pytsk3 = None
    HAS_PYTSK3 = False

SECTOR = 512
MAX_EXTRACT = 512 * 1024 * 1024
_SKIP_DIRS = {"$OrphanFiles", "$Extend", "System Volume Information"}


def local_path(dest_root: str, path: str) -> str | None:
    """Chemin local d'un fichier de l'image sous dest_root, None s'il en sortirait (`..`)."""
    root = os.path.realpath(dest_root)
    dest = os.path.realpath(os.path.join(root, path.lstrip("/")))
    return dest if dest.startswith(root + os.sep) else None

# Artefacts extraits pour le triage, par famille de système de fichiers
LINUX_TRIAGE = (
    "/etc/*", "/var/lib/dpkg/status", "/var/lib/dpkg/diversions", "/var/lib/dpkg/info/*",
    "/var/log/*", "/var/spool/cron/*",
    "/root/.*history", "/root/.ssh/*", "/root/.config/systemd/*",
    "/home/*/.*history", "/home/*/.ssh/*", "/home/*/.config/systemd/*",
    "/home/*/.mozilla/firefox/*/places.sqlite", "/home/*/.mozilla/firefox/*/cookies.sqlite",
    "/home/*/.config/google-chrome/*/History", "/home/*/.config/chromium/*/History",
)
WINDOWS_TRIAGE = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"^/windows/system32/winevt/logs/[^/]+\.evtx$",
    r"^/windows/system32/config/(system|software|sam|security)$",
    r"^/windows/appcompat/programs/amcache\.hve$",
    r"^/users/[^/]+/ntuser\.dat$",
    r"^/windows/prefetch/[^/]+\.pf$",
    r"^/users/[^/]+/appdata/roaming/microsoft/windows/recent/[^/]+\.lnk$",
    r"^/users/[^/]+/appdata/local/(google/chrome|microsoft/edge|bravesoftware/brave-browser)"
    r"/user data/[^/]+/(network/)?(history|cookies|login data|web data|bookmarks)$",
    r"^/users/[^/]+/appdata/roaming/mozilla/firefox/profiles/[^/]+/(places|cookies)\.sqlite$",
))


class ImageFS:
    """Un système de fichiers d'une image, ouvert par pytsk3."""

    def __init__(self, img, offset_sectors: int, label: str):
        self.fs = pytsk3.FS_Info(img, offset=offset_sectors * SECTOR)
        self.offset = offset_sectors
        self.label = label
        ftype = self.fs.info.ftype
        if ftype in (pytsk3.TSK_FS_TYPE_EXT2, pytsk3.TSK_FS_TYPE_EXT3, pytsk3.TSK_FS_TYPE_EXT4):
            self.family = "linux"
        elif ftype == pytsk3.TSK_FS_TYPE_NTFS:
            self.family = "windows"
        else:
            self.family = "other"

    def walk(self, max_depth: int = 64) -> list[BodyEntry]:
        """Métadonnées de toutes les entrées (équivalent de `fls -r -m /`)."""
        entries: list[BodyEntry] = []
        self._walk(self.fs.open_dir("/"), "", 0, max_depth, entries)
        return entries

    def _walk(self, directory, prefix, depth, max_depth, entries):
        for e in directory:
            name = e.info.name.name.decode("utf-8", "replace")
            if name in (".", "..") or e.info.meta is None:
                continue
            m = e.info.meta
            path = f"{prefix}/{name}"
            kind = {pytsk3.TSK_FS_META_TYPE_REG: "r", pytsk3.TSK_FS_META_TYPE_DIR: "d",
                    pytsk3.TSK_FS_META_TYPE_LNK: "l"}.get(m.type, "-")
            perms = stat.filemode(int(m.mode))[1:]
            link = m.link.decode("utf-8", "replace") if kind == "l" and m.link else ""
            entries.append(BodyEntry(
                path=path, inode=str(m.addr), mode=f"{kind}/{kind}{perms}", uid=int(m.uid), gid=int(m.gid),
                size=int(m.size), atime=int(m.atime), mtime=int(m.mtime), ctime=int(m.ctime),
                crtime=int(m.crtime), link_target=link,
                deleted=bool(int(e.info.name.flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC)),
            ))
            if kind == "d" and depth < max_depth and name not in _SKIP_DIRS:
                try:
                    self._walk(e.as_directory(), path, depth + 1, max_depth, entries)
                except OSError:
                    continue

    def _open(self, path: str):
        try:
            f = self.fs.open(path)
        except OSError:
            return None
        return f if f.info.meta is not None and f.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG else None

    def _chunks(self, f, limit: int):
        size = min(int(f.info.meta.size), limit)
        offset = 0
        while offset < size:
            block = f.read_random(offset, min(1 << 20, size - offset))
            if not block:
                break
            offset += len(block)
            yield block

    def md5(self, path: str) -> str | None:
        """MD5 d'un fichier de l'image (None s'il n'existe pas ou n'est pas un fichier)."""
        f = self._open(path)
        if f is None:
            return None
        h = hashlib.md5()
        for block in self._chunks(f, 1 << 40):
            h.update(block)
        return h.hexdigest()

    def extract(self, path: str, dest_root: str) -> str | None:
        """Copie un fichier de l'image sous dest_root (même chemin relatif)."""
        dest = local_path(dest_root, path)
        if dest is None:
            log.warning("Chemin hors du dossier d'extraction ignore : %s", path)
            return None
        f = self._open(path)
        if f is None:
            return None
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as out:
            for block in self._chunks(f, MAX_EXTRACT):
                out.write(block)
        # Dates d'origine : l'année des journaux syslog (sans année) s'en déduit
        try:
            os.utime(dest, (f.info.meta.atime, f.info.meta.mtime))
        except (OSError, OverflowError) as exc:
            log.debug("Dates d'origine non appliquées à %s : %s", dest, exc)
        return dest

    def triage(self, entries: list[BodyEntry], dest_root: str, extra_paths: set[str] = frozenset()) -> list[str]:
        """Extrait les artefacts du profil de triage correspondant au système de fichiers."""
        wanted = set(extra_paths)
        for e in entries:
            if not e.is_file or e.deleted:
                continue
            if self.family == "linux" and any(fnmatch.fnmatchcase(e.path, p) for p in LINUX_TRIAGE):
                wanted.add(e.path)
            elif self.family == "windows" and any(p.match(e.path) for p in WINDOWS_TRIAGE):
                wanted.add(e.path)
        extracted = []
        for path in sorted(wanted):
            dest = self.extract(path, dest_root)
            if dest:
                extracted.append(dest)
        return extracted


def open_filesystems(path: str) -> list[ImageFS]:
    """Systèmes de fichiers reconnus dans l'image (partitions, ou image d'un seul système)."""
    img = pytsk3.Img_Info(path)
    filesystems = []
    try:
        volume = pytsk3.Volume_Info(img)
        candidates = [(int(p.start), f"part@{int(p.start)}") for p in volume
                      if int(p.flags) & int(pytsk3.TSK_VS_PART_FLAG_ALLOC)]
    except OSError:
        candidates = [(0, "fs@0")]
    for start, label in candidates:
        try:
            filesystems.append(ImageFS(img, start, label))
        except OSError:
            continue  # partition sans système de fichiers reconnu (BIOS boot, swap...)
    return filesystems
