"""Archives trouvées parmi les preuves (.zip, .tar, .tar.gz...) : extraction sûre puis analyse du contenu.

L'archive vient de la preuve, donc potentiellement de l'attaquant : chemins absolus ou en `..`,
liens, fichiers spéciaux et bombes de décompression sont refusés. L'extraction se fait dans le
dossier de l'affaire, jamais à côté de la preuve, et un seul niveau est ouvert (pas de cascade).
"""
from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import zipfile

from forensic_analyzer.utils.exports import export_root
from forensic_analyzer.utils.logger import get_logger

log = get_logger("archives")

MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_MEMBERS = 10_000
_TAR_SUFFIXES = (".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")


def is_archive(path: str) -> bool:
    name = path.lower()
    if name.endswith(".zip"):
        return zipfile.is_zipfile(path)
    if name.endswith(_TAR_SUFFIXES):
        try:
            return tarfile.is_tarfile(path)
        except OSError:
            return False
    return False


def _safe_name(name: str) -> str | None:
    """Chemin relatif sûr, ou None (absolu, remontée, vide)."""
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or name.startswith(("/", "\\")) or ":" in parts[0] or ".." in parts:
        return None
    return os.path.join(*parts)


def _human(n: int) -> str:
    return f"{n / 1024 / 1024:.0f} Mo"


def extract_archive(path: str) -> tuple[list[str], str]:
    """Extrait l'archive ; retourne (fichiers extraits, note pour le rapport)."""
    base = os.path.basename(path)
    dest = os.path.realpath(_destination(path))
    if dest.startswith(os.path.realpath(os.path.dirname(path)) + os.sep):
        return [], f"{base} : non extraite (le dossier de sortie est dans le dossier des preuves)"
    try:
        if path.lower().endswith(".zip"):
            return _extract_zip(path, dest)
        return _extract_tar(path, dest)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
        shutil.rmtree(dest, ignore_errors=True)   # pas de contenu à moitié extrait laissé pour un autre scan
        log.warning("Archive illisible '%s' : %s", base, exc)
        return [], f"{base} : archive illisible ({exc})"


def _destination(path: str) -> str:
    """Dossier d'extraction propre à chaque archive : deux evidence.zip de dossiers différents ne s'écrasent pas."""
    tag = hashlib.sha256(os.path.abspath(path).encode()).hexdigest()[:8]
    return os.path.join(export_root(), "extractions", "archives", f"{os.path.basename(path)}-{tag}")


def _refusal(base: str, count: int, total: int, names: list[str]) -> str | None:
    if {"oci-layout", "manifest.json"} <= {os.path.basename(n) for n in names}:
        return f"{base} : image de conteneur (OCI / Docker) non extraite, {_human(total)} de couches système"
    if count > MAX_MEMBERS:
        return f"{base} : non extraite, {count} fichiers (limite {MAX_MEMBERS})"
    if total > MAX_TOTAL_BYTES:
        return f"{base} : non extraite, {_human(total)} décompressés (limite {_human(MAX_TOTAL_BYTES)})"
    return None


def _extract_tar(path: str, dest: str) -> tuple[list[str], str]:
    base = os.path.basename(path)
    with tarfile.open(path) as tar:
        members = [m for m in tar.getmembers() if m.isfile() and _safe_name(m.name)]
        refused = _refusal(base, len(members), sum(m.size for m in members), [m.name for m in tar.getmembers()])
        if refused:
            return [], refused
        skipped = len(tar.getmembers()) - len(members)
        files = []
        for m in members:
            target = os.path.join(dest, _safe_name(m.name))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tar.extractfile(m)
            if src is None:
                continue
            with src, open(target, "wb") as out:
                _copy_bounded(src, out, m.size)
            files.append(target)
    return files, _summary(base, len(files), skipped, dest)


def _extract_zip(path: str, dest: str) -> tuple[list[str], str]:
    base = os.path.basename(path)
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        # Ni répertoire ni lien symbolique (bits de type Unix dans external_attr)
        members = [i for i in infos if not i.is_dir() and _safe_name(i.filename)
                   and (i.external_attr >> 16) & 0o170000 in (0, 0o100000)]
        refused = _refusal(base, len(members), sum(i.file_size for i in members), [i.filename for i in infos])
        if refused:
            return [], refused
        skipped = sum(not i.is_dir() for i in infos) - len(members)
        files = []
        for info in members:
            target = os.path.join(dest, _safe_name(info.filename))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                _copy_bounded(src, out, info.file_size)
            files.append(target)
    return files, _summary(base, len(files), skipped, dest)


def _copy_bounded(src, out, declared: int) -> None:
    """Copie en refusant de dépasser la taille annoncée (en-tête mensonger = bombe de décompression)."""
    written = 0
    while chunk := src.read(1 << 20):
        written += len(chunk)
        if written > declared or written > MAX_TOTAL_BYTES:
            raise ValueError("taille décompressée supérieure à la taille annoncée")
        out.write(chunk)


def _summary(base: str, count: int, skipped: int, dest: str) -> str:
    note = f"{base} : {count} fichier(s) extrait(s) et analysé(s) dans {os.path.relpath(dest)}"
    return note + (f", {skipped} entrée(s) écartée(s) (lien, chemin dangereux ou spécial)" if skipped else "")


def expand_archives(targets: list[str]) -> tuple[list[str], dict[str, str], list[str]]:
    """
    Remplace chaque archive de la liste par son contenu extrait.
    Retourne (cibles, origine de chaque fichier extrait, notes pour le rapport).
    """
    expanded, origins, notes = [], {}, []
    for target in targets:
        if not is_archive(target):
            expanded.append(target)
            continue
        files, note = extract_archive(target)
        notes.append(note)
        root = _destination(target)
        for f in files:
            origins[f] = f"{os.path.basename(target)}:{os.path.relpath(f, os.path.realpath(root))}"
        expanded.extend(files)
        log.info("%s", note)
    return expanded, origins, notes

