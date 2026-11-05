"""Constat transverse d'un chiffrement ou renommage de masse.

Aucun fichier `.locked` ne dit à lui seul ce qui s'est passé : le constat relie les fichiers
marqués, le journal d'audit (qui, d'où, quand), les copies saines, le manifeste qui les atteste
et les inventaires qui donnent l'enjeu métier. Il distingue ce qui est prouvé de ce qui ne l'est pas.
"""

from __future__ import annotations

import csv
import hashlib
import os
import re
from collections import Counter

from forensic_analyzer.analyzers.malware.entropy import calculate_entropy
from forensic_analyzer.core import mitre
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("ransomware")

MIN_MARKED_FILES = 3  # en dessous, une extension rare reste une coïncidence
_ENCRYPTED_ENTROPY = 7.5  # bits par octet
_READ_LIMIT = 1 << 20
_NOTE_LIMIT = 64 * 1024
_MAX_INVENTORY_ROWS = 10_000
_HEADLINE_KEYS = ("[ALERTE]", "[ATTENTION]", "Compte concerné", "Délai", "Dossiers", "Nature", "Source")
# Ni `.lock` (poetry.lock, Cargo.lock) : trop de fichiers légitimes
_KNOWN_EXTENSIONS = {
    ".locked",
    ".encrypted",
    ".enc",
    ".crypt",
    ".crypted",
    ".crypto",
    ".cry",
    ".locky",
    ".lockbit",
    ".ryk",
    ".conti",
    ".akira",
    ".wannacry",
    ".wncry",
    ".cerber",
}
# Seconde extension inconnue après celle d'un document : `budget.xlsx.xyz`
_DOCUMENT_EXTENSIONS = {
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".pdf",
    ".csv",
    ".txt",
    ".jpg",
    ".png",
    ".sql",
    ".zip",
}
_BENIGN_SUFFIXES = {".gz", ".bz2", ".xz", ".zip", ".bak", ".old", ".orig", ".tmp", ".sig", ".asc", ".sha256", ".md5", ".1"}
_NOTE_NAME = re.compile(
    r"(?i)how[_ -]?to[_ -]?(decrypt|recover|restore)|decrypt[_ -]?(files|instructions)|restore[_ -]?files|ransom"
)
_MIN_NOTE_TERMS = 2  # un seul terme : un document qui parle de ransomware, pas une note
_NOTE_TERMS = re.compile(r"(?i)bitcoin|monero|\.onion|tor browser|decrypt|déchiffr|ransom|rançon|payment|paiement")


def _marked_files(paths: list[str], logged_extensions: set[str]) -> dict[str, str]:
    """Fichiers marqués → extension ajoutée, pour les extensions assez répandues parmi les preuves."""
    groups: dict[str, list[str]] = {}
    for path in paths:
        stem, extension = os.path.splitext(os.path.basename(path))
        extension = extension.lower()
        known = extension in _KNOWN_EXTENSIONS or extension in logged_extensions
        doubled = os.path.splitext(stem)[1].lower() in _DOCUMENT_EXTENSIONS and extension not in _BENIGN_SUFFIXES
        if known or doubled:
            groups.setdefault(extension, []).append(path)
    return {p: ext for ext, files in groups.items() if len(files) >= MIN_MARKED_FILES for p in files}


def _severity(marked: dict[str, str], masses: list[dict], logged_extensions: set[str]) -> str:
    """Le journal prouve le geste ; une extension connue le suggère ; une double extension n'est qu'une piste."""
    if masses:
        return "critique"
    return "élevé" if any(e in _KNOWN_EXTENSIONS or e in logged_extensions for e in marked.values()) else "moyen"


def _read_head(path: str, limit: int = _READ_LIMIT) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError as exc:
        log.debug("Lecture impossible de %s : %s", path, exc)
        return b""


def _content_verdict(marked: list[str]) -> str:
    """Chiffré, ou simple marqueur ? Un chiffrement réel ne donne jamais deux contenus identiques."""
    heads = [_read_head(p) for p in marked]
    if len(marked) > 1 and len({hashlib.sha256(h).digest() for h in heads}) == 1:
        preview = heads[0][:40].decode("utf-8", "replace").strip()
        return (
            f"{len(marked)} fichiers au contenu identique ({len(heads[0])} o, entropie "
            f"{calculate_entropy(heads[0]):.1f}), « {preview} » : marqueur de substitution, pas un chiffrement réel"
        )
    mean = sum(calculate_entropy(h) for h in heads) / len(heads)
    nature = "chiffrement probable" if mean >= _ENCRYPTED_ENTROPY else "contenu lisible ou faiblement encodé"
    return f"entropie moyenne {mean:.1f} bits/octet : {nature}"


def _clean_copies(marked: dict[str, str], paths: list[str]) -> dict[str, list[str]]:
    """Pour chaque fichier marqué, les copies sous son nom d'origine ailleurs parmi les preuves."""
    by_name: dict[str, list[str]] = {}
    for path in paths:
        if path not in marked:
            by_name.setdefault(os.path.basename(path), []).append(path)
    return {path: by_name.get(os.path.basename(path)[: -len(ext)], []) for path, ext in marked.items()}


def _attested_paths(findings: list[FindingModel]) -> set[str]:
    return {
        r["path"]
        for f in findings
        if f.type == "evidence_integrity"
        for r in f.extra.get("results", [])
        if r.get("status") == "OK"
    }


def _inventory_context(paths: list[str], names: set[str], labels: dict[str, str]) -> list[str]:
    """Lignes d'inventaire CSV dont la première colonne désigne un partage ou un poste de l'incident."""
    context = []
    for path in paths:
        if not path.lower().endswith(".csv"):
            continue
        try:
            with open(path, newline="", encoding="utf-8", errors="replace") as fh:
                reader = csv.DictReader(fh)
                first = (reader.fieldnames or [""])[0]
                for i, row in enumerate(reader):
                    if i >= _MAX_INVENTORY_ROWS:
                        break
                    if row.get(first) in names:
                        details = ", ".join(f"{k}={v}" for k, v in row.items() if k != first and k and v)
                        context.append(f"{row[first]} ({os.path.basename(labels.get(path, path))}) : {details}")
        except (OSError, csv.Error) as exc:
            log.debug("Inventaire illisible %s : %s", path, exc)
    return context


def _ransom_notes(paths: list[str], labels: dict[str, str]) -> list[str]:
    notes = []
    for path in paths:
        by_name = bool(_NOTE_NAME.search(os.path.basename(path)))
        head = _read_head(path, _NOTE_LIMIT) if os.path.getsize(path) <= _NOTE_LIMIT else b""
        if b"\0" in head:
            head = b""
        terms = {m.lower() for m in _NOTE_TERMS.findall(head.decode("utf-8", "replace"))}
        if by_name or len(terms) >= _MIN_NOTE_TERMS:
            notes.append(labels.get(path, path))
    return notes


def _folder_shares(marked: dict[str, str], paths: list[str], labels: dict[str, str]) -> list[str]:
    totals = Counter(os.path.dirname(labels.get(p, p)) for p in paths)
    hit = Counter(os.path.dirname(labels.get(p, p)) for p in marked)
    return [f"{folder or '.'} : {n}/{totals[folder]} fichier(s) marqué(s)" for folder, n in hit.most_common()]


def _log_vs_evidence(marked: dict[str, str], masses: list[dict], meta: dict, incomplete: list[str]) -> None:
    """Ce que le journal et les fichiers présents se confirment, et ce qui reste hors de portée."""
    if not masses:
        return
    logged = {name for m in masses for name in m["new_names"]}
    present = {os.path.basename(p) for p in marked}
    total = sum(m["total"] for m in masses)
    if present:
        confirmed = present & logged
        meta["Journal et fichiers"] = f"{len(confirmed)}/{len(present)} fichiers marqués ont leur renommage nominatif au journal"
        missing = sorted(present - logged)
        if missing:
            groups = [f"{a['path']} ({a['count']})" for m in masses for a in m["aggregated"]]
            where = f" ; à rapprocher de l'entrée groupée {', '.join(groups)}, sans détail par fichier" if groups else ""
            meta["Sans ligne nominative"] = ", ".join(missing) + where
    if total > len(present):
        incomplete.append(
            f"{total} renommages journalisés pour {len(present)} fichier(s) marqué(s) présent(s) : "
            f"les {total - len(present)} autres sont à constater sur le serveur de fichiers"
        )


def _recovery(marked: dict[str, str], paths: list[str], attested: set[str], labels: dict[str, str]) -> tuple[dict, list[str]]:
    """Copies saines, part attestée par un manifeste, et source de restauration à examiner en premier."""
    meta: dict[str, str] = {}
    incomplete: list[str] = []
    copies = _clean_copies(marked, paths)
    found = {p: c for p, c in copies.items() if c}
    if not found:
        if marked:
            meta["[ATTENTION] Copies saines"] = "aucune copie sous le nom d'origine parmi les preuves"
        return meta, incomplete
    meta["Copies sous le nom d'origine"] = f"{len(found)}/{len(marked)} fichiers marqués"
    folders = Counter(os.path.dirname(labels.get(c, c)) for cs in found.values() for c in cs)
    source = folders.most_common(1)[0][0]
    in_source = [c for cs in found.values() for c in cs if os.path.dirname(labels.get(c, c)) == source]
    proven = [c for c in in_source if c in attested]
    unproven = sorted(os.path.basename(c) for c in in_source if c not in attested)
    meta["Copies attestées par manifeste"] = f"{len(proven)}/{len(in_source)} dans {source or '.'}"
    meta["Source de restauration à valider"] = (
        f"{source or '.'} : {len(in_source)}/{len(marked)} fichiers, {len(proven)} attestés"
    )
    if unproven:
        meta["[ATTENTION] Copies non attestées"] = (
            ", ".join(unproven) + " : aucune empreinte attendue, à valider avant restauration"
        )
        incomplete.append(f"{len(unproven)} copie(s) sans empreinte attendue : {', '.join(unproven)}")
    return meta, incomplete


def assess_ransomware(
    paths: list[str], findings: list[FindingModel], labels: dict[str, str]
) -> tuple[FindingModel | None, set[str]]:
    """Retourne (constat ou None, fichiers marqués examinés)."""
    audits = [f for f in findings if f.type == "log_analysis" and f.extra.get("log_type") == "file_audit"]
    masses = [m for f in audits for m in f.extra["details"]["mass_renames"]]
    logged_extensions = {e for m in masses for e in m["extensions"]}
    existing = [p for p in paths if os.path.isfile(p)]
    marked = _marked_files(existing, logged_extensions)
    if not marked and not masses:
        return None, set()

    total = sum(m["total"] for m in masses)
    extensions = sorted(set(marked.values()) | logged_extensions)
    severity = _severity(marked, masses, logged_extensions)
    facts = ", ".join(
        part
        for part in (
            f"{len(marked)} fichier(s) marqué(s) {', '.join(extensions)} parmi les preuves" if marked else "",
            f"{total} renommage(s) au journal" if masses else "",
        )
        if part
    )
    meta: dict[str, str] = (
        {"[ATTENTION] Piste à confirmer": f"Doubles extensions inhabituelles : {facts}"}
        if severity == "moyen"
        else {"[ALERTE] Verdict": f"Chiffrement ou renommage de masse : {facts}"}
    )
    for m in masses:
        meta[f"Compte concerné : {m['user']}"] = (
            f"poste {m['host'] or '?'}, partage {', '.join(m['shares']) or '?'}, "
            f"{m['first'][11:19]} → {m['last'][11:19]} UTC ({m['seconds']} s)"
        )
    events = sorted((e for f in audits for e in f.extra.get("timeline_events", [])), key=lambda e: e["timestamp"])
    first_rename = next((e for e in events if e["event_type"] in ("rename", "mass_rename")), None)
    first_response = next((e for e in events if e["event_type"] == "containment"), None)
    if first_rename and first_response and first_response["timestamp"] > first_rename["timestamp"]:
        meta["Délai avant confinement"] = (
            f"{first_rename['timestamp'][11:19]} → {first_response['timestamp'][11:19]} UTC (première action de réaction)"
        )

    incomplete: list[str] = []
    if marked:
        meta["Dossiers touchés"] = "\n".join(_folder_shares(marked, existing, labels))
        meta["Nature du contenu"] = _content_verdict(list(marked))
    _log_vs_evidence(marked, masses, meta, incomplete)
    recovery, gaps = _recovery(marked, existing, _attested_paths(findings), labels)
    meta.update(recovery)
    incomplete.extend(gaps)

    names = {s for m in masses for s in m["shares"]} | {m["host"] for m in masses if m["host"]}
    context = _inventory_context(existing, names, labels)
    if context:
        meta["Enjeu (inventaires)"] = "\n".join(context)
    notes = _ransom_notes(existing, labels)
    meta["Note de rançon possible"] = ", ".join(notes[:5]) if notes else "aucune parmi les preuves"

    headline = [k for k in meta if k.startswith(_HEADLINE_KEYS)]
    return (
        FindingModel(
            type="ransomware_impact",
            file="multi-source",
            metadata=meta,
            extra={
                "mitre": mitre.describe(["T1486"]) if severity != "moyen" else [],
                "marked_files": sorted(labels.get(p, p) for p in marked),
                "headline": headline,
                "chronology": events,
            },
            severity=severity,
            incomplete=incomplete,
        ),
        set(marked),
    )
