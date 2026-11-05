"""Lecture des fichiers texte qu'aucun module n'a pris en charge (notes, inventaires, scripts).

Un ticket ou un script écarté en silence peut porter l'essentiel d'une affaire. Cette lecture ne
remplace pas une analyse dédiée : elle dit ce que sont ces fichiers, relève les indicateurs cités
et les opérations sensibles des scripts, et le rapport précise cette limite.
"""

from __future__ import annotations

import csv
import io
import os
import re

from forensic_analyzer.core.iocs import text_indicators
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("triage")

_MAX_BYTES = 2 * 1024 * 1024
_MAX_LISTED_INDICATORS = 20
_SCRIPT_EXT = {".py", ".sh", ".bash", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".pl", ".rb", ".php"}
_TABLE_EXT = {".csv", ".tsv"}
_SENSITIVE = re.compile(
    r"(?i)\b(subprocess|os\.system|os\.popen|eval\(|exec\(|invoke-expression|iex\b|invoke-webrequest|downloadstring|"
    r"-enc(?:odedcommand)?\b|vssadmin|wbadmin|bcdedit|shadowcopy|cipher\s+/w|rm\s+-rf|shutil\.rmtree|os\.remove|os\.unlink|"
    r"socket\.|urllib\.request|requests\.(?:get|post)|curl\s|wget\s|base64\s+-d|nc\s+-e|chmod\s+\+x)"
)


def _read_text(path: str) -> str | None:
    """Contenu d'un fichier texte, ou None (binaire, trop gros, illisible)."""
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        log.debug("Lecture impossible de %s : %s", path, exc)
        return None
    return None if b"\0" in data else data.decode("utf-8", "replace")


def _describe_table(name: str, text: str) -> str:
    delimiter = "\t" if name.lower().endswith(".tsv") else ","
    try:
        rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
    except csv.Error:
        return f"{name} : tableau illisible"
    rows = [r for r in rows if r]
    if not rows:
        return f"{name} : vide"
    return f"{name} : {len(rows) - 1} ligne(s), colonnes {', '.join(rows[0])}"


def _describe_document(name: str, text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    title = next((line.lstrip("# ") for line in lines if line.startswith("#")), "")
    return f"{name} : {len(lines)} ligne(s)" + (f", « {title[:60]} »" if title else "")


def _sensitive_operations(text: str) -> str:
    return ", ".join(sorted({m.group(1).lower() for m in _SENSITIVE.finditer(text)}))


def _triage_metadata(sections: dict[str, list[str]], sensitive: dict[str, str], indicators: dict[str, list[str]]) -> dict:
    meta: dict[str, str] = {}
    for title, items in sections.items():
        if items:
            meta[f"{title} ({len(items)})"] = "\n".join(sorted(items))
    for label, hits in sensitive.items():
        meta[f"[ATTENTION] Script {os.path.basename(label)}"] = hits
    for label, cited in indicators.items():
        meta[f"Cité par {os.path.basename(label)}"] = ", ".join(cited)
    return meta


def triage_text_files(
    paths: list[str], findings: list[FindingModel], labels: dict[str, str], exclude: set[str]
) -> tuple[FindingModel | None, set[str]]:
    """Retourne (constat de lecture ou None, fichiers lus)."""
    covered = {f.file for f in findings} | exclude
    sections: dict[str, list[str]] = {"Documents": [], "Tableaux": [], "Scripts": []}
    sensitive: dict[str, str] = {}
    indicators: dict[str, list[str]] = {}
    read: set[str] = set()

    for path in paths:
        text = None if path in covered or not os.path.isfile(path) else _read_text(path)
        if text is None:
            continue
        read.add(path)
        label = labels.get(path, os.path.basename(path))
        extension = os.path.splitext(path)[1].lower()
        if extension in _TABLE_EXT:
            sections["Tableaux"].append(_describe_table(label, text))
        elif extension in _SCRIPT_EXT:
            hits = _sensitive_operations(text)
            verdict = "opérations sensibles" if hits else "aucune opération sensible"
            sections["Scripts"].append(f"{label} : {len(text.splitlines())} ligne(s), {verdict}")
            if hits:
                sensitive[label] = hits
        else:
            sections["Documents"].append(_describe_document(label, text))
        cited = text_indicators(text)
        if cited:
            indicators[label] = cited[:_MAX_LISTED_INDICATORS]

    if not read:
        return None, set()
    return (
        FindingModel(
            type="text_triage",
            file="multi-source",
            metadata=_triage_metadata(sections, sensitive, indicators),
            extra={"files": sorted(labels.get(p, p) for p in read), "indicators": indicators},
            severity="moyen" if sensitive else "info",
            incomplete=[f"{len(read)} fichier(s) lus en simple texte, sans module dédié : à lire par l'analyste"],
        ),
        read,
    )
