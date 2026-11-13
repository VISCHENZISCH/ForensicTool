"""Exporteur NDJSON au format Elastic Common Schema (ECS 8.x) pour l'ingestion SIEM.

Une ligne JSON par document : un par constat (event.kind « alert » ou « event »), un par
événement de la chronologie consolidée, un par preuve empreintée et un par module en échec.
Les champs suivent ECS (@timestamp, event.*, file.hash.*, source.ip, user.name, threat.*,
rule.*, observer.*) ; le contexte propre à l'outil est rangé sous l'espace `forensic.*`,
comme ECS le recommande pour les champs personnalisés. Ingestion : Elastic (Filebeat ou
_bulk), Splunk (sourcetype _json), Microsoft Sentinel (table personnalisée JSON).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, UTC
from typing import Any

from forensic_analyzer.analyzers.timeline import build_timeline
from forensic_analyzer.analyzers.timeline.analyzer import align_pcap_clock
from forensic_analyzer.core import iocs
from forensic_analyzer.core.timeline import consolidate
from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.utils.exports import output_path as resolve_output
from forensic_analyzer.utils.logger import get_logger

log = get_logger("ecs_exporter")

ECS_VERSION = "8.17.0"
MODULE = "forensic_analyzer"
MAX_TEXT = 1024  # borne la taille d'un document : une valeur tirée d'une preuve peut être énorme

# Gravité de l'outil -> event.severity (1..5) et event.risk_score (échelle Elastic Security)
_SEVERITY = {"info": 1, "faible": 2, "moyen": 3, "élevé": 4, "critique": 5}
_RISK = {"info": 0, "faible": 21, "moyen": 47, "élevé": 73, "critique": 99}

# Type de constat -> event.category (valeurs autorisées par ECS) ; « host » par défaut
_FINDING_CATEGORY = {
    "pcap": "network",
    "network_recon": "network",
    "ids_alerts": "intrusion_detection",
    "malware_analysis": "malware",
    "elf_analysis": "malware",
    "yara": "malware",
    "webshell_analysis": "malware",
    "log_analysis": "web",
    "registry": "registry",
    "memory": "process",
    "chromium_artifacts": "web",
    "firefox_places": "web",
    "firefox_cookies": "web",
    "correlation": "threat",
    "ioc": "threat",
}
_RELATED = {"ipv4": "ip", "sha256": "hash", "md5": "hash", "domain": "hosts"}
MAX_RELATED = 500  # pivots par document : au-delà, l'export JSON complet fait foi
_FILE_TYPES = (
    "pdf_analysis",
    "office_analysis",
    "image",
    "gps",
    "stego",
    "stego_audio",
    "carving",
    "strings",
    "disk",
    "evidence_integrity",
    "text_triage",
    "ransomware_impact",
)

# Source d'un événement de chronologie -> event.category
_TIMELINE_CATEGORY = {
    "auth.log": "authentication",
    "evtx": "host",
    "pcap": "network",
    "mft": "file",
    "filesystem": "file",
    "pdf": "file",
    "image_exif": "file",
    "bash_history": "process",
    "firefox": "web",
    "chromium": "web",
    "access.log": "web",
}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ts(value: Any) -> str | None:
    """Horodatage ISO 8601 UTC, ou None s'il n'est pas lisible (le document est alors écarté)."""
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)  # horodatages du rapport : UTC
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _text(value: Any) -> str:
    text = str(value)
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT] + "…"


def _clean(doc: dict) -> dict:
    """Retire les valeurs vides (un SIEM indexe mal les chaînes vides et les listes vides)."""
    out = {}
    for k, raw in doc.items():
        v = _clean(raw) if isinstance(raw, dict) else raw
        if v not in (None, "", [], {}):
            out[k] = v
    return out


def _category(finding_type: str) -> str:
    if finding_type in _FINDING_CATEGORY:
        return _FINDING_CATEGORY[finding_type]
    return "file" if finding_type in _FILE_TYPES else "host"


def _labels(report: ReportModel) -> dict:
    return {"case_id": report.case_id, "examiner": report.examiner, "organization": report.organization}


def _observer(report: ReportModel) -> dict:
    return {
        "hostname": report.analysis_host,
        "product": "Forensic Analyzer",
        "vendor": "Forensic Analyzer",
        "type": "forensic",
        "version": report.tool,
    }


def _techniques(finding: FindingModel) -> list[dict]:
    """extra["mitre"] : contrat describe() (dicts) ou ancienne forme (identifiants seuls)."""
    out = []
    for t in finding.extra.get("mitre") or []:
        if isinstance(t, dict) and t.get("id"):
            out.append(t)
        elif isinstance(t, str):
            out.append({"id": t})
    return out


def _threat(finding: FindingModel) -> dict:
    techniques = _techniques(finding)
    if not techniques:
        return {}
    tactics = sorted({t["tactic"] for t in techniques if t.get("tactic")})
    return {
        "framework": "MITRE ATT&CK",
        "technique": {
            "id": [t["id"] for t in techniques],
            "name": [t.get("name") for t in techniques if t.get("name")],
            "reference": [f"https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/" for t in techniques],
        },
        "tactic": {"name": tactics},
    }


def _labelled(finding: FindingModel, prefix: str) -> list[str]:
    return [
        f"{_text(str(k)[len(prefix) :].strip())} : {_text(v)}" for k, v in finding.metadata.items() if str(k).startswith(prefix)
    ]


def _file(path: str, metadata: dict, record=None) -> dict:
    return {
        "path": path,
        "name": os.path.basename(path) if path else None,
        "size": record.size if record else None,
        "hash": {
            "sha256": metadata.get("SHA-256") or (record.sha256 if record else None),
            "md5": metadata.get("MD5") or (record.md5 if record else None),
        },
    }


def _finding_file(finding: FindingModel, evidence: dict) -> dict:
    """Fichier analysé ; rien pour un constat transverse (« multi-source »), qui n'est pas un fichier."""
    if not finding.file or (os.sep not in finding.file and not finding.metadata.get("SHA-256")):
        return {}
    record = evidence.get(os.path.abspath(finding.file))
    return _file(finding.file, finding.metadata, record)


def _related(finding: FindingModel) -> dict:
    """related.* : pivots SIEM (IP, empreintes, domaines) tirés des indicateurs du constat."""
    out: dict[str, set] = {"ip": set(), "hash": set(), "hosts": set()}
    for k in ("SHA-256", "MD5"):
        if finding.metadata.get(k):
            out["hash"].add(str(finding.metadata[k]))
    try:
        observed = iocs.observations(finding)
    except Exception as exc:  # noqa: BLE001 - un extracteur en échec ne doit pas priver le SIEM du constat
        log.warning("Indicateurs illisibles pour %s : %s", finding.type, exc)
        observed = []
    for obs in observed:
        field = _RELATED.get(obs.kind)
        if field:
            out[field].add(obs.value)
    return {k: sorted(v)[:MAX_RELATED] for k, v in out.items()}


def finding_document(finding: FindingModel, report: ReportModel, evidence: dict) -> dict:
    alerts = _labelled(finding, "[ALERTE]")
    severity = finding.severity or "info"
    alerting = bool(alerts) or severity in ("moyen", "élevé", "critique")
    category = _category(finding.type)
    doc = {
        "@timestamp": _ts(report.finished_at or report.timestamp),
        "message": f"{finding.type} : " + ("; ".join(alerts) if alerts else os.path.basename(finding.file) or finding.file),
        "event": {
            "kind": "alert" if alerting else "event",
            "category": [category],
            "type": ["indicator"] if category == "threat" else ["info"],
            "module": MODULE,
            "dataset": f"{MODULE}.finding",
            "provider": finding.type,
            "severity": _SEVERITY.get(severity, 1),
            "risk_score": _RISK.get(severity, 0),
            "created": _now(),
        },
        "rule": {"name": finding.type, "ruleset": MODULE, "description": _text("; ".join(alerts))} if alerting else {},
        "threat": _threat(finding),
        "file": _finding_file(finding, evidence),
        "related": _related(finding),
        "forensic": {
            "severity": severity,
            "alerts": alerts,
            "to_check": _labelled(finding, "[ATTENTION]"),
            "incomplete": [_text(i) for i in finding.incomplete],
        },
    }
    return doc


def timeline_document(event: dict) -> dict | None:
    stamp = _ts(event.get("timestamp"))
    if stamp is None:
        return None
    source = str(event.get("source") or "")
    ip, user = event.get("ip"), event.get("user")
    return {
        "@timestamp": stamp,
        "message": _text(event.get("description") or event.get("event_type") or "événement"),
        "event": {
            "kind": "event",
            "category": [_TIMELINE_CATEGORY.get(source, "host")],
            "type": ["info"],
            "action": event.get("event_type"),
            "module": MODULE,
            "dataset": f"{MODULE}.timeline",
            "provider": source,
            "original": _text(event["details"]) if event.get("details") else None,
        },
        "source": {"ip": ip} if ip else {},
        "user": {"name": user} if user else {},
        "file": {"name": event.get("file")} if event.get("file") else {},
        "related": {"ip": [ip] if ip else [], "user": [user] if user else []},
        "forensic": {
            "confidence": event.get("confidence"),
            "corroborating_sources": event.get("corroborating_sources"),
            "original_timestamp": event.get("timestamp_origine"),
        },
    }


def evidence_document(record, report: ReportModel) -> dict:
    """Empreinte d'une preuve : traçabilité dans le SIEM (prise avant analyse, revérifiée après)."""
    return {
        "@timestamp": _ts(record.hashed_at),
        "message": f"Preuve empreintée : {record.file}"
        + (" (MODIFIÉE pendant l'analyse)" if record.changed_during_analysis else ""),
        "event": {
            "kind": "alert" if record.changed_during_analysis else "event",
            "category": ["file"],
            "type": ["change"] if record.changed_during_analysis else ["info"],
            "module": MODULE,
            "dataset": f"{MODULE}.evidence",
        },
        "file": _file(record.file, {}, record),
        "related": {"hash": [record.sha256, record.md5]},
        "forensic": {"evidence_origin": record.origin, "changed_during_analysis": record.changed_during_analysis},
    }


def error_document(error, report: ReportModel) -> dict:
    return {
        "@timestamp": _ts(report.finished_at or report.timestamp),
        "message": _text(str(error)),
        "event": {
            "kind": "event",
            "category": ["host"],
            "type": ["info"],
            "outcome": "failure",
            "module": MODULE,
            "dataset": f"{MODULE}.error",
            "provider": error.module,
        },
        "error": {"type": error.error, "message": _text(error.message)},
        "file": {"path": error.file},
    }


def _timeline_events(report: ReportModel) -> list[dict]:
    events = build_timeline(report)
    align_pcap_clock(events)  # même recalage que le rapport, le CSV et Timesketch
    for fact in consolidate(events):
        for e in fact["events"]:
            e["confidence"] = fact["confidence"]
            e["corroborating_sources"] = "+".join(fact["sources"])
    return events


def ecs_documents(report: ReportModel) -> list[dict]:
    """Tous les documents ECS du rapport, champs communs (ecs, observer, labels, tags) inclus."""
    evidence = {r.file: r for r in report.evidence}
    docs: list[dict | None] = [finding_document(f, report, evidence) for f in report.findings if f.type != "timeline"]
    docs += [timeline_document(e) for e in _timeline_events(report)]
    docs += [evidence_document(r, report) for r in report.evidence]
    docs += [error_document(e, report) for e in report.analysis_errors]
    common = {
        "ecs": {"version": ECS_VERSION},
        "observer": _observer(report),
        "labels": _labels(report),
        "tags": ["forensic-analyzer", *([report.case_id] if report.case_id else [])],
    }
    return [_clean({**doc, **common}) for doc in docs if doc and doc.get("@timestamp")]


class ECSExporter:
    """Constats, chronologie, preuves et échecs au format ECS, une ligne JSON par document."""

    def export(self, report: ReportModel, output_path: str) -> str:
        target_path = resolve_output(output_path)
        docs = ecs_documents(report)
        with open(target_path, "w", encoding="utf-8") as f:
            for doc in docs:
                f.write(json.dumps(doc, ensure_ascii=False, default=str) + "\n")
        log.info("Export ECS (NDJSON) -> %s (%d documents)", target_path, len(docs))
        return target_path
