"""Exporteur MISP - événement JSON (format MISP core) avec les indicateurs de l'analyse.

Fichier à importer dans MISP (« Add Event > Import from… > MISP JSON ») : rien n'est envoyé
par l'outil. Diffusion « organisation seulement » et TLP:AMBER par défaut, événement non
publié : le partage reste une décision de l'analyste dans MISP. Les UUID des attributs sont
dérivés de l'affaire et de la valeur, pour qu'un nouvel export de la même affaire fusionne
au lieu de dupliquer.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, UTC

from forensic_analyzer.core import iocs
from forensic_analyzer.models.finding import ReportModel, max_severity
from forensic_analyzer.utils.exports import output_path as resolve_output
from forensic_analyzer.utils.logger import get_logger

log = get_logger("misp_exporter")

_NAMESPACE = uuid.UUID("6f1c7d52-3b0e-4a8e-9c55-0a3f0e7d2b11")  # espace propre à l'outil (uuid5)
MAX_COMMENT = 255

# Type d'indicateur de l'outil -> (type MISP, catégorie MISP, to_ids)
_ATTRIBUTE = {
    "ipv4": ("ip-dst", "Network activity", True),
    "domain": ("domain", "Network activity", True),
    "url": ("url", "Network activity", True),
    "sha256": ("sha256", "Payload delivery", True),
    "md5": ("md5", "Payload delivery", True),
    "ja3": ("ja3-fingerprint-md5", "Network activity", True),
    "path": ("filename", "Artifacts dropped", False),
    "filename": ("filename", "Artifacts dropped", False),
}
# Sources où une IP est l'attaquant (client du serveur web, auteur des connexions)
_ATTACKER_SOURCES = {"log_analysis", "webshell_analysis", "evtx", "linux_artifacts"}
# Gravité maximale -> threat_level_id MISP (1 élevé, 2 moyen, 3 faible, 4 non défini)
_THREAT_LEVEL = {"critique": "1", "élevé": "1", "moyen": "2", "faible": "3"}
_DISTRIBUTION_ORG_ONLY = "0"
_ANALYSIS_ONGOING = "1"


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, "|".join(parts)))


def _attribute(ioc: iocs.IOC, case: str, stamp: str) -> dict | None:
    mapping = _ATTRIBUTE.get(ioc.kind)
    if mapping is None:
        return None
    misp_type, category, to_ids = mapping
    if misp_type == "ip-dst" and {o.source for o in ioc.observations} & _ATTACKER_SOURCES:
        misp_type = "ip-src"  # IP vue comme origine des requêtes ou des connexions
    contexts = sorted({f"{o.source}: {o.context or o.artifact}" for o in ioc.observations})
    comment = "; ".join(contexts)
    return {
        "uuid": _uuid(case, misp_type, ioc.value),
        "type": misp_type,
        "category": category,
        "value": ioc.value,
        "to_ids": to_ids,
        "distribution": "5",  # hérite de l'événement
        "timestamp": stamp,
        "comment": comment[: MAX_COMMENT - 1] + "…" if len(comment) > MAX_COMMENT else comment,
    }


def _mitre_tags(report: ReportModel) -> list[dict]:
    names = set()
    for f in report.findings:
        for t in f.extra.get("mitre") or []:
            if isinstance(t, dict) and t.get("id") and t.get("name"):
                names.add(f'misp-galaxy:mitre-attack-pattern="{t["name"]} - {t["id"]}"')
    return [{"name": n} for n in sorted(names)]


def misp_event(report: ReportModel) -> dict:
    """Événement MISP {"Event": {...}} construit à partir des IOC du rapport."""
    case = report.case_id or report.timestamp
    now = datetime.now(UTC)
    stamp = str(int(now.timestamp()))
    attributes = [a for a in (_attribute(i, case, stamp) for i in iocs.collect(report)) if a]
    severity = max_severity(*(f.severity for f in report.findings))
    info = f"Forensic Analyzer - affaire {report.case_id}" if report.case_id else "Forensic Analyzer - analyse"
    if report.organization:
        info += f" ({report.organization})"
    return {
        "Event": {
            "uuid": _uuid("event", case),
            "info": info,
            "date": (report.started_at or report.timestamp)[:10],
            "timestamp": stamp,
            "threat_level_id": _THREAT_LEVEL.get(severity or "", "4"),
            "analysis": _ANALYSIS_ONGOING,
            "distribution": _DISTRIBUTION_ORG_ONLY,
            "published": False,
            "Tag": [{"name": "tlp:amber"}, *_mitre_tags(report)],
            "Attribute": attributes,
        }
    }


class MISPExporter:
    """Écrit l'événement MISP dans un fichier JSON, sans aucun envoi réseau."""

    def export(self, report: ReportModel, output_path: str) -> str:
        target_path = resolve_output(output_path)
        event = misp_event(report)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(event, f, indent=2, ensure_ascii=False)
        log.info("Événement MISP exporté -> %s (%d attributs)", target_path, len(event["Event"]["Attribute"]))
        return target_path
