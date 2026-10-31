"""Exporteur Timesketch - chronologie au format JSONL importable tel quel.

Une ligne JSON par événement, avec les trois champs exigés par Timesketch (message, datetime,
timestamp_desc), l'horodatage en microsecondes et le contexte DFIR (source, confiance,
sources concordantes, heure d'origine avant recalage d'horloge).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from forensic_analyzer.analyzers.timeline import build_timeline
from forensic_analyzer.analyzers.timeline.analyzer import align_pcap_clock
from forensic_analyzer.core.timeline import consolidate
from forensic_analyzer.models.finding import ReportModel
from forensic_analyzer.utils.exports import output_path as resolve_output
from forensic_analyzer.utils.logger import get_logger

log = get_logger("timesketch_exporter")

_CONTEXT = ("source", "event_type", "file", "ip", "user", "details", "confidence", "corroborating_sources", "timestamp_origine")


def _parse(value) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)  # horodatages du rapport : UTC


class TimesketchExporter:
    """Chronologie consolidée au format JSONL de Timesketch."""

    def export(self, report: ReportModel, output_path: str) -> str:
        target_path = resolve_output(output_path)
        events = build_timeline(report)
        align_pcap_clock(events)  # même recalage que le rapport et l'export CSV
        for fact in consolidate(events):
            for e in fact["events"]:
                e["confidence"] = fact["confidence"]
                e["corroborating_sources"] = "+".join(fact["sources"])
        written = skipped = 0
        with open(target_path, "w", encoding="utf-8") as f:
            for e in events:
                moment = _parse(e.get("timestamp"))
                if moment is None:
                    skipped += 1
                    continue
                line = {
                    "message": e.get("description") or e.get("event_type") or "événement",
                    "datetime": moment.isoformat(),
                    "timestamp": int(moment.timestamp() * 1_000_000),
                    "timestamp_desc": e.get("event_type") or "Événement",
                }
                line.update({k: e[k] for k in _CONTEXT if e.get(k) not in (None, "")})
                f.write(json.dumps(line, ensure_ascii=False, default=str) + "\n")
                written += 1
        log.info("Chronologie Timesketch exportée -> %s (%d événements, %d sans date lisible)", target_path, written, skipped)
        return target_path
