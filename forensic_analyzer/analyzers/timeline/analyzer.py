"""Analyzer Timeline - correlation multi-sources et export DFIR."""
from __future__ import annotations

import csv
import datetime
import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("timeline")


def _normalize_timestamp(ts: str) -> str:
    """Tente de normaliser un timestamp en ISO 8601."""
    if not ts or ts == "N/A":
        return ""
    # Deja ISO
    if "T" in ts:
        return ts
    # Formats courants
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%b %d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            dt = datetime.datetime.strptime(ts, fmt)
            return dt.isoformat()
        except ValueError:
            continue
    return ts


def build_timeline(report: ReportModel) -> list[dict]:
    """
    Construit une timeline unifiee a partir de tous les findings du rapport.
    Correle les timestamps de toutes les sources.
    """
    events: list[dict] = []

    for finding in report.findings:
        source = finding.type
        file = os.path.basename(finding.file)

        # PDF timestamps
        if source == "pdf":
            for key in ("CreationDate", "ModDate"):
                ts = finding.metadata.get(key, "")
                if ts:
                    events.append({
                        "timestamp": _normalize_timestamp(ts),
                        "source": "pdf",
                        "event_type": key,
                        "description": f"PDF {key}: {file}",
                        "file": file,
                        "details": ts,
                    })

        # Image EXIF timestamps
        elif source == "image":
            for key in ("DateTime", "DateTimeOriginal", "DateTimeDigitized"):
                ts = finding.metadata.get(key, "")
                if ts:
                    events.append({
                        "timestamp": _normalize_timestamp(ts),
                        "source": "image_exif",
                        "event_type": key,
                        "description": f"Image {key}: {file}",
                        "file": file,
                        "details": ts,
                    })

        # Disk / MFT timestamps
        elif source == "disk":
            for rec in finding.extra.get("mft_records", []):
                timestamps = rec.get("timestamps", {})
                fname = rec.get("filename", "?")
                for ts_type, ts_val in timestamps.items():
                    if ts_val and ts_val != "N/A":
                        events.append({
                            "timestamp": _normalize_timestamp(ts_val),
                            "source": "mft",
                            "event_type": ts_type,
                            "description": f"MFT {ts_type}: {fname}",
                            "file": fname,
                            "details": f"{'SUPPRIME' if not rec.get('in_use') else 'actif'}",
                        })

        # EVTX events
        elif source == "evtx":
            for evt in finding.extra.get("security_events", []):
                ts = evt.get("timestamp", "")
                events.append({
                    "timestamp": _normalize_timestamp(ts),
                    "source": "evtx",
                    "event_type": f"EventID {evt.get('event_id', '?')}",
                    "description": evt.get("description", "") or f"EventID {evt.get('event_id', '?')}",
                    "file": file,
                    "details": str(evt.get("data", {}))[:200],
                })

        # Firefox history
        elif source == "firefox_history":
            for entry in finding.extra.get("entries", []):
                ts = entry.get("date", "")
                events.append({
                    "timestamp": _normalize_timestamp(ts),
                    "source": "firefox",
                    "event_type": "navigation",
                    "description": f"Visite: {entry.get('url', '?')[:100]}",
                    "file": file,
                    "details": entry.get("url", ""),
                })

        # Linux auth.log
        elif source == "linux_artifacts":
            auth = finding.extra.get("auth_log", {})
            for entry in auth.get("failed_details", []):
                events.append({
                    "timestamp": _normalize_timestamp(entry.get("timestamp", "")),
                    "source": "auth.log",
                    "event_type": "login_failed",
                    "description": f"Echec SSH: {entry.get('user', '?')} depuis {entry.get('source_ip', '?')}",
                    "file": file,
                    "details": str(entry),
                })
            for entry in auth.get("success_details", []):
                events.append({
                    "timestamp": _normalize_timestamp(entry.get("timestamp", "")),
                    "source": "auth.log",
                    "event_type": "login_success",
                    "description": f"Connexion SSH: {entry.get('user', '?')} depuis {entry.get('source_ip', '?')}",
                    "file": file,
                    "details": str(entry),
                })

        # Chromium history & downloads
        elif source == "chromium_artifacts":
            for url in finding.extra.get("chromium_urls", []):
                ts = url.get("derniere_visite", "")
                if ts:
                    events.append({
                        "timestamp": _normalize_timestamp(ts),
                        "source": "chromium",
                        "event_type": "navigation",
                        "description": f"Visite: {url.get('url', '?')[:100]}",
                        "file": file,
                        "details": url.get("titre", ""),
                    })
            for dl in finding.extra.get("chromium_downloads", []):
                ts = dl.get("debut", "")
                if ts:
                    events.append({
                        "timestamp": _normalize_timestamp(ts),
                        "source": "chromium",
                        "event_type": "download",
                        "description": f"Téléchargement: {dl.get('fichier', '?')}",
                        "file": file,
                        "details": f"URL: {dl.get('url', '?')}",
                    })

        # Windows Execution
        elif source in ("prefetch", "lnk_shortcut"):
            ts = finding.metadata.get("Dernière Exécution", "") or finding.metadata.get("Creation", "")
            if ts:
                events.append({
                    "timestamp": _normalize_timestamp(ts),
                    "source": source,
                    "event_type": "execution",
                    "description": f"Exécution: {finding.metadata.get('Nom supposé', file)}",
                    "file": file,
                    "details": str(finding.metadata),
                })

        # PCAP
        elif source == "pcap":
            for cred in finding.extra.get("credentials", []):
                events.append({
                    "timestamp": "",
                    "source": "pcap",
                    "event_type": "credential_found",
                    "description": f"[{cred.get('protocol','?')}] {cred.get('username','?')}",
                    "file": file,
                    "details": str(cred),
                })

    # Trier par timestamp
    events.sort(key=lambda e: e.get("timestamp", ""))
    return events


def export_timeline_csv(events: list[dict], output_path: str) -> None:
    """Exporte la timeline en CSV compatible Plaso/DFIR."""
    fieldnames = ["timestamp", "source", "event_type", "description", "file", "details"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)
    log.info("Timeline CSV exportee -> %s (%d evenements)", output_path, len(events))


class TimelineAnalyzer(BaseAnalyzer):
    """Construit une timeline forensique unifiee multi-sources."""
    name = "timeline"
    supported_extensions = ()

    def can_handle(self, path: str) -> bool:
        return False

    def analyze(self, path: str) -> FindingModel | None:
        return None

    def build_from_report(self, report: ReportModel) -> FindingModel:
        """Construit la timeline depuis un ReportModel existant."""
        events = build_timeline(report)

        # Stats
        sources = {}
        for e in events:
            src = e.get("source", "unknown")
            sources[src] = sources.get(src, 0) + 1

        meta: dict = {
            "Total evenements": str(len(events)),
        }
        for src, count in sorted(sources.items(), key=lambda x: -x[1]):
            meta[f"Source: {src}"] = str(count)

        if events:
            meta["Premier evenement"] = events[0].get("timestamp", "?")
            meta["Dernier evenement"] = events[-1].get("timestamp", "?")

        return FindingModel(
            type="timeline",
            file="multi-source",
            metadata=meta,
            extra={"events": events[:2000], "source_stats": sources},
        )
