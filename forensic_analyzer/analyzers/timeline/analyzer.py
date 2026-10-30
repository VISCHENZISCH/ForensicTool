"""Analyzer Timeline - corrélation multi-sources et export DFIR."""
from __future__ import annotations

import datetime
import os
import re

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.core.timeline import consolidate, parse_ts
from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("timeline")


def _normalize_timestamp(ts) -> str:
    """Tente de normaliser un timestamp en ISO 8601 (chaîne, ou datetime fourni par LnkParse3)."""
    if isinstance(ts, datetime.datetime):
        return ts.isoformat()
    if not ts or ts == "N/A":
        return ""
    ts = str(ts)
    if "T" in ts:
        return ts
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
    Construit une timeline unifiée à partir de tous les findings du rapport.
    Corrélé les timestamps de toutes les sources.
    """
    events: list[dict] = []

    for finding in report.findings:
        source = finding.type
        file = os.path.basename(finding.file)

        # Événements déjà normalises par l'analyzer (Linux, mémoire, ...)
        events.extend(finding.extra.get("timeline_events", []))

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

        # Linux auth.log, sudo, et bash_history
        elif source == "linux_artifacts":
            auth = finding.extra.get("auth_log", {})
            for entry in auth.get("failed_details", []):
                events.append({
                    "timestamp": _normalize_timestamp(entry.get("timestamp", "")),
                    "source": "auth.log",
                    "event_type": "login_failed",
                    "description": f"Échec SSH: {entry.get('user', '?')} depuis {entry.get('source_ip', '?')}",
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
            for entry in auth.get("sudo_details", []):
                events.append({
                    "timestamp": _normalize_timestamp(entry.get("timestamp", "")),
                    "source": "auth.log",
                    "event_type": "sudo",
                    "description": f"Commande SUDO par {entry.get('user', '?')} : {entry.get('command', '?')[:80]}",
                    "file": file,
                    "details": str(entry),
                })
            bh = finding.extra.get("bash_history")
            histories = finding.extra.get("bash_histories", {})
            all_bh = ([bh] if bh else []) + list(histories.values())
            for h in all_bh:
                if not h: continue
                for cmd_str in h.get("commands", []):
                    if cmd_str.startswith("[") and "]" in cmd_str:
                        ts_part, real_cmd = cmd_str[1:].split("]", 1)
                        events.append({
                            "timestamp": _normalize_timestamp(ts_part.strip()),
                            "source": "bash_history",
                            "event_type": "bash_command",
                            "description": f"Commande bash : {real_cmd.strip()[:80]}",
                            "file": file,
                            "details": real_cmd.strip(),
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
                ts = dl.get("date", "")
                if ts:
                    events.append({
                        "timestamp": _normalize_timestamp(ts),
                        "source": "chromium",
                        "event_type": "download",
                        "description": f"Téléchargement: {dl.get('fichier', '?')}",
                        "file": file,
                        "details": f"URL: {dl.get('url', '?')}",
                    })

        # Windows Exécution
        elif source in ("prefetch", "lnk_shortcut"):
            ts = finding.metadata.get("Dernière Exécution", "") or finding.metadata.get("Date Création (LNK)", "")
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
            for step in finding.extra.get("timeline", []):
                events.append({
                    "timestamp": step.get("time", ""),
                    "source": "pcap",
                    "event_type": step.get("type", ""),
                    "description": step.get("desc", ""),
                    "file": file,
                    "details": "",
                })
            # Seuls les identifiants datés (ceux qui ont fonctionné) : un mot de passe essayé
            # pendant un brute-force n'est pas un événement
            for cred in (c for c in finding.extra.get("credentials", []) if c.get("time")):
                events.append({
                    "timestamp": datetime.datetime.fromtimestamp(cred["time"], datetime.timezone.utc).isoformat(),
                    "source": "pcap",
                    "event_type": "credential_found",
                    "description": f"[{cred.get('protocol','?')}] {cred.get('username','?')}",
                    "file": file,
                    "details": str(cred),
                })

        if finding.file and os.path.isfile(finding.file) and source not in ("timeline", "scan_summary", "evidence_integrity"):
            try:
                mtime = os.path.getmtime(finding.file)
                mtime_iso = datetime.datetime.fromtimestamp(mtime, datetime.timezone.utc).isoformat()
                events.append({
                    "timestamp": mtime_iso,
                    "source": "filesystem",
                    "event_type": "file_modified",
                    "description": f"Dernière modification : {file}",
                    "file": file,
                    "details": f"mtime: {mtime_iso}",
                })
            except OSError:
                pass

    far_future = parse_ts("9999-01-01T00:00:00")
    events.sort(key=lambda e: parse_ts(e.get("timestamp", "")) or far_future)
    return events


_HOST_SOURCES = {"syslog", "auth.log", "web_access", "web_error", "wp_debug"}
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _span(seconds: float) -> str:
    minutes = round(abs(seconds) / 60)
    days, rem = divmod(minutes, 24 * 60)
    return (f"{days} j " if days else "") + f"{rem // 60} h {rem % 60:02d} min"


def align_pcap_clock(events: list[dict]) -> dict | None:
    """
    Recale les événements PCAP sur l'horloge des hôtes quand elles divergent de plus d'une heure.

    Le décalage est mesuré sur les IP vues des deux côtés (première apparition dans la capture
    contre première apparition dans les journaux), médiane arrondie à la minute. L'heure d'origine
    reste dans `timestamp_origine` : seule la mise en concordance des sources change.
    """
    first_pcap: dict[str, datetime.datetime] = {}
    first_host: dict[str, datetime.datetime] = {}
    for e in events:
        ts = parse_ts(e.get("timestamp", ""))
        side = first_pcap if e.get("source") == "pcap" else first_host if e.get("source") in _HOST_SOURCES else None
        if ts is None or side is None:
            continue
        for ip in set(_IPV4.findall(f"{e.get('description', '')} {e.get('ip', '')}")):
            if ip not in side or ts < side[ip]:
                side[ip] = ts
    shared = set(first_pcap) & set(first_host)
    if not shared:
        return None
    offsets = sorted((first_pcap[ip] - first_host[ip]).total_seconds() for ip in shared)
    offset = round(offsets[len(offsets) // 2] / 60) * 60
    if abs(offset) < 3600:
        return None
    anchor = min(shared, key=lambda ip: abs((first_pcap[ip] - first_host[ip]).total_seconds() - offset))
    shift = datetime.timedelta(seconds=offset)
    shifted = 0
    for e in events:
        ts = parse_ts(e.get("timestamp", "")) if e.get("source") == "pcap" else None
        if ts:
            e["timestamp_origine"] = e["timestamp"]
            e["timestamp"] = (ts - shift).isoformat()
            shifted += 1
    far_future = parse_ts("9999-01-01T00:00:00")
    events.sort(key=lambda e: parse_ts(e.get("timestamp", "")) or far_future)
    return {"offset_seconds": offset, "anchor": anchor, "shifted": shifted}


class TimelineAnalyzer(BaseAnalyzer):
    """Construit une timeline forensique unifiée multi-sources."""
    name = "timeline"
    supported_extensions = ()

    def can_handle(self, path: str) -> bool:
        return False

    def analyze(self, path: str) -> FindingModel | None:
        return None

    def build_from_report(self, report: ReportModel) -> FindingModel:
        """Construit la timeline depuis un ReportModel existant."""
        events = build_timeline(report)

        sources = {}
        for e in events:
            src = e.get("source", "unknown")
            sources[src] = sources.get(src, 0) + 1

        meta: dict = {
            "Total événements": str(len(events)),
        }
        for src, count in sorted(sources.items(), key=lambda x: -x[1]):
            meta[f"Source: {src}"] = str(count)

        # Horloge de la capture recalée sur celle des hôtes (ancre : une IP vue des deux côtés)
        clock = align_pcap_clock(events)
        if clock:
            meta["[ATTENTION] Décalage d'horloge"] = (
                f"{_span(clock['offset_seconds'])} entre le PCAP et les journaux hôtes "
                f"({'PCAP en avance' if clock['offset_seconds'] > 0 else 'PCAP en retard'})")
            meta["Recalage PCAP"] = (f"{clock['shifted']} événement(s) recalé(s), ancre : première apparition de "
                                     f"{clock['anchor']} ; heure d'origine conservée (timestamp_origine)")

        if events:
            meta["Premier événement"] = events[0].get("timestamp", "?")
            meta["Dernier événement"] = events[-1].get("timestamp", "?")

        facts = consolidate(events)
        if facts:
            levels = {lvl: sum(f["confidence"] == lvl for f in facts) for lvl in ("élevée", "moyenne", "faible")}
            meta["Faits consolides"] = (f"{len(facts)} (confiance élevée {levels['élevée']}, "
                                        f"moyenne {levels['moyenne']}, faible {levels['faible']})")

        return FindingModel(
            type="timeline",
            file="multi-source",
            metadata=meta,
            extra={"events": events[:2000], "facts": facts[:2000], "source_stats": sources},
        )
