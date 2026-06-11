"""Generateur de Timeline DFIR."""
import csv
from datetime import datetime
from typing import Any

from forensic_analyzer.models.finding import FindingModel


class DFIRTimelineEvent:
    """Evénement unique pour la Timeline forensique."""
    
    def __init__(self, timestamp: str, source: str, event_type: str, description: str, raw_data: Any = None):
        self.timestamp = timestamp
        self.source = source
        self.event_type = event_type
        self.description = description
        self.raw_data = raw_data
        
        # Tente de parser le timestamp en UTC
        self.dt = self._parse_ts(timestamp)

    def _parse_ts(self, ts: str) -> datetime | None:
        if not ts or ts == "N/A":
            return None
        try:
            # ISO format: 2024-06-11T12:00:00+00:00 or similar
            # On remplace le Z par +00:00 pour la compatibilite pre-3.11
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None


def generate_timeline(findings: list[FindingModel]) -> list[DFIRTimelineEvent]:
    """Ingere tous les resultats et produit une timeline chronologique."""
    events = []

    for f in findings:
        t = f.type
        src_file = f.file
        extra = f.extra

        if t == "evtx" and "events" in extra:
            for ev in extra["events"]:
                events.append(DFIRTimelineEvent(
                    timestamp=ev.get("timestamp", ""),
                    source=f"EVTX: {src_file}",
                    event_type=f"EventID {ev.get('event_id')}",
                    description=f"{ev.get('channel')} - {str(ev.get('event_data'))[:200]}",
                    raw_data=ev
                ))

        elif t == "disk":
            if "mft_records" in extra:
                for rec in extra["mft_records"]:
                    ts = rec.get("timestamps", {})
                    fname = rec.get("filename", "?")
                    if ts.get("created"):
                        events.append(DFIRTimelineEvent(ts["created"], f"MFT: {src_file}", "File Creation", f"Created: {fname}", rec))
                    if ts.get("modified"):
                        events.append(DFIRTimelineEvent(ts["modified"], f"MFT: {src_file}", "File Modification", f"Modified: {fname}", rec))
                    if ts.get("accessed"):
                        events.append(DFIRTimelineEvent(ts["accessed"], f"MFT: {src_file}", "File Access", f"Accessed: {fname}", rec))
            if "deleted_files" in extra:
                for rec in extra["deleted_files"]:
                    ts = rec.get("timestamps", {})
                    fname = rec.get("filename", "?")
                    if ts.get("modified"):
                        events.append(DFIRTimelineEvent(ts["modified"], f"MFT(Deleted): {src_file}", "Deleted File Mod", f"{fname}", rec))

        elif t == "registry":
            if "entries" in extra:
                for entry in extra["entries"]:
                    ts = entry.get("timestamp")
                    if ts:
                        events.append(DFIRTimelineEvent(
                            timestamp=ts,
                            source=f"Registry: {src_file}",
                            event_type="Key Modified",
                            description=f"Key: {entry.get('path')} -> {entry.get('name')} = {entry.get('value')[:100]}",
                            raw_data=entry
                        ))

        elif t == "chromium":
            if "history" in extra:
                for h in extra["history"]:
                    events.append(DFIRTimelineEvent(
                        timestamp=h.get("visit_time", ""),
                        source=f"Chromium: {src_file}",
                        event_type="Web Visit",
                        description=f"URL: {h.get('url')} - Title: {h.get('title')}",
                        raw_data=h
                    ))
            if "downloads" in extra:
                for d in extra["downloads"]:
                    events.append(DFIRTimelineEvent(
                        timestamp=d.get("start_time", ""),
                        source=f"Chromium: {src_file}",
                        event_type="File Download",
                        description=f"Downloaded: {d.get('target_path')} from {d.get('url')}",
                        raw_data=d
                    ))

        elif t == "linux_artifacts":
            if "bash_histories" in extra:
                for path, hist in extra["bash_histories"].items():
                    for cmd in hist.get("last_commands", []) + [s["command"] for s in hist.get("suspicious", [])]:
                        if cmd.startswith("["):
                            parts = cmd.split("]", 1)
                            if len(parts) == 2:
                                events.append(DFIRTimelineEvent(
                                    timestamp=parts[0][1:],
                                    source=f"Bash History: {path}",
                                    event_type="Command Execution",
                                    description=parts[1].strip(),
                                    raw_data=cmd
                                ))
            if "ssh" in extra:
                for k in extra["ssh"].get("keys", []):
                    if k.get("modified"):
                        events.append(DFIRTimelineEvent(
                            timestamp=k["modified"],
                            source=f"SSH Key: {k.get('file')}",
                            event_type="File Modification",
                            description=f"SSH Key modified for user {k.get('user')}",
                            raw_data=k
                        ))
                        
        elif t == "pdf":
            if "metadata" in extra:
                pmeta = extra["metadata"]
                if pmeta.get("CreationDate"):
                    events.append(DFIRTimelineEvent(
                        timestamp=pmeta["CreationDate"],
                        source=f"PDF: {src_file}",
                        event_type="File Creation",
                        description=f"PDF Created: {src_file}",
                        raw_data=pmeta
                    ))
                if pmeta.get("ModDate"):
                    events.append(DFIRTimelineEvent(
                        timestamp=pmeta["ModDate"],
                        source=f"PDF: {src_file}",
                        event_type="File Modification",
                        description=f"PDF Modified: {src_file}",
                        raw_data=pmeta
                    ))

        elif t == "prefetch":
            # Si pyscca a pu extraire une date brute
            for k, v in f.metadata.items():
                if k == "Dernière Exécution" and v != "Extraite (voir pyscca object)" and isinstance(v, str):
                    events.append(DFIRTimelineEvent(
                        timestamp=v,
                        source=f"Prefetch: {src_file}",
                        event_type="Execution",
                        description=f"Program Executed: {f.metadata.get('Exécutable Source', 'Unknown')}",
                        raw_data=f.metadata
                    ))

    # Conserver uniquement les events ayant un datetime valide
    valid_events = [e for e in events if e.dt is not None]
    
    # Trier chronologiquement (UTC)
    valid_events.sort(key=lambda x: x.dt)
    
    return valid_events


def filter_timeline(events: list[DFIRTimelineEvent], start_iso: str | None = None, end_iso: str | None = None) -> list[DFIRTimelineEvent]:
    """Filtre la timeline selon une plage de dates (ISO 8601)."""
    filtered = events
    if start_iso:
        start_dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        filtered = [e for e in filtered if e.dt >= start_dt]
    if end_iso:
        end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
        filtered = [e for e in filtered if e.dt <= end_dt]
    return filtered


def detect_gaps(events: list[DFIRTimelineEvent], min_gap_hours: int = 24) -> list[dict]:
    """Détecte les périodes d'inactivité suspectes (Anti-Forensics, Wiping)."""
    gaps = []
    if len(events) < 2:
        return gaps
        
    for i in range(1, len(events)):
        prev = events[i-1]
        curr = events[i]
        
        diff = (curr.dt - prev.dt).total_seconds()
        if diff > (min_gap_hours * 3600):
            gaps.append({
                "start": prev.dt.isoformat(),
                "end": curr.dt.isoformat(),
                "duration_hours": round(diff / 3600, 2),
                "prev_event": f"[{prev.source}] {prev.description}",
                "next_event": f"[{curr.source}] {curr.description}",
            })
            
    # Trier par duree descendante
    gaps.sort(key=lambda x: x["duration_hours"], reverse=True)
    return gaps


def export_timeline_csv(events: list[DFIRTimelineEvent], output_path: str):
    """Exporte la timeline en CSV compatible Timeline Explorer (Zimmerman)."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Headers inspirés de log2timeline / Timeline Explorer
        writer.writerow(["datetime", "timestamp_desc", "source", "source_long", "message", "parser", "display_name", "tag"])
        
        for e in events:
            writer.writerow([
                e.dt.strftime("%Y-%m-%d %H:%M:%S"),
                e.event_type,
                "forensic_analyzer",
                e.source,
                e.description,
                "custom_dfir",
                e.source.split("/")[-1] if "/" in e.source else e.source,
                ""
            ])
