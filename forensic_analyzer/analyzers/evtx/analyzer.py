"""Analyzer Windows Event Logs (.evtx)."""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET

from forensic_analyzer.core import mitre
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger
from forensic_analyzer.utils.exports import export_root
from forensic_analyzer.utils.spreadsheet import neutralize_formula

from .detections import EventDetector

log = get_logger("evtx")

try:
    import Evtx.Evtx as evtx
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False

# Event IDs d'intérêt forensique
_SECURITY_EVENTS = {
    4624: "Logon réussi",
    4625: "Logon échoué",
    4634: "Logoff",
    4648: "Logon avec credentials explicites",
    4672: "Privilèges spéciaux assignés",
    4688: "Nouveau processus créé",
    4689: "Processus terminé",
    4697: "Service installé",
    4698: "Tâche planifiée créée",
    4720: "Compte utilisateur créé",
    4722: "Compte utilisateur activé",
    4724: "Reset mot de passe",
    4728: "Membre ajouté au groupe global",
    4732: "Membre ajouté au groupe local",
    4756: "Membre ajouté au groupe universel",
    4768: "Kerberos TGT demandé",
    4769: "Kerberos service ticket demandé",
    4771: "Kerberos pre-authentication échouée",
    4776: "NTLM authentication",
    7045: "Nouveau service installé",
    1102: "Audit log effacé",
    4702: "Tâche planifiée modifiée",
    4104: "PowerShell Script Block",
}

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _parse_evtx_event(xml_str: str) -> dict | None:
    """Parse un événement EVTX depuis son XML."""
    try:
        root = ET.fromstring(xml_str)
        system = root.find(f"{_NS}System")
        if system is None:
            return None

        event_id_el = system.find(f"{_NS}EventID")
        event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0

        time_el = system.find(f"{_NS}TimeCreated")
        timestamp = time_el.get("SystemTime", "") if time_el is not None else ""

        computer_el = system.find(f"{_NS}Computer")
        computer = computer_el.text if computer_el is not None else ""

        provider_el = system.find(f"{_NS}Provider")
        provider = provider_el.get("Name", "") if provider_el is not None else ""

        channel_el = system.find(f"{_NS}Channel")
        channel = channel_el.text if channel_el is not None else ""

        event_data = {}
        # Some logs use UserData instead of EventData
        data_section = root.find(f"{_NS}EventData")
        if data_section is None:
            data_section = root.find(f"{_NS}UserData")
            if data_section is not None and len(data_section) > 0:
                data_section = data_section[0] # Usually wrapped in EventXML
        
        if data_section is not None:
            for data_el in data_section:
                name = data_el.get("Name", "") or data_el.tag.replace(_NS, "")
                value = data_el.text or ""
                if name:
                    event_data[name] = value

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "computer": computer,
            "provider": provider,
            "channel": channel,
            "description": _SECURITY_EVENTS.get(event_id, "Autre"),
            "data": event_data,
        }
    except ET.ParseError:
        return None


class EVTXAnalyzer(BaseAnalyzer):
    """Analyse des fichiers Windows Event Log (.evtx)."""
    name = "evtx"
    supported_extensions = ('.evtx',)

    def analyze(self, path: str) -> FindingModel | None:
        if not HAS_EVTX:
            log.error("python-evtx requis - pip install python-evtx")
            return None
        try:
            events = []
            security_events = []
            event_ids_counter: dict[int, int] = {}
            unreadable = 0
            detector = EventDetector()

            with evtx.Evtx(path) as log_file:
                for record in log_file.records():
                    try:
                        xml_str = record.xml()
                        parsed = _parse_evtx_event(xml_str)
                        if parsed:
                            eid = parsed["event_id"]
                            event_ids_counter[eid] = event_ids_counter.get(eid, 0) + 1
                            events.append(parsed)
                            detector.feed(parsed)

                            if eid in _SECURITY_EVENTS:
                                security_events.append(parsed)
                    except Exception as exc:
                        log.debug("Enregistrement EVTX illisible : %s", exc)
                        unreadable += 1
                        continue

            detector.finish()
            events.sort(key=lambda e: e.get("timestamp", ""))
            security_events.sort(key=lambda e: e.get("timestamp", ""))

            top_events = sorted(event_ids_counter.items(), key=lambda x: -x[1])[:20]

            meta: dict = {
                "Total événements": str(len(events)),
                "Événements sécurité": str(len(security_events)),
                "Event IDs uniques": str(len(event_ids_counter)),
            }
            if unreadable:
                meta["Enregistrements illisibles"] = str(unreadable)
            if not events:
                meta["Avertissement"] = "Aucun événement lisible : fichier vide, corrompu ou chunks endommagés"

            for eid, count in top_events[:10]:
                desc = _SECURITY_EVENTS.get(eid, "")
                label = f"EventID {eid}"
                if desc:
                    label += f" ({desc})"
                meta[label] = f"{count} occurrences"

            import csv
            anomalies = []
            # Dans export/, jamais à côté de la preuve
            csv_dir = os.path.join(export_root(), "timelines")
            csv_path = os.path.join(csv_dir, os.path.basename(path) + ".timeline.csv")
            try:
                os.makedirs(csv_dir, exist_ok=True)
                with open(csv_path, "w", encoding="utf-8", newline="") as f_csv:
                    writer = csv.writer(f_csv)
                    writer.writerow(["Timestamp", "EventID", "Description", "User", "Computer", "Details"])
                    
                    for e in security_events:
                        eid = e["event_id"]
                        ts = e.get("timestamp", "")
                        user = e["data"].get("TargetUserName", e["data"].get("SubjectUserName", ""))
                        if not user:
                            user = e["data"].get("UserID", "")
                            
                        details = ""
                        if eid == 4688:
                            details = f"Proc: {e['data'].get('NewProcessName', '')} | Cmd: {e['data'].get('CommandLine', '')}"
                        elif eid == 4104:
                            details = f"Script: {e['data'].get('ScriptBlockText', '')[:200]}"
                        elif eid in (4624, 4625):
                            details = f"IP: {e['data'].get('IpAddress', '')} | LogonType: {e['data'].get('LogonType', '')}"
                            
                        # Détection Anomalies Heures (Nuit)
                        if eid in (4624, 4625, 4688):
                            try:
                                if ts and "T" in ts:
                                    hour = int(ts.split("T")[1][:2])
                                    if hour < 6 or hour > 22: # Entre 22h et 6h
                                        if user and not user.endswith("$"): # Ignore system accounts
                                            anomalies.append(f"Activité hors heures ({hour}h) par {user} (Event {eid})")
                            except Exception: pass
                            
                        writer.writerow([neutralize_formula(v) for v in
                                         (ts, eid, e["description"], user, e.get("computer", ""), details)])
            except Exception as e:
                log.warning(f"Impossible de créer la timeline CSV: {e}")

            # Alertes spécifiques
            failed_logons = sum(1 for e in security_events if e["event_id"] == 4625)
            audit_cleared = sum(1 for e in security_events if e["event_id"] == 1102)
            new_services = sum(1 for e in security_events if e["event_id"] in (4697, 7045))

            if failed_logons > 0:
                meta["[ALERTE] Logons échoués"] = str(failed_logons)
            if audit_cleared > 0:
                meta["[ALERTE] Audit log effacé"] = str(audit_cleared)
            if new_services > 0:
                meta["[ALERTE] Nouveaux services"] = str(new_services)
                
            if anomalies:
                meta["Anomalies Comportementales"] = f"{len(anomalies)} détectées (ex: {anomalies[0]})"

            # Détections (force brute, pulvérisation, LOLBins, persistance, Sysmon) : critiques d'abord
            rank = {"critique": 0, "haute": 1, "moyenne": 2}
            detections = sorted(detector.alerts, key=lambda a: (rank.get(a["severity"], 3), a["timestamp"]))
            for kind, count in sorted(detector.counts.items(), key=lambda x: -x[1]):
                if any(a["kind"] == kind for a in detections):
                    meta[f"[ALERTE] Détection {kind}"] = str(count)
            for i, a in enumerate(detections[:10], 1):
                meta[f"[ALERTE] #{i} ({a['severity']})"] = f"{a['timestamp'][:19]} {a['description'][:150]}"
            if detector.remote_logons:
                meta["Connexions distantes (réseau / RDP)"] = ", ".join(
                    f"{user} depuis {ip} (type {lt}, {n}x)"
                    for (ip, user, lt), n in detector.remote_logons.most_common(5))
            if detector.techniques:
                meta["MITRE ATT&CK"] = mitre.summary(detector.techniques)
                
            meta["Timeline Exportée"] = csv_path

            return FindingModel(
                type="evtx",
                file=os.path.abspath(path),
                metadata=meta,
                extra={
                    "total_events": len(events),
                    "security_events": security_events[:200],
                    "event_id_stats": dict(top_events),
                    "alerts": {
                        "failed_logons": failed_logons,
                        "audit_cleared": audit_cleared,
                        "new_services": new_services,
                    },
                    "detections": detections,
                    "mitre": sorted(detector.techniques),
                },
            )
        except Exception as exc:
            log.error("Erreur EVTX '%s' : %s", os.path.basename(path), exc)
            return None
