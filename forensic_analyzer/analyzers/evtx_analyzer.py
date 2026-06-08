"""Analyzer Windows Event Logs (.evtx)."""
from __future__ import annotations

import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("evtx")

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as evtx_views
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False
    class DummyEvtx:
        pass
    evtx = DummyEvtx
    evtx_views = None

try:
    import xml.etree.ElementTree as ET
    HAS_XML = True
except ImportError:
    HAS_XML = False

# Event IDs d'interet forensique
_SECURITY_EVENTS = {
    4624: "Logon reussi",
    4625: "Logon echoue",
    4634: "Logoff",
    4648: "Logon avec credentials explicites",
    4672: "Privileges speciaux assignes",
    4688: "Nouveau processus cree",
    4689: "Processus termine",
    4697: "Service installe",
    4698: "Tache planifiee creee",
    4720: "Compte utilisateur cree",
    4722: "Compte utilisateur active",
    4724: "Reset mot de passe",
    4728: "Membre ajoute au groupe global",
    4732: "Membre ajoute au groupe local",
    4756: "Membre ajoute au groupe universel",
    4768: "Kerberos TGT demande",
    4769: "Kerberos service ticket demande",
    4771: "Kerberos pre-authentication echouee",
    4776: "NTLM authentication",
    7045: "Nouveau service installe",
    1102: "Audit log efface",
}

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _parse_evtx_event(xml_str: str) -> dict | None:
    """Parse un evenement EVTX depuis son XML."""
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

        # Event data
        event_data = {}
        data_section = root.find(f"{_NS}EventData")
        if data_section is not None:
            for data_el in data_section:
                name = data_el.get("Name", "")
                value = data_el.text or ""
                if name:
                    event_data[name] = value

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "computer": computer,
            "provider": provider,
            "channel": channel,
            "description": _SECURITY_EVENTS.get(event_id, ""),
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

            with evtx.Evtx(path) as log_file:
                for record in log_file.records():
                    try:
                        xml_str = record.xml()
                        parsed = _parse_evtx_event(xml_str)
                        if parsed:
                            eid = parsed["event_id"]
                            event_ids_counter[eid] = event_ids_counter.get(eid, 0) + 1
                            events.append(parsed)

                            if eid in _SECURITY_EVENTS:
                                security_events.append(parsed)
                    except Exception:
                        continue

            # Trier par timestamp
            events.sort(key=lambda e: e.get("timestamp", ""))
            security_events.sort(key=lambda e: e.get("timestamp", ""))

            # Top event IDs
            top_events = sorted(event_ids_counter.items(), key=lambda x: -x[1])[:20]

            meta: dict = {
                "Fichier": os.path.basename(path),
                "Total evenements": str(len(events)),
                "Evenements securite": str(len(security_events)),
                "Event IDs uniques": str(len(event_ids_counter)),
            }

            for eid, count in top_events[:10]:
                desc = _SECURITY_EVENTS.get(eid, "")
                label = f"EventID {eid}"
                if desc:
                    label += f" ({desc})"
                meta[label] = f"{count} occurrences"

            # Alertes specifiques
            failed_logons = sum(1 for e in security_events if e["event_id"] == 4625)
            audit_cleared = sum(1 for e in security_events if e["event_id"] == 1102)
            new_services = sum(1 for e in security_events if e["event_id"] in (4697, 7045))

            if failed_logons > 0:
                meta["[ALERTE] Logons echoues"] = str(failed_logons)
            if audit_cleared > 0:
                meta["[ALERTE] Audit log efface"] = str(audit_cleared)
            if new_services > 0:
                meta["[ALERTE] Nouveaux services"] = str(new_services)

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
                },
            )
        except Exception as exc:
            log.error("Erreur EVTX '%s' : %s", os.path.basename(path), exc)
            return None
