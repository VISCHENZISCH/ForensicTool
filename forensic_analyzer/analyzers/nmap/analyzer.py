"""Analyzer pour les rapports de scan réseau Nmap (format XML)."""
from __future__ import annotations

import datetime
import os
import xml.etree.ElementTree as ET
from typing import Any

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("nmap")


class NmapAnalyzer(BaseAnalyzer):
    """Analyse des rapports d'audit réseau et cartographie Nmap XML."""
    name = "nmap"
    supported_extensions = (".xml",)

    def can_handle(self, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        basename = os.path.basename(path).lower()
        if not basename.endswith(".xml") and "nmap" not in basename:
            return False
        try:
            with open(path, "rb") as f:
                head = f.read(512)
                if b"<nmaprun" in head:
                    return True
        except Exception:
            pass
        return False

    def analyze(self, path: str) -> FindingModel | None:
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            if root.tag != "nmaprun":
                return None

            scanner = root.get("scanner", "nmap")
            args = root.get("args", "")
            start_epoch = root.get("start")
            iso_start = ""
            if start_epoch and start_epoch.isdigit():
                dt = datetime.datetime.fromtimestamp(int(start_epoch), datetime.timezone.utc)
                iso_start = dt.isoformat()

            hosts_data = []
            scripts: list[str] = []
            all_ips = set()
            total_open_ports = 0

            for host in root.findall("host"):
                # Sans <status>, nmap ne liste que les hôtes qui ont répondu
                status_el = host.find("status")
                if status_el is not None and status_el.get("state") != "up":
                    continue

                addr_el = host.find("address[@addrtype='ipv4']")
                if addr_el is None:
                    addr_el = host.find("address")
                ip = addr_el.get("addr") if addr_el is not None else ""
                if ip:
                    all_ips.add(ip)

                hostnames = [hn.get("name") for hn in host.findall("hostnames/hostname") if hn.get("name")]

                open_ports = []
                for p in host.findall("ports/port"):
                    state_el = p.find("state")
                    if state_el is not None and state_el.get("state") == "open":
                        port_id = p.get("portid")
                        proto = p.get("protocol", "tcp")
                        svc_el = p.find("service")
                        svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                        product = svc_el.get("product", "") if svc_el is not None else ""
                        version = svc_el.get("version", "") if svc_el is not None else ""
                        desc = f"{port_id}/{proto} ({svc_name}" + (" " + f"{product} {version}".strip() if product else "") + ")"
                        open_ports.append(desc)
                        total_open_ports += 1
                        for script in p.findall("script"):
                            output = " ".join(script.get("output", "").split())
                            if output:
                                scripts.append(f"{ip}:{port_id} [{script.get('id')}] {output}")

                hosts_data.append({
                    "ip": ip,
                    "hostnames": hostnames,
                    "open_ports": open_ports,
                })

            meta: dict[str, Any] = {
                "Outil": f"{scanner} (Scan réseau)",
                "Commande": args[:80] if args else "Non spécifiée",
                "Hôtes actifs découverts": str(len(hosts_data)),
                "Total ports ouverts": str(total_open_ports),
            }

            for i, out in enumerate(scripts[:5], 1):
                meta[f"Script nmap #{i}"] = out[:160]

            for i, h in enumerate(hosts_data[:5]):
                ports_str = ", ".join(h["open_ports"][:5]) or "Aucun port ouvert détecté"
                meta[f"Cible #{i+1} : {h['ip']}"] = ports_str

            events = []
            if iso_start:
                events.append({
                    "timestamp": iso_start,
                    "source": "nmap",
                    "event_type": "network_recon",
                    "description": f"Scan de reconnaissance réseau Nmap : {args[:100]}",
                    "ip": ", ".join(sorted(all_ips)[:3]),
                    "file": path,
                })

            return FindingModel(
                type="network_recon",
                file=os.path.abspath(path),
                metadata=meta,
                extra={
                    "args": args,
                    "hosts": hosts_data,
                    "iocs": {"ips": sorted(list(all_ips))},
                    "timeline_events": events,
                },
                severity="faible",   # trace de reconnaissance, pas une compromission
            )
        except Exception as exc:
            log.error("Erreur lors de l'analyse du rapport Nmap '%s' : %s", path, exc)
            return None
