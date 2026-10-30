"""Extraction normalisée des indicateurs (IOC) depuis les résultats de tous les analyzers.

Chaque analyzer stocke ses indicateurs à sa façon ; ce module les ramène à une forme
commune (type, valeur) pour la corrélation, la génération de règles et l'export STIX.
"""
from __future__ import annotations

import ipaddress
import ntpath
import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from forensic_analyzer.models.finding import FindingModel, ReportModel

_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>|]+", re.IGNORECASE)
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.IGNORECASE)
_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_MD5 = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
# Domaines de documentation / licences présents dans presque tous les binaires légitimes
_BENIGN_DOMAINS = {"www.debian.org", "debian.org", "gnu.org", "www.gnu.org", "example.com",
                   "www.example.com", "schemas.microsoft.com", "www.w3.org", "w3.org"}

# Types de résultats dont le fichier analysé est lui-même un indicateur (empreinte, nom)
_FILE_ARTIFACT_TYPES = {"elf_analysis", "malware_analysis", "pe_analysis", "pdf_analysis", "webshell_analysis"}


@dataclass(frozen=True)
class Observation:
    kind: str          # ipv4, domain, url, sha256, md5, path, filename, ja3, service
    value: str
    source: str        # type du résultat (elf_analysis, pcap, memory...)
    artifact: str      # fichier ou origine dans l'image
    context: str = ""


@dataclass
class IOC:
    kind: str
    value: str
    observations: list[Observation] = field(default_factory=list)

    @property
    def sources(self) -> set[str]:
        return {o.source for o in self.observations}



def _keep_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or value == "255.255.255.255")


def _filename(path: str) -> str:
    return (ntpath.basename(path) if "\\" in path else os.path.basename(path)).lower()


def _artifact(f: FindingModel) -> str:
    return f.metadata.get("Origine (image)") or os.path.basename(f.file)


class _Collector:
    def __init__(self, finding: FindingModel):
        self.f = finding
        self.items: list[Observation] = []

    def add(self, kind: str, value, context: str = "") -> None:
        if not value or not isinstance(value, str):
            return
        value = value.strip()
        if kind == "ipv4" and not _keep_ip(value):
            return
        if kind == "domain":
            value = value.lower().rstrip(".")
            if not _DOMAIN.match(value) or value in _BENIGN_DOMAINS:
                return
        if kind in ("sha256", "md5", "ja3"):
            value = value.lower()
        if kind == "url":
            host = re.sub(r"^https?://", "", value, flags=re.I).split("/")[0].split(":")[0]
            if host.lower() in _BENIGN_DOMAINS:
                return
            if _IP.fullmatch(host):
                self.add("ipv4", host, context)
            else:
                self.add("domain", host, context)
        if kind == "path":
            self.add("filename", _filename(value), context)
        self.items.append(Observation(kind, value, self.f.type, _artifact(self.f), context))

    def text(self, text, context: str = "") -> None:
        """IP et URL trouvées dans un texte libre."""
        if not isinstance(text, str):
            return
        for url in _URL.findall(text):
            self.add("url", url.rstrip(".,;)"), context)
        for ip in _IP.findall(text):
            self.add("ipv4", ip, context)


# Extracteurs spécifiques, par type de résultat

def _behaviour(c: _Collector, f: FindingModel) -> None:
    """Destinations, fichiers et commandes reconstruits par désassemblage (ELF et PE)."""
    for net in f.extra.get("network", []):
        c.add("ipv4", net.get("host"), f"connect() vers le port {net.get('port')}")
    summary = (f.extra.get("disassembly") or {}).get("summary", {})
    for path in summary.get("files", []):
        c.add("path", path, "fichier ouvert par le binaire (désassemblage)")
    for url in summary.get("urls", []):
        c.add("url", url, "URL utilisée par le binaire (désassemblage)")


def _elf(c: _Collector, f: FindingModel) -> None:
    iocs = f.extra.get("iocs", {})
    for ip in iocs.get("ips", []):
        c.add("ipv4", ip, "chaîne du binaire")
    for url in iocs.get("urls", []):
        c.add("url", url, "chaîne du binaire")
    for p in iocs.get("paths", []):
        c.add("path", p, "chemin référencé par le binaire")
    _behaviour(c, f)


def _pe(c: _Collector, f: FindingModel) -> None:
    for category in ("urls", "ips"):
        for item in f.extra.get("strings_iocs", {}).get(category, []):
            c.text(item.get("value") if isinstance(item, dict) else item, "chaîne du binaire")
    for url in f.extra.get("pdf_urls", []):
        c.add("url", url, "URL du document")
    _behaviour(c, f)


def _pcap(c: _Collector, f: FindingModel) -> None:
    for beacon in f.extra.get("c2_beacons", {}).get("beacons", []):
        c.text(beacon.get("connection", ""), f"beacon ~{beacon.get('avg_interval_sec')} s")
    for ip in f.extra.get("top_dst_ips", {}):
        c.add("ipv4", ip, "destination fréquente")
    for d in f.extra.get("typosquatting", []):
        c.add("domain", d.get("domain") if isinstance(d, dict) else d, "domaine suspect (typosquatting)")
    for q in f.extra.get("dns_exfiltration", {}).get("long_queries", []) or []:
        c.add("domain", q if isinstance(q, str) else q.get("query"), "requête DNS anormale")
    for conn, ja3 in (f.extra.get("ja3_fingerprints") or {}).items():  # {connexion: hash JA3}
        c.add("ja3", ja3, f"empreinte TLS {conn}")
    for cred in f.extra.get("credentials", []):
        c.add("domain", cred.get("host"), f"identifiants {cred.get('protocol', '')} en clair")
    for req in f.extra.get("http_exfiltration", []):
        c.text(str(req), "exfiltration HTTP")


def _memory(c: _Collector, f: FindingModel) -> None:
    for s in f.extra.get("remote_sockets", []):
        c.add("ipv4", s.get("dst", "").rsplit(":", 1)[0], f"socket ouverte par {s.get('process')} ({s.get('pid')})")
    for p in f.extra.get("suspicious_processes", []):
        exe = (p.get("args") or "").split()[0] if p.get("args") else ""
        c.add("path", exe, f"processus {p.get('comm')} (PID {p.get('pid')})")
    for p in f.extra.get("hidden_processes", []):
        c.add("filename", str(p.get("COMM", "")).lower(), f"processus caché (PID {p.get('PID')})")


def _linux(c: _Collector, f: FindingModel) -> None:
    for unit in f.extra.get("systemd", {}).get("units", []):
        if unit.get("suspicious"):
            c.add("path", unit["unit"], "unité systemd suspecte")
            c.add("service", os.path.basename(unit["unit"]), "unité systemd suspecte")
            c.add("path", unit.get("binary"), f"ExecStart de {os.path.basename(unit['unit'])}")
    for items in f.extra.get("file_anomalies", {}).values():
        for item in items:
            c.add("path", item.get("path"), "fichier anormal (propriétaire / caché / hors paquet)")
    for item in f.extra.get("other_persistence", []):
        if item.get("severity") != "info":
            c.add("path", item.get("path"), "persistance")
    for a in f.extra.get("auth_log", {}).get("failed_details", []):
        c.add("ipv4", a.get("source_ip"), "échec d'authentification")


def _disk(c: _Collector, f: FindingModel) -> None:
    for items in f.extra.get("file_anomalies", {}).values():
        for item in items:
            c.add("path", item.get("path"), "fichier anormal dans l'image")


def _evtx(c: _Collector, f: FindingModel) -> None:
    for e in f.extra.get("security_events", []):
        data = e.get("data", {}) or {}
        if e.get("event_id") in (7045, 4697):
            c.add("service", data.get("ServiceName"), "service installé (EVTX)")
            c.add("path", data.get("ImagePath") or data.get("ServiceFileName"), "binaire de service (EVTX)")
        if e.get("event_id") in (4624, 4625):
            c.add("ipv4", data.get("IpAddress"), f"logon {e.get('event_id')}")
        if e.get("event_id") == 4688:
            c.add("path", data.get("NewProcessName"), "processus créé (EVTX 4688)")


def _registry(c: _Collector, f: FindingModel) -> None:
    for p in f.extra.get("persistence", []):
        c.add("path", str(p.get("value", "")).split('"')[1] if '"' in str(p.get("value", "")) else p.get("value"),
              f"{p.get('type')} {p.get('key')}")


_DROPPED_EXT = (".exe", ".dll", ".scr", ".ps1", ".bat", ".vbs", ".hta", ".js", ".jar", ".msi", ".sh", ".elf", ".bin")


def _suspicious_browser_url(url: str) -> bool:
    """Un site visite n'est pas un indicateur : seuls l'IP brute et le téléchargement d'exécutable le sont."""
    host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split(":")[0]
    path = url.split("?")[0].lower()
    return bool(_IP.fullmatch(host)) or path.endswith(_DROPPED_EXT)


def _chromium(c: _Collector, f: FindingModel) -> None:
    for d in f.extra.get("chromium_downloads", []):
        c.add("path", d.get("fichier"), "téléchargement navigateur")
    for u in f.extra.get("chromium_urls", [])[:500]:
        if _suspicious_browser_url(u.get("url") or ""):
            c.add("url", u.get("url"), "historique navigateur")


def _firefox(c: _Collector, f: FindingModel) -> None:
    for url in f.extra.get("suspects", []):
        c.add("url", url, "site suspect (historique navigateur)")
    for entry in f.extra.get("history", [])[:500]:
        if _suspicious_browser_url(entry.get("url") or ""):
            c.add("url", entry.get("url"), "historique navigateur")


def _prefetch(c: _Collector, f: FindingModel) -> None:
    name = os.path.basename(f.file)
    if name.lower().endswith(".pf"):
        c.add("filename", name.rsplit("-", 1)[0].lower(), "exécution (Prefetch)")
    for p in f.extra.get("chemins_touches", []):
        c.add("path", p, "fichier référencé")


def _ids(c: _Collector, f: FindingModel) -> None:
    for a in f.extra.get("raw_alerts", []):
        c.add("ipv4", a.get("dest_ip"), f"alerte IDS : {a.get('signature')}")
        c.add("ipv4", a.get("src_ip"), f"alerte IDS : {a.get('signature')}")


def _ioc_extractor(c: _Collector, f: FindingModel) -> None:
    iocs = f.extra.get("iocs", {})
    for ip in iocs.get("ipv4", []):
        c.add("ipv4", ip, "extraction IOC")
    for url in iocs.get("urls", []):
        c.add("url", url, "extraction IOC")
    for d in iocs.get("domains", []):
        c.add("domain", d, "extraction IOC")


def _log_analysis(c: _Collector, f: FindingModel) -> None:
    iocs = f.extra.get("iocs", {})
    for ip in iocs.get("ips", []):
        c.add("ipv4", ip, f"journal {f.extra.get('log_type', 'système')}")
    for url in iocs.get("urls", []):
        c.add("url", url, f"journal {f.extra.get('log_type', 'système')}")
    for rfile in f.extra.get("referenced_files", []):
        c.add("path", rfile, "fichier référencé dans les logs")


def _webshell(c: _Collector, f: FindingModel) -> None:
    c.add("filename", _filename(f.file), "webshell détecté")


def _network_recon(c: _Collector, f: FindingModel) -> None:
    for h in f.extra.get("hosts", []):
        if h.get("ip"):
            c.add("ipv4", h["ip"], "cible scan nmap")
        for hn in h.get("hostnames", []):
            c.add("domain", hn, "nom d'hôte nmap")


_EXTRACTORS: dict[str, Callable[[_Collector, FindingModel], None]] = {
    "elf_analysis": _elf,
    "malware_analysis": _pe, "pe_analysis": _pe, "pdf_analysis": _pe,
    "pcap": _pcap,
    "memory": _memory,
    "linux_artifacts": _linux,
    "disk": _disk,
    "evtx": _evtx,
    "registry": _registry,
    "chromium_artifacts": _chromium,
    "firefox_places": _firefox,
    "prefetch": _prefetch, "lnk_shortcut": _prefetch,
    "ids_alerts": _ids,
    "ioc": _ioc_extractor,
    "log_analysis": _log_analysis,
    "webshell_analysis": _webshell,
    "network_recon": _network_recon,
}


def observations(finding: FindingModel) -> list[Observation]:
    """Indicateurs d'un résultat."""
    c = _Collector(finding)
    if finding.type in _FILE_ARTIFACT_TYPES:
        for key, kind in (("SHA-256", "sha256"), ("MD5", "md5")):
            c.add(kind, finding.metadata.get(key), "empreinte du fichier analysé")
        origin = finding.metadata.get("Origine (image)", "")
        if ":" in origin:
            c.add("path", origin.split(":", 1)[1], "fichier analysé (chemin dans l'image)")
        else:
            c.add("filename", _filename(finding.file), "fichier analysé")
    extractor = _EXTRACTORS.get(finding.type)
    if extractor:
        extractor(c, finding)
    return c.items


def collect(findings: Iterable[FindingModel] | ReportModel) -> list[IOC]:
    """IOC uniques de tous les résultats, avec leurs observations."""
    if isinstance(findings, ReportModel):
        findings = findings.findings
    merged: dict[tuple[str, str], IOC] = {}
    for f in findings:
        for obs in observations(f):
            key = (obs.kind, obs.value)
            ioc = merged.setdefault(key, IOC(obs.kind, obs.value))
            if obs not in ioc.observations:
                ioc.observations.append(obs)
    return sorted(merged.values(), key=lambda i: (i.kind, i.value))
