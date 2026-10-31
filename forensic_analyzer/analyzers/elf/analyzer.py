"""Analyse statique de binaires ELF (Linux), sans exécution."""
from __future__ import annotations

import os
import re
from typing import Any

from forensic_analyzer.analyzers.malware.entropy import calculate_entropy
from forensic_analyzer.analyzers.malware.yara_scanner import scan_yara
from forensic_analyzer.core import mitre
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils import disasm
from forensic_analyzer.utils.capa import run_capa
from forensic_analyzer.utils.logger import get_logger
from forensic_analyzer.utils.strings_extractor import extract_strings_with_offsets

from .parser import ELFError, parse_elf

log = get_logger("elf")

MAX_BYTES = 64 * 1024 * 1024
_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"https?://[^\s\"'<>]+")
# Chemins absolus sous un répertoire système ou temporaire
_SYSTEM_PATH = re.compile(r"(?<![\w.])/(?:tmp|var|dev/shm|usr|etc|lib|lib64|opt)/[\w./%-]+")
_TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
# Sockets et verrous X11 standards dans /tmp
_BENIGN_TEMP = re.compile(r"^\.(?:X(?:%d|\d+)-lock|X11-unix|ICE-unix|XIM-unix|font-unix|Test-unix)$")
# Versions de bibliothèques et adresses non routables fréquentes dans les binaires légitimes
_BENIGN_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
# Domaines/URL courants dans les binaires légitimes (licences, code source, doc)
_BENIGN_URL_DOMAINS = {
    "github.com", "www.github.com", "gitlab.com", "www.gnu.org", "gnu.org",
    "www.debian.org", "debian.org", "www.kernel.org", "kernel.org",
    "www.w3.org", "w3.org", "schemas.microsoft.com", "example.com",
    "www.example.com", "sourceware.org", "busybox.net", "www.busybox.net",
    "uclibc.org", "musl.libc.org", "www.openssl.org", "openssl.org",
    "creativecommons.org", "spdx.org", "fsf.org", "www.fsf.org",
}
# Signatures de logiciels connus dans les chaînes (nom, regex version)
_KNOWN_SOFTWARE = [
    (re.compile(r"BusyBox\s+v?(\d+\.\d+[\.\d]*)"), "BusyBox"),
    (re.compile(r"GNU\s+coreutils\s+(\d+[\.\d]*)"), "GNU coreutils"),
    (re.compile(r"OpenSSH[_\s]+(\d+[\.\d]*)"), "OpenSSH"),
    (re.compile(r"OpenSSL\s+(\d+[\.\d]+[a-z]?)"), "OpenSSL"),
    (re.compile(r"bash,?\s+version\s+(\d+[\.\d]*)"), "GNU Bash"),
    (re.compile(r"curl\s+(\d+[\.\d]*)"), "curl"),
    (re.compile(r"GNU\s+Wget\s+(\d+[\.\d]*)"), "GNU Wget"),
    (re.compile(r"dropbear(?:bear)?\s+v?(\d+[\.\d]*)"), "Dropbear"),
    (re.compile(r"nmap(?:\.org)?\s+(\d+[\.\d]*)"), "Nmap"),
]


def _is_benign_ip(ip_str: str) -> bool:
    """IP privée, de documentation, link-local ou multicast : pas un indicateur dans un binaire."""
    import ipaddress as _ipa
    try:
        ip = _ipa.ip_address(ip_str)
    except ValueError:
        return True
    return (ip.is_private or ip.is_reserved or ip.is_loopback
            or ip.is_link_local or ip.is_multicast or ip.is_unspecified
            or ip_str in _BENIGN_IPS)


def _is_benign_url(url: str) -> bool:
    """URL appartenant à un domaine de documentation / code source légitime."""
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0].lower()
    return host in _BENIGN_URL_DOMAINS


def _identify_software(strings: list[str]) -> list[str]:
    """Identifie les logiciels connus à partir des chaînes extraites du binaire."""
    identified = []
    for s in strings:
        for pattern, name in _KNOWN_SOFTWARE:
            m = pattern.search(s)
            if m:
                version = m.group(1)
                ident = f"{name} {version}"
                if ident not in identified:
                    identified.append(ident)
    # Détection BusyBox par sa signature multi-call
    if not any("BusyBox" in i for i in identified):
        if any("BusyBox is a multi-call binary" in s for s in strings):
            identified.insert(0, "BusyBox (version non déterminée)")
    return identified


def _hidden_system_paths(strings: list[str]) -> list[str]:
    """
    Chemins cachés typiques d'un implant : tout composant caché sous un répertoire
    temporaire (ex : /tmp/.X11-unix/.lock), ou un répertoire caché sous /usr, /etc, /lib, /opt
    (ex : /usr/lib/systemd/.cache/x). Les chemins de débogage et de sources sont ignorés.
    Limite connue : quelques outils légitimes utilisent aussi /tmp/.xxx (nstat, guestfish).
    """
    found = set()
    for s in strings:
        for p in _SYSTEM_PATH.findall(s):
            if p.startswith(("/usr/lib/debug/", "/usr/src/")):
                continue
            parts = [c for c in p.split("/") if c]
            if p.startswith(_TEMP_PREFIXES):
                hidden = [c for c in parts if c.startswith(".") and c not in (".", "..") and not _BENIGN_TEMP.match(c)]
            else:
                hidden = [c for c in parts[:-1] if c.startswith(".") and c not in (".", "..")]
            if hidden:
                found.add(p)
    return sorted(found)


class ELFAnalyzer(BaseAnalyzer):
    """Binaires Linux : liaison, symboles, capacités, IOC et YARA."""
    name = "binaire_elf"
    supported_extensions = (".elf",)

    def analyze(self, path: str) -> FindingModel | None:
        try:
            with open(path, "rb") as f:
                data = f.read(MAX_BYTES)
            info = parse_elf(data)
        except (OSError, ELFError) as exc:
            log.warning("ELF illisible '%s' : %s", path, exc)
            return None

        meta: dict[str, Any] = {
            "Format": f"{info['class']} {info['machine']} ({info['endianness']} endian)",
            "Type": info["type"],
            "Liaison": info["linking"] + (f" ({info['interpreter']})" if info["interpreter"] else ""),
            "Strippé": "Non (symboles présents)" if not info["stripped"] else "Oui",
            "BuildID": info["build_id"] or "absent",
            "Point d'entrée": info["entry_point"],
            "Entropie": f"{calculate_entropy(data):.2f}",
        }
        techniques: set[str] = set()

        for cap, syms in info["capabilities"].items():
            meta[f"Capacité : {cap}"] = ", ".join(syms)

        strings = [s for _, s in extract_strings_with_offsets(data, min_length=6)]
        software = _identify_software(strings)
        if software:
            meta["Identification"] = ", ".join(software)

        all_ips = {ip for s in strings for ip in _IP.findall(s)}
        ips = sorted(ip for ip in all_ips if not _is_benign_ip(ip))
        # Internes / réservées : trop banales pour une alerte (adresses par défaut de BusyBox...),
        # mais gardées : la corrélation les fait ressortir si une autre source les voit aussi
        internal_ips = sorted(ip for ip in all_ips if _is_benign_ip(ip) and ip not in _BENIGN_IPS
                              and not ip.startswith(("0.", "127.", "255.")))
        urls = sorted({u for s in strings for u in _URL.findall(s) if not _is_benign_url(u)})
        paths = _hidden_system_paths(strings)
        if ips:
            meta["[ALERTE] Adresses IP codées en dur"] = ", ".join(ips[:20])
        if internal_ips:
            meta["Adresses IP internes ou réservées"] = ", ".join(internal_ips[:20])
        if urls:
            meta["URLs"] = ", ".join(urls[:20])
        if paths:
            meta["[ALERTE] Chemins cachés / temporaires"] = ", ".join(paths[:20])
            techniques.add("T1564.001")
        if info["linking"] == "statique" and not info["stripped"] and (ips or paths):
            meta["Verdict"] = "Binaire statique autonome avec indicateurs réseau / fichiers cachés : à investiguer"

        behaviour = disasm.describe(disasm.analyze_elf(data) if info["machine"] in ("x86-64", "x86") else None,
                                    meta, techniques)

        capa = run_capa(path)
        if capa:
            meta["capa"] = ", ".join(capa["capabilities"][:15]) or "aucune capacité"
            techniques.update(capa["attack"])

        yara_hits = scan_yara(path)
        if yara_hits:
            meta["[ALERTE] YARA"] = ", ".join(h["rule"] for h in yara_hits)

        if techniques:
            meta["MITRE ATT&CK"] = mitre.summary(techniques)

        severity = "critique" if yara_hits else ("élevé" if ips or paths else "info")
        return FindingModel(
            type="elf_analysis",
            file=os.path.abspath(path),
            metadata=meta,
            extra={
                "elf": info,
                "iocs": {"ips": ips, "urls": urls, "paths": paths, "internal_ips": internal_ips},
                "yara": yara_hits,
                "disassembly": behaviour,
                "network": (behaviour or {}).get("summary", {}).get("endpoints", []),
                "capa": capa,
                "mitre": mitre.describe(techniques),
            },
            severity=severity,
        )
