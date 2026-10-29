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
        ips = sorted({ip for s in strings for ip in _IP.findall(s)} - _BENIGN_IPS)
        urls = sorted({u for s in strings for u in _URL.findall(s)})
        paths = _hidden_system_paths(strings)
        if ips:
            meta["[ALERTE] Adresses IP codées en dur"] = ", ".join(ips[:20])
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

        return FindingModel(
            type="elf_analysis",
            file=os.path.abspath(path),
            metadata=meta,
            extra={
                "elf": info,
                "iocs": {"ips": ips, "urls": urls, "paths": paths},
                "yara": yara_hits,
                "disassembly": behaviour,
                "network": (behaviour or {}).get("summary", {}).get("endpoints", []),
                "capa": capa,
                "mitre": mitre.describe(techniques),
            },
        )
