"""Règles de détection (YARA, Suricata, Sigma) et partage STIX 2.1 à partir des indicateurs trouvés.

Les indicateurs proviennent de tous les analyzers (core.iocs) ; les règles réseau
utilisent les destinations reconstruites par désassemblage (IP + port).
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import uuid

from forensic_analyzer.core import iocs as ioc_mod
from forensic_analyzer.core import mitre
from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.utils.logger import get_logger

logger = get_logger("forensic.rules")

_INTERNAL = [ipaddress.ip_network(n) for n in
             ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8")]
_BINARY_TYPES = {"elf_analysis": ("ELF", "uint32(0) == 0x464c457f"),
                 "malware_analysis": ("PE", "uint16(0) == 0x5a4d")}
_SID_BASE = 9_100_000


def _external_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not any(ip in net for net in _INTERNAL)


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", text).strip("_")[:60] or "artefact"


def _suricata_content(text: str) -> str:
    """Caractères réservés d'un content Suricata en hexadécimal."""
    return text.replace('"', "|22|").replace(";", "|3B|").replace("\\", "|5C|")


def _yara_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


class DefenseRulesGenerator:
    """Génère YARA, Suricata, Sigma et STIX 2.1 depuis le rapport complet."""

    def generate(self, report: ReportModel, output_dir: str = "rules_export") -> dict[str, str]:
        findings = [f for f in report.findings if f.type not in ("timeline",)]
        all_iocs = ioc_mod.collect(findings)
        malicious = [f for f in findings if f.type in _BINARY_TYPES and _is_suspicious_binary(f)]
        if not all_iocs and not malicious:
            logger.info("Aucun indicateur exploitable : pas de règle générée.")
            return {}

        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "sigma"), exist_ok=True)
        outputs = {
            "yara": self._write(output_dir, "forensic_analyzer.yar", self.yara(malicious)),
            "suricata": self._write(output_dir, "forensic_analyzer.rules", self.suricata(all_iocs, findings)),
            "stix": self._write(output_dir, "stix_bundle.json", json.dumps(self.stix(all_iocs, findings, malicious),
                                                                          indent=2, ensure_ascii=False)),
        }
        for name, content in self.sigma(all_iocs, findings).items():
            outputs[f"sigma/{name}"] = self._write(os.path.join(output_dir, "sigma"), name, content)
        logger.info("Règles de détection et bundle STIX exportés dans %s", output_dir)
        return {k: v for k, v in outputs.items() if v}

    @staticmethod
    def _write(directory: str, name: str, content: str) -> str:
        if not content:
            return ""
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    # YARA

    def yara(self, binaries: list[FindingModel]) -> str:
        """Une règle par binaire suspect : chaînes distinctives + en-tête du format, et ses empreintes."""
        rules = ['/*\n  Regles YARA generees par Forensic Analyzer\n*/\n\nimport "hash"\n']
        hashes = []
        names: set[str] = set()
        for f in binaries:
            fmt, magic = _BINARY_TYPES[f.type]
            # Logiciel identifié (BusyBox...) : ses chaînes sont celles de toute installation légitime,
            # seule l'empreinte désigne ce fichier
            strings = [] if f.metadata.get("Identification") else _distinctive_strings(f)
            name = _slug(os.path.basename(f.metadata.get("Origine (image)", "").split(":")[-1] or f.file))
            sha256 = f.metadata.get("SHA-256", "")
            if sha256:
                if sha256.lower() in hashes:
                    continue  # même binaire vu deux fois
                hashes.append(sha256.lower())
            if not strings:
                continue
            base, n = name, 2
            while name in names:
                name, n = f"{base}_{n}", n + 1
            names.add(name)
            modifiers = "ascii wide" if fmt == "PE" else "ascii"
            lines = [f'        $s{i} = "{_yara_escape(s)}" {modifiers}' for i, s in enumerate(strings)]
            # Chaînes propres au binaire : toutes requises (au plus 3), sinon la règle reconnaîtrait d'autres binaires
            strings = strings[:3]
            lines = lines[:3]
            needed = "all"
            rules.append(
                f"rule FA_{fmt}_{name} {{\n"
                f"    meta:\n"
                f'        description = "Binaire {fmt} suspect identifie par Forensic Analyzer"\n'
                f'        source = "{_yara_escape(os.path.basename(f.file))}"\n'
                f'        sha256 = "{sha256}"\n'
                f"    strings:\n" + "\n".join(lines) + "\n"
                f"    condition:\n        {magic} and {needed} of them\n}}\n")
        if hashes:
            conditions = " or\n        ".join(f'hash.sha256(0, filesize) == "{h}"' for h in sorted(set(hashes)))
            rules.append("rule FA_Known_Hashes {\n    meta:\n        description = \"Empreintes des binaires suspects analyses\"\n"
                         f"    condition:\n        {conditions}\n}}\n")
        return "\n".join(rules) if len(rules) > 1 else ""

    # Suricata

    def suricata(self, all_iocs: list[ioc_mod.IOC], findings: list[FindingModel]) -> str:
        rules, sid = [], _SID_BASE
        endpoints = {(e.get("host"), e.get("port")) for f in findings for e in f.extra.get("network", [])
                     if e.get("host") and _external_ip(e["host"])}
        for host, port in sorted(endpoints, key=str):
            rules.append(f'alert tcp $HOME_NET any -> {host} {port or "any"} (msg:"FA - Balise vers C2 {host}:{port or "any"}"; '
                         f'flow:to_server; flags:S; classtype:trojan-activity; sid:{sid}; rev:1;)')
            sid += 1
        # Comportements observés dans le PCAP : balise sortante et brute-force de formulaire
        beacons = {(b["destination"], b["port"], b["uri"].split("?")[0]) for f in findings
                   for b in f.extra.get("http_attack", {}).get("beacons", []) if b.get("outbound")}
        for host, port, uri in sorted(beacons, key=str):
            rules.append(f'alert http $HOME_NET any -> {host} {port} (msg:"FA - Balise C2 HTTP vers {host}:{port}"; '
                         f'flow:to_server,established; http.uri; content:"{_suricata_content(uri)}"; startswith; '
                         f'classtype:trojan-activity; sid:{sid}; rev:1;)')
            sid += 1
        login_uris = {f.extra["http_attack"]["successful_logins"][0]["uri"] if f.extra.get("http_attack", {}).get("successful_logins")
                      else "/wp-login.php" for f in findings if f.extra.get("http_attack", {}).get("brute_force")}
        for uri in sorted(login_uris):
            rules.append(f'alert http any any -> $HOME_NET any (msg:"FA - Brute-force sur {_suricata_content(uri)}"; '
                         f'flow:to_server,established; http.method; content:"POST"; http.uri; content:"{_suricata_content(uri)}"; '
                         f'threshold:type both, track by_src, count 20, seconds 60; classtype:attempted-user; sid:{sid}; rev:1;)')
            sid += 1
        covered = {h for h, _p in endpoints}
        for i in all_iocs:
            if i.kind == "ipv4" and _external_ip(i.value) and i.value not in covered:
                contexts = " ".join(o.context.lower() for o in i.observations)
                is_suspect_or_threat = any(k in contexts for k in (
                    "c2", "balise", "alerte", "scan", "brute-force", "attaque", "suspect", "exfiltration", "webshell",
                    "offensi", "cron"
                )) or not contexts
                if not is_suspect_or_threat:
                    continue
                # Dans les deux sens : un attaquant externe initie souvent lui-même la connexion
                rules.append(f'alert ip {i.value} any <> $HOME_NET any (msg:"FA - Trafic avec IP suspecte {i.value}"; '
                             f'classtype:trojan-activity; sid:{sid}; rev:1;)')
            elif i.kind == "domain":
                rules.append(f'alert dns $HOME_NET any -> any any (msg:"FA - Résolution du domaine suspect {i.value}"; '
                             f'dns.query; content:"{i.value}"; nocase; endswith; classtype:trojan-activity; sid:{sid}; rev:1;)')
            elif i.kind == "url":
                host = re.sub(r"^https?://", "", i.value, flags=re.I).split("/")[0].split(":")[0]
                path = re.sub(r"^https?://[^/]+", "", i.value) or "/"
                if path == "/" and not _external_ip(host):
                    continue  # tout le trafic HTTP vers un hôte interne : règle sans valeur de détection
                uri = f' http.uri; content:"{_suricata_content(path[:200])}";' if path != "/" else ""
                rules.append(f'alert http any any -> any any (msg:"FA - Requête vers URL suspecte {_suricata_content(host)}"; '
                             f'http.host; content:"{_suricata_content(host)}"; nocase;{uri} classtype:trojan-activity; sid:{sid}; rev:1;)')
            elif i.kind == "ja3":
                rules.append(f'alert tls $HOME_NET any -> any any (msg:"FA - Empreinte JA3 suspecte"; '
                             f'ja3.hash; content:"{i.value}"; classtype:trojan-activity; sid:{sid}; rev:1;)')
            else:
                continue
            sid += 1
        header = "# Regles Suricata generees par Forensic Analyzer\n"
        return header + "\n".join(rules) + "\n" if rules else ""

    # Sigma

    def sigma(self, all_iocs: list[ioc_mod.IOC], findings: list[FindingModel]) -> dict[str, str]:
        rules: dict[str, str] = {}
        linux_paths = sorted({i.value for i in all_iocs if i.kind == "path" and i.value.startswith("/")})
        windows_paths = sorted({i.value for i in all_iocs if i.kind == "path" and re.match(r"^[A-Za-z]:\\", i.value)})
        hidden_bins = [p for p in linux_paths if any(c.startswith(".") for c in p.split("/")[:-1])]
        units = sorted({i.value for i in all_iocs if i.kind == "service" and i.value.endswith(".service")})
        win_services = sorted({i.value for i in all_iocs if i.kind == "service" and not i.value.endswith(".service")})
        tags = _tags(findings, _LINUX_TYPES)
        win_tags = _tags(findings, _WINDOWS_TYPES)

        if hidden_bins:
            rules["linux_process_hidden_path.yml"] = _sigma(
                "Exécution d'un binaire suspect identifié par Forensic Analyzer",
                {"product": "linux", "category": "process_creation"},
                {"selection": {"Image": hidden_bins}}, "selection", tags, "high")
        if linux_paths:
            rules["linux_file_event_iocs.yml"] = _sigma(
                "Création d'un fichier d'implant ou de persistance connu",
                {"product": "linux", "category": "file_event"},
                {"selection": {"TargetFilename": linux_paths}}, "selection", tags, "high")
        if units:
            rules["linux_auditd_service_start.yml"] = _sigma(
                "Démarrage d'une unité systemd malveillante",
                {"product": "linux", "service": "auditd"},
                {"selection": {"type": "SERVICE_START", "unit": [u.removesuffix(".service") for u in units]}},
                "selection", tags, "critical")
        if windows_paths:
            rules["windows_process_iocs.yml"] = _sigma(
                "Exécution ou création d'un fichier suspect (Windows)",
                {"product": "windows", "category": "process_creation"},
                {"selection_image": {"Image|endswith": [ntname(p) for p in windows_paths]},
                 "selection_cmd": {"CommandLine|contains": windows_paths}},
                "1 of selection_*", win_tags, "high")
        if win_services:
            rules["windows_service_install.yml"] = _sigma(
                "Installation d'un service suspect",
                {"product": "windows", "service": "system"},
                {"selection": {"EventID": 7045, "ServiceName": win_services}}, "selection", win_tags, "high")
        commands = sorted({c for f in findings for c in f.extra.get("disassembly", {}).get("summary", {}).get("commands", [])})
        if commands:
            rules["windows_command_from_implant.yml"] = _sigma(
                "Commande codée en dur dans un binaire suspect",
                {"product": "windows", "category": "process_creation"},
                {"selection": {"CommandLine|contains": commands}}, "selection", win_tags, "high")
        return rules

    # STIX 2.1

    def stix(self, all_iocs: list[ioc_mod.IOC], findings: list[FindingModel], malicious: list[FindingModel]) -> dict:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        identity = {"type": "identity", "spec_version": "2.1", "id": f"identity--{uuid.uuid4()}",
                    "created": now, "modified": now, "name": "Forensic Analyzer", "identity_class": "system"}
        objects = [identity]

        def sdo(kind: str, **fields) -> dict:
            obj = {"type": kind, "spec_version": "2.1", "id": f"{kind}--{uuid.uuid4()}", "created": now,
                   "modified": now, "created_by_ref": identity["id"], **fields}
            objects.append(obj)
            return obj

        malware_objs = [sdo("malware", name=os.path.basename(f.metadata.get("Origine (image)", "").split(":")[-1] or f.file),
                            is_family=False, malware_types=["backdoor" if f.extra.get("network") else "unknown"],
                            description=f.metadata.get("[ALERTE] Comportement", f.metadata.get("Verdict", "")))
                        for f in malicious]
        endpoints = {(e["host"], e.get("port")) for f in findings for e in f.extra.get("network", []) if e.get("host")}
        for host, port in sorted(endpoints, key=str):
            pattern = f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{host}'"
            pattern += f" AND network-traffic:dst_port = {port}]" if port else "]"
            ind = sdo("indicator", name=f"Balise vers {host}:{port}", pattern=pattern, pattern_type="stix",
                      valid_from=now, indicator_types=["malicious-activity"])
            for m in malware_objs:
                sdo("relationship", relationship_type="indicates", source_ref=ind["id"], target_ref=m["id"])

        patterns = {
            "ipv4": "[ipv4-addr:value = '{}']", "domain": "[domain-name:value = '{}']", "url": "[url:value = '{}']",
            "sha256": "[file:hashes.'SHA-256' = '{}']", "md5": "[file:hashes.MD5 = '{}']",
            "path": "[file:name = '{}']", "filename": "[file:name = '{}']",
        }
        for i in all_iocs:
            if i.kind not in patterns or (i.kind == "ipv4" and not _external_ip(i.value)):
                continue
            value = os.path.basename(i.value) if i.kind == "path" else i.value
            ind = sdo("indicator", name=f"{i.kind} : {i.value}"[:250],
                      description="Observé dans : " + ", ".join(sorted(i.sources)),
                      pattern=patterns[i.kind].format(value.replace("\\", "\\\\").replace("'", "\\'")),
                      pattern_type="stix", valid_from=now, indicator_types=["malicious-activity"])
            if i.kind in ("sha256", "md5"):
                for m in malware_objs:
                    sdo("relationship", relationship_type="indicates", source_ref=ind["id"], target_ref=m["id"])

        techniques = {t["id"] for f in findings for t in f.extra.get("mitre", []) if isinstance(t, dict)}
        for t in mitre.describe(techniques):
            ap = sdo("attack-pattern", name=t["name"], external_references=[{
                "source_name": "mitre-attack", "external_id": t["id"],
                "url": f"https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/"}])
            for m in malware_objs:
                sdo("relationship", relationship_type="uses", source_ref=m["id"], target_ref=ap["id"])
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


_LINUX_TYPES = {"linux_artifacts", "elf_analysis", "memory", "disk"}
_WINDOWS_TYPES = {"malware_analysis", "evtx", "registry", "prefetch", "lnk_shortcut", "chromium_artifacts"}


def _tags(findings: list[FindingModel], types: set[str]) -> list[str]:
    """Tags ATT&CK Sigma issus des résultats d'une plateforme."""
    ids = {t["id"] for f in findings if f.type in types for t in f.extra.get("mitre", []) if isinstance(t, dict)}
    return [f"attack.{t.lower()}" for t in sorted(ids)]


def ntname(path: str) -> str:
    return path.rsplit("\\", 1)[-1]


def _is_suspicious_binary(f: FindingModel) -> bool:
    """Alerte explicite, YARA, ou profil de porte dérobée : réseau + exécution de commandes."""
    if any(k.startswith("[ALERTE]") for k in f.metadata) or f.extra.get("yara") or f.extra.get("yara_matches"):
        return True
    caps = " ".join(k for k in f.metadata if k.startswith("Capacité"))
    return "réseau" in caps.lower() and "exécution de commandes" in caps.lower()


_GENERIC_STRINGS = {
    "/dev/null", "/dev/tty", "/dev/console", "/dev/urandom", "/dev/random", "/dev/zero",
    "/proc/self", "/proc/self/exe", "/proc/self/maps", "/proc/cpuinfo", "/etc/resolv.conf",
    "/bin/sh", "/bin/bash", "/usr/bin/env", "cmd.exe", "powershell.exe",
}


def _distinctive_strings(f: FindingModel) -> list[str]:
    """Chaînes propres au binaire : IP, chemins cachés, fichiers et commandes reconstruits."""
    summary = f.extra.get("disassembly", {}).get("summary", {}) if f.extra.get("disassembly") else {}
    candidates = [*f.extra.get("iocs", {}).get("ips", []), *f.extra.get("iocs", {}).get("paths", []),
                  *[e["host"] for e in summary.get("endpoints", []) if e.get("host")],
                  *summary.get("files", []), *summary.get("commands", []), *summary.get("urls", [])]
    seen, strings = set(), []
    for s in candidates:
        if not s or len(s) < 6:
            continue
        s_clean = s.strip()
        if s_clean in _GENERIC_STRINGS or s_clean.startswith(("/dev/", "/proc/", "/sys/")):
            continue
        if any(lib in s_clean.lower() for lib in ("libc.so", "ld-linux", "glibc", "uclibc", "musl")):
            continue
        if s_clean not in seen:
            seen.add(s_clean)
            strings.append(s_clean)
    return strings[:10]


def _sigma(title: str, logsource: dict, detection: dict, condition: str, tags: list[str], level: str) -> str:
    """Règle Sigma en YAML (écrite sans dépendance)."""
    def scalar(v):
        if isinstance(v, int):
            return str(v)
        return "'" + str(v).replace("'", "''") + "'"

    lines = [f"title: {title}", f"id: {uuid.uuid4()}", "status: experimental",
             "description: Règle générée automatiquement par Forensic Analyzer à partir des indicateurs de l'enquête",
             "author: Forensic Analyzer", f"date: {datetime.date.today():%Y-%m-%d}"]
    if tags:
        lines.append("tags:")
        lines += [f"    - {t}" for t in tags]
    lines.append("logsource:")
    lines += [f"    {k}: {v}" for k, v in logsource.items()]
    lines.append("detection:")
    for name, fields in detection.items():
        lines.append(f"    {name}:")
        for field, value in fields.items():
            if isinstance(value, list):
                lines.append(f"        {field}:")
                lines += [f"            - {scalar(v)}" for v in value]
            else:
                lines.append(f"        {field}: {scalar(value)}")
    lines.append(f"    condition: {condition}")
    lines.append("falsepositives:\n    - Inconnus (indicateurs propres à l'incident)")
    lines.append(f"level: {level}")
    return "\n".join(lines) + "\n"
