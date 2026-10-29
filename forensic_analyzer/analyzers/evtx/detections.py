"""Détections sur les journaux d'événements Windows (Security, System, PowerShell, Sysmon).

Le détecteur reçoit les événements un par un (lecture en flux) et ne conserve que
des compteurs et des alertes bornées.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

SYSMON = "Microsoft-Windows-Sysmon"
MAX_ALERTS = 500
ADMIN_GROUPS = {"S-1-5-32-544", "S-1-5-32-555"}  # Administrateurs, Utilisateurs du Bureau à distance
_LOCAL_IPS = {"", "-", "::1", "127.0.0.1", "0.0.0.0"}

BRUTE_FORCE_THRESHOLD = 10     # échecs depuis une même source
SPRAY_USERS_THRESHOLD = 5      # comptes distincts visés depuis une même source

# Lignes de commande caractéristiques d'attaques (LOLBins, PowerShell offensif, destruction de sauvegardes)
_SUSPICIOUS_COMMANDS = [
    (re.compile(r"powershell[^\n]{0,80}\s-(e|en|enc|enco|encod|encode|encodedcommand)\s", re.I),
     "PowerShell encodé", "T1027"),
    (re.compile(r"(iex|invoke-expression)[\s(]|downloadstring|downloadfile|net\.webclient", re.I),
     "PowerShell : téléchargement / exécution en mémoire", "T1059.001"),
    (re.compile(r"certutil[^\n]{0,60}(-urlcache|-decode)", re.I), "certutil : téléchargement ou décodage", "T1105"),
    (re.compile(r"bitsadmin[^\n]{0,60}/transfer", re.I), "bitsadmin : téléchargement", "T1197"),
    (re.compile(r"mshta[^\n]{0,40}(https?:|javascript:|vbscript:)", re.I), "mshta : script distant", "T1218.005"),
    (re.compile(r"rundll32[^\n]{0,80}javascript:", re.I), "rundll32 : JavaScript", "T1218.011"),
    (re.compile(r"regsvr32[^\n]{0,60}/i:https?:", re.I), "regsvr32 : scriptlet distant (Squiblydoo)", "T1218.010"),
    (re.compile(r"vssadmin[^\n]{0,30}delete\s+shadows|wmic[^\n]{0,30}shadowcopy\s+delete|bcdedit[^\n]{0,40}recoveryenabled\s+no",
                re.I), "Suppression des copies de sauvegarde", "T1490"),
    (re.compile(r"wevtutil[^\n]{0,10}\s(cl|clear-log)\s", re.I), "Effacement de journal (wevtutil)", "T1070.001"),
    (re.compile(r"(mimikatz|sekurlsa|lsadump|procdump[^\n]{0,40}lsass|comsvcs[^\n]{0,40}minidump)", re.I),
     "Vol d'identifiants (LSASS)", "T1003.001"),
]
_SUSPICIOUS_SERVICE_PATH = re.compile(
    r"(cmd(\.exe)?\s*/c|powershell|%comspec%|\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\|"
    r"\\perflogs\\|mshta|rundll32|regsvr32|\.bat\b|\.ps1\b)", re.I)
_RUN_KEYS = re.compile(r"\\(currentversion\\(run|runonce|runservices)|winlogon\\(userinit|shell))", re.I)


def _user(data: dict) -> str:
    user = data.get("TargetUserName") or data.get("SubjectUserName") or ""
    domain = data.get("TargetDomainName") or ""
    return f"{domain}\\{user}" if domain and user and domain != "-" else user


def _ip(data: dict) -> str:
    ip = (data.get("IpAddress") or "").removeprefix("::ffff:")
    return "" if ip in _LOCAL_IPS else ip


class EventDetector:
    """Détections en flux ; `alerts` est borné à MAX_ALERTS."""

    def __init__(self) -> None:
        self.failures_by_source: Counter[str] = Counter()
        self.users_by_source: dict[str, set[str]] = defaultdict(set)
        self.alerts: list[dict] = []
        self.remote_logons: Counter[tuple[str, str, str]] = Counter()
        self.techniques: set[str] = set()
        self.counts: Counter[str] = Counter()

    def _alert(self, event: dict, kind: str, description: str, technique: str, severity: str = "haute") -> None:
        self.counts[kind] += 1
        self.techniques.add(technique)
        if len(self.alerts) < MAX_ALERTS:
            self.alerts.append({"timestamp": event.get("timestamp", ""), "event_id": event["event_id"],
                                "kind": kind, "description": description, "technique": technique,
                                "severity": severity, "computer": event.get("computer", "")})

    def feed(self, event: dict) -> None:
        eid, data, provider = event["event_id"], event.get("data", {}), event.get("provider", "")
        if provider.startswith(SYSMON):
            self._sysmon(event, eid, data)
            return

        if eid == 4625:
            source = _ip(data) or data.get("WorkstationName") or "local"
            self.failures_by_source[source] += 1
            self.users_by_source[source].add(_user(data).lower())
        elif eid == 4624:
            ip, logon_type = _ip(data), str(data.get("LogonType", ""))
            if ip and logon_type in ("3", "10"):
                self.remote_logons[(ip, _user(data), logon_type)] += 1
                if logon_type == "10":
                    self.techniques.add("T1021.001")
            if ip and self.failures_by_source.get(ip, 0) >= 5:
                self._alert(event, "success_after_failures",
                            f"Connexion reussie de {_user(data)} depuis {ip} apres "
                            f"{self.failures_by_source[ip]} echecs", "T1110", "critique")
        elif eid == 4648:
            target = data.get("TargetServerName", "")
            if target and target.lower() not in ("localhost", "-"):
                self.counts["explicit_credentials"] += 1
        elif eid in (1102, 104):
            self._alert(event, "log_cleared", f"Journal efface ({event.get('channel', '')})", "T1070.001", "critique")
        elif eid in (7045, 4697):
            name = data.get("ServiceName", "?")
            image = data.get("ImagePath") or data.get("ServiceFileName") or ""
            suspicious = bool(_SUSPICIOUS_SERVICE_PATH.search(image))
            self._alert(event, "service_installed", f"Service installe : {name} -> {image}", "T1543.003",
                        "critique" if suspicious else "moyenne")
        elif eid == 4698:
            self._alert(event, "scheduled_task", f"Tache planifiee creee : {data.get('TaskName', '?')}",
                        "T1053.005", "moyenne")
        elif eid == 4720:
            self._alert(event, "account_created", f"Compte cree : {_user(data)}", "T1136.001")
        elif eid in (4728, 4732, 4756) and data.get("TargetSid") in ADMIN_GROUPS:
            self._alert(event, "admin_group", f"{data.get('MemberName') or data.get('MemberSid', '?')} ajoute au groupe "
                                              f"{data.get('TargetUserName', '?')}", "T1098", "critique")
        elif eid == 4104:
            self._command(event, data.get("ScriptBlockText", ""), "Script PowerShell")
        elif eid == 4688:
            self._command(event, data.get("CommandLine") or data.get("NewProcessName", ""), "Processus")

    def _sysmon(self, event: dict, eid: int, data: dict) -> None:
        if eid == 1:
            self._command(event, data.get("CommandLine", ""), f"Processus (parent {data.get('ParentImage', '?')})")
        elif eid == 3:
            ip = data.get("DestinationIp", "")
            if ip and ip not in _LOCAL_IPS and data.get("Initiated", "true").lower() == "true":
                self.counts["sysmon_network"] += 1
                if _SUSPICIOUS_SERVICE_PATH.search(data.get("Image", "")):
                    self._alert(event, "network_from_suspicious_path",
                                f"{data.get('Image')} -> {ip}:{data.get('DestinationPort', '?')}", "T1071")
        elif eid in (12, 13, 14) and _RUN_KEYS.search(data.get("TargetObject", "")):
            self._alert(event, "registry_persistence",
                        f"Cle de demarrage modifiee : {data.get('TargetObject')} = {data.get('Details', '')}",
                        "T1547.001")

    def _command(self, event: dict, command: str, label: str) -> None:
        for pattern, description, technique in _SUSPICIOUS_COMMANDS:
            if pattern.search(command or ""):
                self._alert(event, "suspicious_command", f"{label} : {description} - {command[:300]}", technique)
                break

    def finish(self) -> None:
        """Détections agrégées (force brute, pulvérisation) une fois tous les événements lus."""
        for source, count in self.failures_by_source.items():
            users = self.users_by_source[source]
            if len(users) >= SPRAY_USERS_THRESHOLD:
                self._alert({"event_id": 4625}, "password_spraying",
                            f"Pulverisation de mots de passe depuis {source} : {count} echecs sur {len(users)} comptes",
                            "T1110.003", "critique")
            elif count >= BRUTE_FORCE_THRESHOLD:
                self._alert({"event_id": 4625}, "brute_force",
                            f"Force brute depuis {source} : {count} echecs ({', '.join(sorted(users))[:120]})",
                            "T1110.001", "critique")
        if self.remote_logons:
            self.techniques.add("T1078")
