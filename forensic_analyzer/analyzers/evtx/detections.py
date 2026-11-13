"""Détections sur les journaux d'événements Windows (Security, System, PowerShell, Sysmon, Defender).

Le détecteur reçoit les événements un par un (lecture en flux) et ne conserve que
des compteurs, des tables de suivi bornées et des alertes bornées.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from collections import Counter, defaultdict
from collections.abc import Callable

from . import rules
from .rules import CRIT, HIGH, LOW, MED

SYSMON = "Microsoft-Windows-Sysmon"
DEFENDER = "Microsoft-Windows-Windows Defender"
RDP_CONNECTION_MANAGER = "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
MAX_ALERTS = 500
MAX_TRACKED = 20_000  # clés par table de suivi : borne mémoire face à un journal hostile ou gigantesque
_LOCAL_IPS = {"", "-", "::1", "127.0.0.1", "0.0.0.0"}  # nosec B104 - constante de détection, aucun socket ouvert
# Comptes de service intégrés : leurs logons sont du bruit système
_BUILTIN_ACCOUNTS = {"", "-", "system", "local service", "network service", "anonymous logon", "autorite nt\\system"}
ADMIN_GROUPS = rules.PRIVILEGED_LOCAL_SIDS  # compatibilité

# Seuils (choisis au-dessus du bruit d'un parc normal ; cf. Sigma / Hayabusa)
BRUTE_FORCE_THRESHOLD = 10  # échecs depuis une même source
SPRAY_USERS_THRESHOLD = 5  # comptes distincts visés depuis une même source
SUCCESS_AFTER_FAILURES = 5  # échecs préalables avant un succès depuis la même source
LATERAL_HOSTS_THRESHOLD = 3  # hôtes distincts atteints par un même compte (réseau / RDP)
EXPLICIT_TARGETS_THRESHOLD = 3  # serveurs distincts visés en 4648 par un même compte
KERBEROAST_SPN_THRESHOLD = 3  # services RC4 distincts demandés par un même compte
LATERAL_CHAIN_SECONDS = 600  # logon réseau puis service installé sur le même hôte (PsExec, JPCERT)

# Valeurs de champs
REMOTE_LOGON_TYPES = {"3": "réseau", "10": "RDP"}
NEW_CREDENTIALS_LOGON = "9"  # runas /netonly, Overpass-the-Hash (Mimikatz sekurlsa::pth)
KERBEROS_SUCCESS = "0x0"
KERBEROS_PREAUTH_FAILED = "0x18"
NO_PREAUTH = "0"
AUDIT_REMOVED = ("%%8448", "%%8450")  # « Succès supprimé », « Échec supprimé » (4719)
DISABLED_START = re.compile(r"disabled|désactivé", re.I)
PROTECTED_SERVICES = re.compile(r"windows defender|microsoft defender|windefend|event ?log|journal d.événements|sysmon", re.I)
TASK_COMMAND = re.compile(r"<(Command|Arguments)>([^<]{1,1024})</\1>", re.I)

_UTC = datetime.UTC


def to_utc(ts: str) -> str:
    """Horodatage EVTX (« 2024-01-02 03:04:05.123456 », « …Z », 7 décimales) → ISO 8601 UTC."""
    dt = parse_time(ts)
    return dt.isoformat() if dt else (ts or "")


def parse_time(ts: str) -> datetime.datetime | None:
    if not ts:
        return None
    text = ts.strip().replace("Z", "+00:00")
    # Windows écrit 7 décimales : on tronque à la microseconde
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=_UTC)).astimezone(_UTC)


def _user(data: dict) -> str:
    user = data.get("TargetUserName") or data.get("SubjectUserName") or ""
    domain = data.get("TargetDomainName") or ""
    return f"{domain}\\{user}" if domain and user and domain != "-" else user


def _is_noise_account(user: str) -> bool:
    """Compte machine (`HOST$`), SYSTEM, services intégrés, DWM/UMFD : pas d'intérêt pour la chasse."""
    name = (user or "").lower()
    short = name.rsplit("\\", 1)[-1]
    return short.endswith("$") or name in _BUILTIN_ACCOUNTS or short in _BUILTIN_ACCOUNTS or short.startswith(("dwm-", "umfd-"))


def _ip(data: dict, key: str = "IpAddress") -> str:
    ip = (data.get(key) or "").removeprefix("::ffff:")
    return "" if ip in _LOCAL_IPS else ip


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _track(table: dict, key, value) -> None:
    """Ajoute `value` à l'ensemble `table[key]` sans dépasser MAX_TRACKED clés."""
    if key in table or len(table) < MAX_TRACKED:
        table[key].add(value)


class EventDetector:
    """Détections en flux ; `alerts` est borné à MAX_ALERTS, les doublons sont comptés (`count`)."""

    def __init__(self) -> None:
        self.failures_by_source: Counter[str] = Counter()
        self.users_by_source: dict[str, set[str]] = defaultdict(set)
        self.first_seen: dict[str, str] = {}
        self.alerts: list[dict] = []
        self._index: dict[tuple[str, str], int] = {}
        self.remote_logons: Counter[tuple[str, str, str]] = Counter()
        self.techniques: set[str] = set()
        self.counts: Counter[str] = Counter()
        self.hosts_by_user: dict[str, set[str]] = defaultdict(set)
        self.explicit_targets: dict[str, set[str]] = defaultdict(set)
        self.rc4_services: dict[str, set[str]] = defaultdict(set)
        self.created_accounts: set[str] = set()
        self.last_network_logon: dict[str, tuple[datetime.datetime, str, str]] = {}
        self._security: dict[int, Callable[[dict, dict], None]] = {
            4625: self._failed_logon,
            4771: self._failed_logon,
            4624: self._logon,
            4648: self._explicit_credentials,
            4672: self._special_privileges,
            1102: self._log_cleared,
            104: self._log_cleared,
            4719: self._audit_policy,
            7045: self._service,
            4697: self._service,
            7040: self._service_start_type,
            4698: self._scheduled_task,
            4702: self._scheduled_task,
            4720: self._account_created,
            4722: self._account_enabled,
            4728: self._group_member,
            4732: self._group_member,
            4756: self._group_member,
            4769: self._service_ticket,
            4768: self._tgt_request,
            4662: self._directory_access,
            5140: self._share_access,
            4104: self._script_block,
            4688: self._process_created,
        }
        self._sysmon_handlers: dict[int, Callable[[dict, dict], None]] = {
            1: self._sysmon_process,
            3: self._sysmon_network,
            8: self._sysmon_remote_thread,
            10: self._sysmon_process_access,
            11: self._sysmon_file,
            12: self._sysmon_registry,
            13: self._sysmon_registry,
            14: self._sysmon_registry,
            22: self._sysmon_dns,
        }
        self._defender: dict[int, Callable[[dict, dict], None]] = {
            1116: self._defender_threat,
            1117: self._defender_threat,
            5001: self._defender_disabled,
            5010: self._defender_disabled,
            5012: self._defender_disabled,
            5007: self._defender_config,
        }

    # -- Infrastructure -------------------------------------------------------------------------

    def _alert(self, event: dict, kind: str, description: str, technique: str | tuple[str, ...], severity: str = HIGH) -> None:
        techniques = (technique,) if isinstance(technique, str) else tuple(technique)
        self.counts[kind] += 1
        self.techniques.update(t for t in techniques if t)
        key = (kind, description[:200])
        if key in self._index:
            self.alerts[self._index[key]]["count"] += 1
            return
        if len(self.alerts) < MAX_ALERTS:
            self._index[key] = len(self.alerts)
            self.alerts.append(
                {
                    "timestamp": to_utc(event.get("timestamp", "")),
                    "event_id": event.get("event_id", 0),
                    "kind": kind,
                    "description": description,
                    "technique": ", ".join(techniques),
                    "techniques": list(techniques),
                    "severity": severity,
                    "computer": event.get("computer", ""),
                    "count": 1,
                }
            )

    def feed(self, event: dict) -> None:
        eid, data, provider = event["event_id"], event.get("data", {}), event.get("provider", "")
        if provider.startswith(SYSMON):
            table = self._sysmon_handlers
        elif provider.startswith(DEFENDER):
            table = self._defender
        elif provider.startswith(RDP_CONNECTION_MANAGER):
            table = {1149: self._rdp_authenticated}
        else:
            table = self._security
        handler = table.get(eid)
        if handler:
            handler(event, data)

    # -- Authentification -----------------------------------------------------------------------

    def _failed_logon(self, event: dict, data: dict) -> None:
        if event["event_id"] == 4771 and data.get("Status", "").lower() != KERBEROS_PREAUTH_FAILED:
            return  # 4771 : seul le mauvais mot de passe (0x18) relève de la force brute
        source = _ip(data) or data.get("WorkstationName") or "local"
        if source not in self.failures_by_source and len(self.failures_by_source) >= MAX_TRACKED:
            return
        self.failures_by_source[source] += 1
        self.users_by_source[source].add(_user(data).lower())
        self.first_seen.setdefault(f"fail:{source}", event.get("timestamp", ""))

    def _logon(self, event: dict, data: dict) -> None:
        ip, logon_type, user = _ip(data), str(data.get("LogonType", "")), _user(data)
        if logon_type == NEW_CREDENTIALS_LOGON and data.get("LogonProcessName", "").strip().lower() == "seclogo":
            self._alert(
                event,
                "overpass_the_hash",
                f"Logon type 9 (seclogo) pour {user} : identifiants injectés (runas /netonly ou Overpass-the-Hash)",
                "T1550.002",
                MED,
            )
        if not ip or logon_type not in REMOTE_LOGON_TYPES:
            return
        if self.failures_by_source.get(ip, 0) >= SUCCESS_AFTER_FAILURES:
            self._alert(
                event,
                "success_after_failures",
                f"Connexion réussie de {user} depuis {ip} après {self.failures_by_source[ip]} échecs",
                "T1110",
                CRIT,
            )
        if _is_noise_account(user):
            return  # comptes machine et ANONYMOUS LOGON : trafic de domaine normal
        self.remote_logons[(ip, user, logon_type)] += 1
        _track(self.hosts_by_user, user.lower(), event.get("computer", "").lower())
        self.first_seen.setdefault(f"spread:{user.lower()}", event.get("timestamp", ""))
        dt = parse_time(event.get("timestamp", ""))
        if dt and logon_type == "3" and len(self.last_network_logon) < MAX_TRACKED:
            self.last_network_logon[event.get("computer", "").lower()] = (dt, user, ip)
        if logon_type == "10":
            self.techniques.add("T1021.001")
            if _is_public(ip):
                self._alert(event, "rdp_from_internet", f"RDP de {user} depuis l'adresse publique {ip}", ("T1021.001", "T1133"))
        self._pass_the_hash(event, data, user, ip)

    def _pass_the_hash(self, event: dict, data: dict, user: str, ip: str) -> None:
        # Sigma « Pass the Hash Activity 2 » : NTLM réseau sans clé de session
        if (
            data.get("LogonType") == "3"
            and data.get("LogonProcessName", "").strip().lower() == "ntlmssp"
            and data.get("KeyLength") == "0"
            and data.get("SubjectUserSid") == "S-1-0-0"
        ):
            self._alert(event, "pass_the_hash", f"Logon NTLM réseau sans clé de session : {user} depuis {ip}", "T1550.002", MED)

    def _rdp_authenticated(self, event: dict, data: dict) -> None:
        ip, user = (data.get("Param3") or "").strip(), data.get("Param1") or ""
        if ip and ip not in _LOCAL_IPS and not _is_noise_account(user):
            self.remote_logons[(ip, user, "RDP")] += 1
            self.techniques.add("T1021.001")

    def _explicit_credentials(self, event: dict, data: dict) -> None:
        target = (data.get("TargetServerName") or "").lower()
        subject = data.get("SubjectUserName", "")
        if not target or target in ("localhost", "-") or _is_noise_account(subject):
            return
        self.counts["explicit_credentials"] += 1
        _track(self.explicit_targets, subject.lower(), target)
        self.first_seen.setdefault(f"explicit:{subject.lower()}", event.get("timestamp", ""))

    def _special_privileges(self, event: dict, data: dict) -> None:
        user = (data.get("SubjectUserName") or "").lower()
        if user and user in self.created_accounts:
            self._alert(
                event,
                "new_account_privileged",
                f"Compte créé dans ce journal puis connecté avec des privilèges spéciaux : {user}",
                ("T1136.001", "T1078"),
                CRIT,
            )

    def _service_ticket(self, event: dict, data: dict) -> None:
        service = data.get("ServiceName", "")
        if (
            data.get("TicketEncryptionType", "").lower() in rules.WEAK_KERBEROS_ETYPES
            and data.get("Status", KERBEROS_SUCCESS).lower() == KERBEROS_SUCCESS
            and not service.endswith("$")
            and service.lower() != "krbtgt"
        ):
            requester = _user(data).lower()
            if _is_noise_account(requester):
                return
            _track(self.rc4_services, requester, service.lower())
            self.first_seen.setdefault(f"rc4:{requester}", event.get("timestamp", ""))

    def _tgt_request(self, event: dict, data: dict) -> None:
        user = data.get("TargetUserName", "")
        if (
            data.get("PreAuthType") == NO_PREAUTH
            and data.get("Status", KERBEROS_SUCCESS).lower() == KERBEROS_SUCCESS
            and not _is_noise_account(user)
        ):
            self._alert(
                event,
                "asrep_roasting",
                f"TGT délivré sans pré-authentification pour {user} depuis {_ip(data) or '?'} (AS-REP roasting)",
                "T1558.004",
            )

    def _directory_access(self, event: dict, data: dict) -> None:
        props = (data.get("Properties") or "").lower()
        subject = data.get("SubjectUserName", "")
        if (
            data.get("AccessMask", "").lower() == rules.CONTROL_ACCESS_MASK
            and any(g in props for g in rules.REPLICATION_GUIDS)
            and not _is_noise_account(subject)  # les contrôleurs de domaine répliquent avec leur compte machine
        ):
            self._alert(event, "dcsync", f"Réplication d'annuaire demandée par {subject} (DCSync)", "T1003.006", CRIT)

    # -- Comptes et groupes ---------------------------------------------------------------------

    def _account_created(self, event: dict, data: dict) -> None:
        name = data.get("TargetUserName", "?")
        self.created_accounts.add(name.lower())
        hidden = name.endswith("$")
        self._alert(
            event,
            "account_created",
            f"Compte créé : {_user(data)} par {data.get('SubjectUserName', '?')}"
            + (" (nom en $ : compte caché)" if hidden else ""),
            ("T1136.001", "T1564.002") if hidden else "T1136.001",
            CRIT if hidden else HIGH,
        )

    def _account_enabled(self, event: dict, data: dict) -> None:
        if (data.get("TargetSid") or "").endswith(rules.DEFAULT_DISABLED_RIDS):
            self._alert(event, "builtin_account_enabled", f"Compte intégré réactivé : {_user(data)}", "T1078.001")

    def _group_member(self, event: dict, data: dict) -> None:
        sid = data.get("TargetSid") or ""
        if sid in rules.PRIVILEGED_LOCAL_SIDS or sid.endswith(rules.PRIVILEGED_DOMAIN_RIDS):
            self._alert(
                event,
                "admin_group",
                f"{data.get('MemberName') or data.get('MemberSid', '?')} ajouté au groupe {data.get('TargetUserName', '?')}"
                f" par {data.get('SubjectUserName', '?')}",
                "T1098",
                CRIT,
            )

    # -- Persistance et évasion -----------------------------------------------------------------

    def _log_cleared(self, event: dict, data: dict) -> None:
        who = data.get("SubjectUserName") or data.get("ClientProcessId") or ""
        self._alert(event, "log_cleared", f"Journal effacé ({event.get('channel', '')}) {who}".strip(), "T1070.001", CRIT)

    def _audit_policy(self, event: dict, data: dict) -> None:
        changes = data.get("AuditPolicyChanges", "")
        if any(code in changes for code in AUDIT_REMOVED):
            self._alert(
                event,
                "audit_policy_disabled",
                f"Audit désactivé ({data.get('SubcategoryGuid', '?')}) par {data.get('SubjectUserName', '?')}",
                "T1562.002",
            )

    def _service(self, event: dict, data: dict) -> None:
        name = data.get("ServiceName", "?")
        image = data.get("ImagePath") or data.get("ServiceFileName") or ""
        computer = event.get("computer", "").lower()
        if rules.REMOTE_EXEC_SERVICE.search(f"{name} {image}"):
            self._alert(
                event,
                "remote_exec_service",
                f"Service d'exécution distante : {name} -> {image}",
                ("T1569.002", "T1021.002", "T1543.003"),
                CRIT,
            )
        else:
            suspicious = bool(rules.SUSPICIOUS_PATH.search(image))
            level = CRIT if suspicious else MED
            self._alert(event, "service_installed", f"Service installé : {name} -> {image}", "T1543.003", level)
        self._lateral_chain(event, computer, f"service {name}")

    def _lateral_chain(self, event: dict, computer: str, what: str) -> None:
        """JPCERT : un logon réseau suivi de peu d'un service (PsExec, Impacket) signe un mouvement latéral."""
        previous, dt = self.last_network_logon.get(computer), parse_time(event.get("timestamp", ""))
        if previous and dt and 0 <= (dt - previous[0]).total_seconds() <= LATERAL_CHAIN_SECONDS:
            _, user, ip = previous
            self._alert(
                event,
                "lateral_movement_chain",
                f"Mouvement latéral : logon réseau de {user} depuis {ip} puis {what} sur {computer or '?'}",
                ("T1021.002", "T1569.002"),
                CRIT,
            )

    def _service_start_type(self, event: dict, data: dict) -> None:
        service, new = data.get("param1", ""), data.get("param3", "")
        if PROTECTED_SERVICES.search(service) and DISABLED_START.search(new):
            self._alert(event, "security_service_disabled", f"Service de sécurité désactivé : {service}", "T1562.001")

    def _scheduled_task(self, event: dict, data: dict) -> None:
        content = data.get("TaskContent") or data.get("TaskContentNew") or ""
        action = " ".join(m.group(2) for m in TASK_COMMAND.finditer(content))[:300]
        verb = "créée" if event["event_id"] == 4698 else "modifiée"
        suspicious = bool(action and (rules.SUSPICIOUS_PATH.search(action) or self._match_commands(action)))
        self._alert(
            event,
            "scheduled_task",
            f"Tâche planifiée {verb} : {data.get('TaskName', '?')} -> {action or '?'}",
            "T1053.005",
            CRIT if suspicious else MED,
        )

    def _share_access(self, event: dict, data: dict) -> None:
        share, user, ip = data.get("ShareName", ""), data.get("SubjectUserName", ""), _ip(data)
        if ip and share.upper().endswith(("\\ADMIN$", "\\C$")) and not _is_noise_account(user):
            self._alert(event, "admin_share", f"Partage administratif {share} ouvert par {user} depuis {ip}", "T1021.002", MED)
            dt = parse_time(event.get("timestamp", ""))
            if dt and len(self.last_network_logon) < MAX_TRACKED:
                self.last_network_logon[event.get("computer", "").lower()] = (dt, user, ip)

    # -- Exécution ------------------------------------------------------------------------------

    @staticmethod
    def _match_commands(command: str) -> list[rules.Rule]:
        return [rule for rule in rules.COMMAND_RULES if rule[0].search(command)]

    def _command(self, event: dict, command: str, label: str) -> None:
        matches = self._match_commands(command or "")
        if not matches:
            return
        severity = min((m[3] for m in matches), key=rules.SEVERITY_RANK.__getitem__)
        techniques = tuple(dict.fromkeys(t for m in matches for t in m[2]))
        labels = " ; ".join(m[1] for m in matches[:3])
        self._alert(event, "suspicious_command", f"{label} : {labels} - {command[:300]}", techniques, severity)

    def _parentage(self, event: dict, parent: str, image: str, command: str) -> None:
        for parent_re, child_re, label, techniques, severity in rules.PARENT_RULES:
            if parent_re.search(parent or "") and child_re.search(image or ""):
                self._alert(event, "suspicious_parent", f"{label} : {parent} -> {command[:250] or image}", techniques, severity)
                return

    def _process_created(self, event: dict, data: dict) -> None:
        command = data.get("CommandLine") or data.get("NewProcessName", "")
        self._command(event, command, "Processus")
        self._parentage(event, data.get("ParentProcessName", ""), data.get("NewProcessName", ""), command)

    def _script_block(self, event: dict, data: dict) -> None:
        text = data.get("ScriptBlockText", "")
        self._command(event, text, "Script PowerShell")
        score = sum(len(marker.findall(text)) for marker in rules.OBFUSCATION_MARKERS)
        if score >= rules.OBFUSCATION_THRESHOLD:
            self._alert(
                event,
                "obfuscated_script",
                f"Script PowerShell obfusqué ({score} marqueurs) : {text[:200]}",
                ("T1027", "T1059.001"),
            )

    # -- Sysmon ---------------------------------------------------------------------------------

    def _sysmon_process(self, event: dict, data: dict) -> None:
        command = data.get("CommandLine", "")
        self._command(event, command, f"Processus (parent {data.get('ParentImage', '?')})")
        self._parentage(event, data.get("ParentImage", ""), data.get("Image", ""), command)

    def _sysmon_network(self, event: dict, data: dict) -> None:
        ip = data.get("DestinationIp", "")
        if ip and ip not in _LOCAL_IPS and data.get("Initiated", "true").lower() == "true":
            self.counts["sysmon_network"] += 1
            if rules.SUSPICIOUS_PATH.search(data.get("Image", "")):
                self._alert(
                    event,
                    "network_from_suspicious_path",
                    f"{data.get('Image')} -> {ip}:{data.get('DestinationPort', '?')}",
                    "T1071",
                )

    def _sysmon_remote_thread(self, event: dict, data: dict) -> None:
        source, target = data.get("SourceImage", ""), data.get("TargetImage", "")
        if target.lower().endswith("\\lsass.exe") or rules.SUSPICIOUS_PATH.search(source):
            self._alert(event, "remote_thread", f"Thread distant : {source} -> {target}", "T1055")

    def _sysmon_process_access(self, event: dict, data: dict) -> None:
        source, target = data.get("SourceImage", ""), data.get("TargetImage", "")
        if not target.lower().endswith("\\lsass.exe") or rules.LSASS_BENIGN_SOURCES.search(source):
            return
        access = data.get("GrantedAccess", "").lower()
        if access in rules.LSASS_ACCESS_MASKS or rules.DUMP_CALLTRACE.search(data.get("CallTrace", "")):
            self._alert(event, "lsass_access", f"Accès à LSASS ({access}) par {source}", "T1003.001", CRIT)

    def _sysmon_file(self, event: dict, data: dict) -> None:
        path, image = data.get("TargetFilename", ""), data.get("Image", "")
        if rules.LSASS_DUMP_FILE.search(path):
            self._alert(event, "lsass_dump_file", f"Fichier de vidage LSASS : {path} (par {image})", "T1003.001", CRIT)
        elif rules.STARTUP_FOLDER.search(path):
            self._alert(event, "startup_folder", f"Fichier déposé dans le dossier Démarrage : {path} (par {image})", "T1547.001")
        elif rules.EXECUTABLE_EXT.search(path) and rules.SUSPICIOUS_PATH.search(path):
            self._alert(event, "dropped_executable", f"Exécutable déposé : {path} (par {image})", "T1105", MED)

    def _sysmon_registry(self, event: dict, data: dict) -> None:
        target = data.get("TargetObject", "")
        for pattern, label, techniques, severity in rules.REGISTRY_RULES:
            if pattern.search(target):
                details = data.get("Details", "")
                self._alert(event, "registry_persistence", f"{label} : {target} = {details[:200]}", techniques, severity)
                return

    def _sysmon_dns(self, event: dict, data: dict) -> None:
        query = (data.get("QueryName") or "").lower().rstrip(".")
        for pattern, label, techniques, severity in rules.DNS_RULES:
            if pattern.search(query):
                self._alert(event, "suspicious_dns", f"{label} : {query} (par {data.get('Image', '?')})", techniques, severity)
                return

    # -- Microsoft Defender ---------------------------------------------------------------------

    def _defender_threat(self, event: dict, data: dict) -> None:
        name, path = data.get("Threat Name", "?"), data.get("Path", "")
        verb = "détectée" if event["event_id"] == 1116 else "traitée"
        self._alert(event, "defender_detection", f"Menace {verb} par Defender : {name} {path[:200]}".strip(), (), HIGH)

    def _defender_disabled(self, event: dict, data: dict) -> None:
        text = f"Protection Microsoft Defender désactivée (événement {event['event_id']})"
        self._alert(event, "defender_disabled", text, "T1562.001")

    def _defender_config(self, event: dict, data: dict) -> None:
        new = data.get("New Value", "")
        if "exclusions" in new.lower() or re.search(r"disable\w*\s*=\s*0x1", new, re.I):
            self._alert(event, "defender_tampering", f"Configuration Defender affaiblie : {new[:200]}", "T1562.001")

    # -- Agrégats -------------------------------------------------------------------------------

    def finish(self) -> None:
        """Détections agrégées (force brute, pulvérisation, propagation, Kerberoasting) après lecture complète."""
        self._finish_failures()
        self._finish_spread()
        if self.remote_logons:
            self.techniques.add("T1078")

    def _finish_failures(self) -> None:
        for source, count in self.failures_by_source.items():
            users = self.users_by_source[source]
            first = {"event_id": 4625, "timestamp": self.first_seen.get(f"fail:{source}", "")}
            if len(users) >= SPRAY_USERS_THRESHOLD:
                self._alert(
                    first,
                    "password_spraying",
                    f"Pulvérisation de mots de passe depuis {source} : {count} échecs sur {len(users)} comptes",
                    "T1110.003",
                    CRIT,
                )
            elif count >= BRUTE_FORCE_THRESHOLD:
                self._alert(
                    first,
                    "brute_force",
                    f"Force brute depuis {source} : {count} échecs ({', '.join(sorted(users))[:120]})",
                    "T1110.001",
                    CRIT,
                )

    def _finish_spread(self) -> None:
        for user, hosts in self.hosts_by_user.items():
            if len(hosts) >= LATERAL_HOSTS_THRESHOLD:
                first = {"event_id": 4624, "timestamp": self.first_seen.get(f"spread:{user}", "")}
                listed = ", ".join(sorted(hosts)[:10])
                self._alert(first, "lateral_spread", f"{user} connecté à {len(hosts)} hôtes : {listed}", ("T1021", "T1078"))
        for user, targets in self.explicit_targets.items():
            if len(targets) >= EXPLICIT_TARGETS_THRESHOLD:
                first = {"event_id": 4648, "timestamp": self.first_seen.get(f"explicit:{user}", "")}
                listed = ", ".join(sorted(targets)[:10])
                text = f"{user} : identifiants explicites vers {listed}"
                self._alert(first, "explicit_credentials_spread", text, ("T1021", "T1078"))
        for user, services in self.rc4_services.items():
            first = {"event_id": 4769, "timestamp": self.first_seen.get(f"rc4:{user}", "")}
            many = len(services) >= KERBEROAST_SPN_THRESHOLD
            self._alert(
                first,
                "kerberoasting",
                f"{user} : {len(services)} ticket(s) de service RC4 ({', '.join(sorted(services)[:8])})",
                "T1558.003",
                CRIT if many else MED,
            )


__all__ = ["CRIT", "HIGH", "LOW", "MED", "EventDetector", "parse_time", "to_utc"]
