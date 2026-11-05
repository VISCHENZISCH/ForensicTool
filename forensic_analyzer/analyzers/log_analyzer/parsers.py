"""Parseurs spécialisés pour journaux web (Nginx, Apache), syslog, auth.log et WordPress."""

from __future__ import annotations

import datetime
import gzip
import os
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Any, Generator

from forensic_analyzer.analyzers.linux.analyzer import _syslog_iso
from forensic_analyzer.core.timeline import parse_ts


# Regex Web Access (Combined Log Format & Common Log Format)
_ACCESS_LOG_REGEX = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)?(?:\s+([^"]+))?"\s+(\d{3})\s+(\d+|-)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'
)

# Regex Nginx Error
_NGINX_ERROR_REGEX = re.compile(
    # Message gourmand jusqu'à « , client: » : en non gourmand suivi de groupes optionnels, il restait vide
    r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+\d+#\d+:\s+(?:\*\d+\s+)?((?:(?!,\s+client:).)*)"
    r'(?:,\s+client:\s+([^,\s]+))?(?:,\s+server:\s+([^,\s]+))?(?:,\s+request:\s+"([^"]*)")?'
)

# Regex Apache Error
_APACHE_ERROR_REGEX = re.compile(r"^\[([^\]]+)\]\s+\[(?:[^:]+:)?(\w+)\]\s+(?:\[pid \d+\]\s+)?(?:\[client ([^\]]+)\]\s+)?(.*)")

# Regex Syslog RFC 3164 (ex: Oct 12 10:14:02)
_SYSLOG_RFC3164 = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s+(.*)$")

# Regex Syslog RFC 5424 / ISO (ex: 2026-10-12T10:14:02.123456+02:00)
_SYSLOG_RFC5424 = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s+(.*)$"
)

# Regex WordPress Debug Log
_WP_DEBUG_REGEX = re.compile(
    r"^\[(\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\s+UTC)?)\]\s+(PHP\s+(?:Fatal error|Parse error|Warning|Notice|Deprecated)):\s+(.*)$"
)

# Avis WordPress significatifs dans wp-debug.log : (motif, type, gabarit)
_WP_NOTABLE = [
    (re.compile(r"wp_login_failed (\S+) from (\S+)"), "auth_failed", "Échec de connexion WordPress '{0}' depuis {1}"),
    (re.compile(r"wp_login OK (\S+) from (\S+)"), "auth_success", "Connexion WordPress réussie '{0}' depuis {1}"),
    (re.compile(r"attachment uploaded (\S+) by (\S+)"), "upload", "Fichier {0} téléversé par '{1}'"),
    (
        re.compile(r"(?i)file extension (\.\w+) allowed in uploads"),
        "misconfiguration",
        "Extension {0} autorisée dans les téléversements (mauvaise configuration)",
    ),
]

# Audit « horodatage CATÉGORIE clé=valeur... » (partage de fichiers, SIEM, pare-feu)
_AUDIT_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)\s+([A-Za-z][\w-]*)\s+(\w[\w.-]*=.*)$"
)
_AUDIT_FIELD = re.compile(r'([\w.-]+)=("[^"]*"|\S+)')
_MIN_AUDIT_FIELDS = 2
_REFUSED = {"deny", "denied", "refused", "failure", "failed", "blocked"}
_RESPONSE_CATEGORIES = {"SYSTEM", "RESPONSE"}
_IP_FIELDS = ("ip", "src", "src_ip", "client", "client_ip")
MASS_RENAME_THRESHOLD = 20  # renommages par un même compte et poste dans la fenêtre
MASS_RENAME_WINDOW = 300  # secondes
_MAX_RENAME_EVENTS = 20  # lignes nominatives gardées en chronologie, par compte et poste
_MAX_DENIED = 500  # accès refusés détaillés ; un balayage peut en produire des millions

# Attaques web courantes dans les URI / requêtes
_WEB_ATTACKS = [
    (
        re.compile(
            r'(?i)(?:union\s+select|select\s+.*\s+from|concat\(|information_schema|waitfor\s+delay|sleep\(\d+\)|benchmark\(|load_file\(|order\s+by\s+\d+|[\'"]\s+or\s+[\'"]\d+[\'"]=[\'"]\d+|[\'"]\s+or\s+1=1)'
        ),
        "SQL Injection (SQLi)",
    ),
    (
        re.compile(r"(?i)(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|/var/log/|c:\\windows|boot\.ini|win\.ini)"),
        "Path Traversal / LFI",
    ),
    (
        re.compile(r"(?i)(?:<script|javascript:|onerror\s*=|onload\s*=|alert\(|document\.cookie|<img\s+src=)"),
        "Cross-Site Scripting (XSS)",
    ),
    (re.compile(r"(?i)\b(?:x|shell|cmd|c99|r57|b374k|wso|alfa|root|backdoor|weevely)\.php"), "Webshell Access"),
    (re.compile(r"(?i)(?:php://input|php://filter|data://text|expect://)"), "PHP Wrapper / RFI"),
]

# Scanners web identifiables dans User-Agent
_SCANNER_AGENTS = re.compile(
    r"(?i)(?:sqlmap|nikto|wpscan|dirbuster|gobuster|ffuf|acunetix|masscan|zgrab|nessus|openvas|hydra|burpcollaborator|^nmap|nmap scripting engine)"
)
_LOGIN_URI = re.compile(r"(?i)wp-login\.php|xmlrpc\.php|/login|/signin")
_UPLOAD_URI = re.compile(r"(?i)async-upload\.php|/upload|media-new\.php")
_SENSITIVE_DOWNLOAD = re.compile(r"(?i)\.(sql|sql\.gz|gz|tgz|tar|zip|7z|rar|bak|dump|db|sqlite|csv|xlsx?)$")
_CMD_PARAMS = ("c", "cmd", "command", "exec", "e")
BRUTE_FORCE_THRESHOLD = 20  # tentatives de connexion depuis une même IP

# Lignes syslog notables : (motif, type, gabarit de description, alerte)
_SYSLOG_NOTABLE = [
    (re.compile(r"(\S+)\s*:\s*.*NOT in sudoers"), "sudo_denied", "Tentative sudo refusée pour '{0}'", True),
    (re.compile(r"LOGIN SUCCESS user=(\S+) from (\S+)"), "app_login", "Connexion applicative réussie '{0}' depuis {1}", True),
    (re.compile(r"RELOAD \((/etc/cron[^)]*)\)"), "cron_reload", "Rechargement de la tâche planifiée {0}", True),
    (
        re.compile(r"(?i)seg(?:mentation)? ?fault.*?from (\d+\.\d+\.\d+\.\d+)"),
        "crash",
        "Plantage déclenché par une requête de {0}",
        True,
    ),
    (re.compile(r"Connection from (\S+) port"), "ssh_connection", "Connexion SSH entrante depuis {0}", False),
    (re.compile(r"useradd\[?\d*\]?:.*new user: name=(\S+?),"), "user_created", "Création du compte {0}", True),
]


def _open_log(path: str) -> Generator[str, None, None]:
    """Ouvre un fichier texte ou gzippé (.gz) ligne par ligne."""
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line


def _parse_apache_timestamp(ts_str: str) -> str:
    """Convertit un timestamp Apache (12/Oct/2026:13:55:36 +0200) en ISO 8601 UTC."""
    try:
        # 12/Oct/2026:13:55:36 +0200
        dt = datetime.datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(datetime.timezone.utc).isoformat()
    except Exception:
        return ts_str


def _parse_syslog_timestamp(ts_str: str, ref: datetime.datetime) -> str:
    """Timestamp syslog sans année (Oct 12 10:14:02) en ISO 8601 UTC : année du mtime du journal."""
    iso = _syslog_iso(ts_str, ref)
    return iso + "+00:00" if iso[:4].isdigit() and "+" not in iso[10:] else iso


def _log_mtime(path: str) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(os.path.getmtime(path))


def parse_web_access_log(path: str) -> dict[str, Any]:
    """Parse un journal d'accès web (Nginx ou Apache Combined/Common)."""
    ip_counts: dict[str, int] = {}
    status_counts: dict[int, int] = {}
    methods: dict[str, int] = {}
    uri_counts: dict[str, int] = {}
    suspicious_requests: list[dict[str, Any]] = []
    scanners_detected: set[str] = set()
    events: list[dict[str, Any]] = []
    total_lines = 0
    valid_entries = 0

    login_attempts: dict[str, int] = {}
    login_window: dict[str, list[str]] = {}
    login_success: list[dict[str, Any]] = []
    webshell_access: list[dict[str, Any]] = []
    webshell_commands: list[dict[str, Any]] = []
    uploads: list[dict[str, Any]] = []
    exfiltration: list[dict[str, Any]] = []
    scanner_ips: set[str] = set()

    for line in _open_log(path):
        if not line.strip():
            continue
        total_lines += 1
        m = _ACCESS_LOG_REGEX.match(line.strip())
        if not m:
            continue
        valid_entries += 1
        ip = m.group(1)
        ts_raw = m.group(3)
        method = m.group(4)
        uri = m.group(5) or ""
        status = int(m.group(7))
        size = int(m.group(8)) if m.group(8).isdigit() else 0
        ua = m.group(10) or ""
        path_only, _, query = uri.partition("?")

        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1
        methods[method] = methods.get(method, 0) + 1
        uri_counts[uri] = uri_counts.get(uri, 0) + 1

        iso_ts = _parse_apache_timestamp(ts_raw)

        # Détection scanners
        if ua and _SCANNER_AGENTS.search(ua):
            scanners_detected.add(f"{ip} ({ua[:50]})")
            if ip not in scanner_ips:
                scanner_ips.add(ip)
                events.append(
                    {
                        "timestamp": iso_ts,
                        "source": "web_access",
                        "event_type": "recon",
                        "description": f"Reconnaissance par outil automatisé ({ua[:40]}) depuis {ip} : {method} {uri[:60]}",
                        "ip": ip,
                        "file": path,
                    }
                )

        params = urllib.parse.parse_qs(query)
        cmd_key = next((k for k in _CMD_PARAMS if k in params), None)
        shell_command = bool(cmd_key and path_only.lower().endswith((".php", ".jsp", ".asp", ".aspx")))
        if shell_command:
            command = params[cmd_key][0]
            webshell_commands.append({"timestamp": iso_ts, "ip": ip, "shell": path_only, "command": command})
            events.append(
                {
                    "timestamp": iso_ts,
                    "source": "web_access",
                    "event_type": "webshell_command",
                    "description": f"Commande via webshell {path_only} : {command[:80]} ({ip})",
                    "ip": ip,
                    "file": path,
                }
            )

        if method == "POST" and _UPLOAD_URI.search(path_only) and status < 400:
            uploads.append({"timestamp": iso_ts, "ip": ip, "uri": path_only})
            events.append(
                {
                    "timestamp": iso_ts,
                    "source": "web_access",
                    "event_type": "upload",
                    "description": f"Téléversement de fichier par {ip} : POST {path_only}",
                    "ip": ip,
                    "file": path,
                }
            )

        if method == "GET" and status in (200, 206) and _SENSITIVE_DOWNLOAD.search(path_only):
            exfiltration.append({"timestamp": iso_ts, "ip": ip, "uri": path_only, "bytes": size})
            events.append(
                {
                    "timestamp": iso_ts,
                    "source": "web_access",
                    "event_type": "exfiltration",
                    "description": f"Téléchargement de {path_only} ({size / 1024 / 1024:.1f} Mo) par {ip}",
                    "ip": ip,
                    "file": path,
                }
            )

        # Détection attaques web dans l'URI
        attack_detected = None
        for pattern, attack_name in _WEB_ATTACKS:
            if pattern.search(uri):
                attack_detected = attack_name
                break

        if attack_detected:
            req_info = {
                "timestamp": iso_ts,
                "ip": ip,
                "method": method,
                "uri": uri,
                "status": status,
                "attack": attack_detected,
                "user_agent": ua,
            }
            suspicious_requests.append(req_info)
            if not shell_command:  # sinon déjà l'événement « Commande via webshell », plus précis
                events.append(
                    {
                        "timestamp": iso_ts,
                        "source": "web_access",
                        "event_type": "web_attack",
                        "description": f"Attaque web [{attack_detected}] depuis {ip} : {method} {uri[:80]} (HTTP {status})",
                        "ip": ip,
                        "file": path,
                    }
                )
            if attack_detected == "Webshell Access":
                webshell_access.append(req_info)

        # Brute-force web : regroupé par IP en fin de lecture ; un 302 après POST = connexion acceptée
        if method == "POST" and _LOGIN_URI.search(path_only):
            login_attempts[ip] = login_attempts.get(ip, 0) + 1
            login_window.setdefault(ip, [iso_ts, iso_ts])[1] = iso_ts
            if status in (301, 302, 303):
                login_success.append({"timestamp": iso_ts, "ip": ip, "uri": path_only})

    brute_force = []
    for ip, count in sorted(login_attempts.items(), key=lambda x: -x[1]):
        won = [s for s in login_success if s["ip"] == ip]
        if count >= BRUTE_FORCE_THRESHOLD:
            start, end = login_window[ip]
            brute_force.append({"ip": ip, "attempts": count, "first": start, "last": end, "succeeded": bool(won)})
            events.append(
                {
                    "timestamp": start,
                    "source": "web_access",
                    "event_type": "brute_force",
                    "description": f"Début du brute-force web depuis {ip} ({count} tentatives jusqu'à {end})",
                    "ip": ip,
                    "file": path,
                }
            )
        for w in won:
            events.append(
                {
                    "timestamp": w["timestamp"],
                    "source": "web_access",
                    "event_type": "auth_success",
                    "description": f"Connexion web réussie depuis {ip} ({w['uri']}, HTTP 302)"
                    + (" après brute-force" if count >= BRUTE_FORCE_THRESHOLD else ""),
                    "ip": ip,
                    "file": path,
                }
            )

    # Attaquant : IP qui a agi offensivement, et non simple client fréquent
    attackers = (
        {b["ip"] for b in brute_force}
        | {r["ip"] for r in suspicious_requests}
        | scanner_ips
        | {c["ip"] for c in webshell_commands}
        | {e["ip"] for e in exfiltration}
    )
    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]
    top_uris = sorted(uri_counts.items(), key=lambda x: -x[1])[:10]
    events.sort(key=lambda e: e["timestamp"])

    return {
        "log_type": "web_access",
        "total_lines": total_lines,
        "valid_entries": valid_entries,
        "unique_ips": len(ip_counts),
        "top_ips": top_ips,
        "status_distribution": status_counts,
        "methods": methods,
        "top_uris": top_uris,
        "suspicious_requests": suspicious_requests,
        "webshell_hits": webshell_access,
        "login_attempts": login_attempts,
        "brute_force": brute_force,
        "login_success": login_success,
        "webshell_commands": webshell_commands,
        "uploads": uploads,
        "exfiltration": exfiltration,
        "attackers": sorted(attackers),
        "scanners": sorted(scanners_detected),
        "events": events,  # faits d'attaque uniquement (les tentatives de connexion sont regroupées)
    }


def _audit_entry(line: str) -> tuple[datetime.datetime, str, dict[str, str]] | None:
    """(horodatage, catégorie, champs) d'une ligne d'audit, ou None si elle n'en est pas une."""
    m = _AUDIT_LINE.match(line.strip())
    if not m:
        return None
    ts = parse_ts(m.group(1).replace(" ", "T", 1))
    fields = {k: v.strip('"') for k, v in _AUDIT_FIELD.findall(m.group(3))}
    return (ts, m.group(2), fields) if ts and len(fields) >= _MIN_AUDIT_FIELDS else None


def _rename_count(fields: dict[str, str]) -> int:
    """Une ligne agrégée (path=/reports/*, count=179) compte pour autant de fichiers."""
    count = fields.get("count", "1")
    return int(count) if count.isdigit() and int(count) > 0 else 1


def _peak_renames(renames: list[dict[str, Any]]) -> int:
    """Plus grand nombre de renommages dans une fenêtre glissante de MASS_RENAME_WINDOW secondes."""
    peak = total = start = 0
    for item in renames:
        total += item["count"]
        while (item["dt"] - renames[start]["dt"]).total_seconds() > MASS_RENAME_WINDOW:
            total -= renames[start]["count"]
            start += 1
        peak = max(peak, total)
    return peak


def _mass_rename(user: str, host: str, renames: list[dict[str, Any]]) -> dict[str, Any]:
    named = [r for r in renames if r["new_name"]]
    return {
        "user": user,
        "host": host,
        "shares": sorted({r["share"] for r in renames if r["share"]}),
        "total": sum(r["count"] for r in renames),
        "named": len(named),
        "aggregated": [{"path": r["path"], "count": r["count"]} for r in renames if not r["new_name"]],
        "new_names": [r["new_name"] for r in named],
        "extensions": sorted({os.path.splitext(r["new_name"])[1].lower() for r in named} - {""}),
        "first": renames[0]["dt"].isoformat(),
        "last": renames[-1]["dt"].isoformat(),
        "seconds": int((renames[-1]["dt"] - renames[0]["dt"]).total_seconds()),
    }


def _audit_event(dt: datetime.datetime, kind: str, description: str, path: str) -> dict[str, Any]:
    return {"timestamp": dt.isoformat(), "source": "file_audit", "event_type": kind, "description": description, "file": path}


def _response_text(category: str, fields: dict[str, str]) -> str:
    who = fields.get("actor") or fields.get("host") or category
    target = next((f"{k}={fields[k]}" for k in ("user", "host", "share") if k in fields and fields[k] != who), "")
    reason = fields.get("reason") or fields.get("result") or ""
    details = ", ".join(x for x in (target, reason) if x)
    return f"{who} : {fields.get('action', '?')}" + (f" ({details})" if details else "")


@dataclass
class _AuditState:
    """Ce qu'on retient d'un journal d'audit au fil de sa lecture."""

    path: str
    denied_total: int = 0
    renames: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)
    first_seen: dict[tuple[str, str], tuple[datetime.datetime, str]] = field(default_factory=dict)
    ips: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    denied: list[dict[str, Any]] = field(default_factory=list)
    responses: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)


def _record_refusal(state: _AuditState, dt: datetime.datetime, actor: tuple[str, str], fields: dict[str, str]) -> None:
    state.denied_total += 1
    if state.denied_total > _MAX_DENIED:
        return
    user, host = actor
    share, target = fields.get("share", ""), fields.get("path", "")
    state.denied.append({"timestamp": dt.isoformat(), "user": user, "host": host, "share": share, "path": target})
    text = f"Accès refusé à {target} (partage {share or '?'}) pour {user} sur {host}"
    state.events.append(_audit_event(dt, "access_denied", text, state.path))


def _record_audit_entry(state: _AuditState, dt: datetime.datetime, category: str, fields: dict[str, str]) -> None:
    if category.upper() in _RESPONSE_CATEGORIES:
        text = _response_text(category, fields)
        state.responses.append({"timestamp": dt.isoformat(), "description": text})
        state.events.append(_audit_event(dt, "containment", f"Réaction {text}", state.path))
        return
    actor = (fields.get("user", ""), fields.get("host", ""))
    if not actor[0]:
        return
    target = fields.get("path", "")
    state.first_seen.setdefault(actor, (dt, target))
    state.ips.setdefault(actor, set()).update(fields[k] for k in _IP_FIELDS if k in fields)
    if fields.get("result", "").lower() in _REFUSED:
        _record_refusal(state, dt, actor, fields)
    elif fields.get("action", "").lower() == "rename":
        state.renames.setdefault(actor, []).append(
            {
                "dt": dt,
                "path": target,
                "share": fields.get("share", ""),
                "count": _rename_count(fields),
                "new_name": fields.get("new_name", ""),
            }
        )


def _mass_rename_events(state: _AuditState, user: str, host: str, items: list[dict[str, Any]]) -> None:
    seen_at, seen_path = state.first_seen[(user, host)]
    if seen_at < items[0]["dt"]:
        text = f"Premier accès de {user} sur {host} : {seen_path}"
        state.events.append(_audit_event(seen_at, "first_access", text, state.path))
    for r in [r for r in items if r["new_name"]][:_MAX_RENAME_EVENTS]:
        text = f"Renommage de {r['path']} en {r['new_name']} par {user} sur {host} (partage {r['share'] or '?'})"
        state.events.append(_audit_event(r["dt"], "rename", text, state.path))
    for r in items:
        if not r["new_name"]:
            text = f"Renommage groupé de {r['count']} fichiers ({r['path']}) par {user} sur {host}"
            state.events.append(_audit_event(r["dt"], "mass_rename", text, state.path))


def parse_file_audit_log(path: str) -> dict[str, Any]:
    """Audit clé=valeur : renommages de masse par compte et poste, accès refusés, actions de confinement."""
    state = _AuditState(path)
    total_lines = valid = 0
    for line in _open_log(path):
        if not line.strip():
            continue
        total_lines += 1
        entry = _audit_entry(line)
        if entry:
            valid += 1
            _record_audit_entry(state, *entry)

    mass = []
    for (user, host), items in state.renames.items():
        items.sort(key=lambda r: r["dt"])
        if _peak_renames(items) >= MASS_RENAME_THRESHOLD:
            mass.append(_mass_rename(user, host, items))
            _mass_rename_events(state, user, host, items)
    mass.sort(key=lambda m: -m["total"])
    state.events.sort(key=lambda e: e["timestamp"])
    offenders = {(m["user"], m["host"]) for m in mass}
    return {
        "log_type": "file_audit",
        "total_lines": total_lines,
        "valid_entries": valid,
        "accounts": sorted(f"{u}@{h}" if h else u for u, h in state.first_seen),
        "mass_renames": mass,
        "denied": state.denied,
        "denied_total": state.denied_total,
        "responses": state.responses,
        "offender_ips": sorted(ip for actor in offenders for ip in state.ips.get(actor, ())),
        "events": state.events,
    }


def parse_web_error_log(path: str) -> dict[str, Any]:
    """Parse un journal d'erreurs web (Nginx ou Apache)."""
    error_levels: dict[str, int] = {}
    client_errors: dict[str, int] = {}
    suspicious_errors: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    total_lines = 0

    for line in _open_log(path):
        total_lines += 1
        line_clean = line.strip()
        m_nginx = _NGINX_ERROR_REGEX.match(line_clean)
        if m_nginx:
            ts_raw, level, msg, client, _, req = m_nginx.groups()
            iso_ts = ts_raw.replace("/", "-").replace(" ", "T") + "+00:00"
            error_levels[level] = error_levels.get(level, 0) + 1
            if client:
                client_errors[client] = client_errors.get(client, 0) + 1
            if "limiting requests" in msg:
                msg = "Limitation de débit déclenchée (rafale de requêtes, brute-force probable)"
            if level in ("crit", "alert", "error", "emerg") or "FastCGI" in msg or "denied" in msg:
                err_data = {
                    "timestamp": iso_ts,
                    "level": level,
                    "message": msg[:200],
                    "client": client or "",
                    "request": req or "",
                }
                suspicious_errors.append(err_data)
                events.append(
                    {
                        "timestamp": iso_ts,
                        "source": "web_error",
                        "event_type": "web_error",
                        "description": f"Erreur Nginx [{level}] : {msg[:100]}" + (f" (client {client})" if client else ""),
                        "ip": client or "",
                        "file": path,
                    }
                )
            continue

        m_apache = _APACHE_ERROR_REGEX.match(line_clean)
        if m_apache:
            ts_raw, level, client, msg = m_apache.groups()
            error_levels[level] = error_levels.get(level, 0) + 1
            if client:
                client_errors[client] = client_errors.get(client, 0) + 1
            if level in ("crit", "alert", "error", "emerg"):
                suspicious_errors.append(
                    {
                        "timestamp": ts_raw,
                        "level": level,
                        "message": msg[:200],
                        "client": client or "",
                    }
                )
                events.append(
                    {
                        "timestamp": ts_raw,
                        "source": "web_error",
                        "event_type": "web_error",
                        "description": f"Erreur Apache [{level}] : {msg[:100]}",
                        "ip": client or "",
                        "file": path,
                    }
                )

    return {
        "log_type": "web_error",
        "total_lines": total_lines,
        "error_levels": error_levels,
        "client_errors": sorted(client_errors.items(), key=lambda x: -x[1])[:10],
        "suspicious_errors": suspicious_errors[:50],
        "events": events[:50],
    }


def parse_syslog_file(path: str) -> dict[str, Any]:
    """Parse un journal syslog / auth.log (format RFC 3164 ou RFC 5424)."""
    services: dict[str, int] = {}
    auth_failures = 0
    auth_successes = 0
    sudo_commands: list[dict[str, Any]] = []
    failed_ips: dict[str, int] = {}
    events: list[dict[str, Any]] = []
    notable: list[dict[str, Any]] = []
    notable_ips: set[str] = set()
    ssh_pairs: set[tuple[str, str]] = set()
    total_lines = 0
    ref = _log_mtime(path)

    re_failed = re.compile(r"Failed\s+(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)")
    re_accepted = re.compile(r"Accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)")
    re_sudo = re.compile(r"(?:sudo:\s*)?(\S+)\s*:\s*.*COMMAND=(.*)")

    for line in _open_log(path):
        total_lines += 1
        line_clean = line.strip()
        m = _SYSLOG_RFC5424.match(line_clean)
        if m:
            iso_ts = m.group(1)
            service = m.group(3).strip()
            msg = m.group(5)
        else:
            m2 = _SYSLOG_RFC3164.match(line_clean)
            if not m2:
                continue
            iso_ts = _parse_syslog_timestamp(m2.group(1), ref)
            service = m2.group(3).strip()
            msg = m2.group(5)

        services[service] = services.get(service, 0) + 1

        # Analyse SSH / authentification
        mf = re_failed.search(msg)
        if mf:
            user, ip = mf.group(1), mf.group(2)
            auth_failures += 1
            failed_ips[ip] = failed_ips.get(ip, 0) + 1
            events.append(
                {
                    "timestamp": iso_ts,
                    "source": "syslog",
                    "event_type": "auth_failed",
                    "description": f"Échec d'authentification SSH pour l'utilisateur '{user}' depuis {ip}",
                    "ip": ip,
                    "file": path,
                }
            )

        ma = re_accepted.search(msg)
        if ma:
            user, ip = ma.group(1), ma.group(2)
            auth_successes += 1
            # Une connexion par (compte, source) suffit : la première d'une nouvelle source est le
            # signal utile, les suivantes (sessions d'exploitation régulières) noient la chronologie
            if (user, ip) not in ssh_pairs:
                ssh_pairs.add((user, ip))
                events.append(
                    {
                        "timestamp": iso_ts,
                        "source": "syslog",
                        "event_type": "auth_success",
                        "description": f"Première connexion SSH réussie de '{user}' depuis {ip}",
                        "ip": ip,
                        "file": path,
                    }
                )

        for pattern, kind, template, alert in _SYSLOG_NOTABLE:
            mn = pattern.search(msg)
            if mn:
                description = template.format(*mn.groups())
                notable.append({"timestamp": iso_ts, "type": kind, "description": description, "alert": alert})
                notable_ips.update(g for g in mn.groups() if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", g or ""))
                events.append(
                    {
                        "timestamp": iso_ts,
                        "source": "syslog",
                        "event_type": kind,
                        "description": description,
                        "ip": "",
                        "file": path,
                    }
                )
                break

        ms = re_sudo.search(msg) or re_sudo.search(line_clean)
        if ms:
            user, cmd = ms.group(1), ms.group(2).strip()
            # Refus sur la même ligne (format sudo standard) ou sur la ligne suivante (voir plus bas)
            denied = "NOT in sudoers" in line_clean or "incorrect password" in line_clean
            sudo_commands.append({"timestamp": iso_ts, "user": user, "command": cmd, "denied": denied})
            events.append(
                {
                    "timestamp": iso_ts,
                    "source": "syslog",
                    "event_type": "sudo",
                    "description": f"Commande SUDO par '{user}' : {cmd[:80]}",
                    "ip": "",
                    "file": path,
                }
            )

    # Refus journalisé à part ("www-data : NOT in sudoers") : même compte, même seconde
    refusals = {(n["description"].split("'")[1], n["timestamp"]) for n in notable if n["type"] == "sudo_denied"}
    for cmd in sudo_commands:
        cmd["denied"] = cmd["denied"] or (cmd["user"], cmd["timestamp"]) in refusals

    return {
        "log_type": "syslog",
        "total_lines": total_lines,
        "services": sorted(services.items(), key=lambda x: -x[1])[:10],
        "auth_failures": auth_failures,
        "auth_successes": auth_successes,
        "ssh_sources": sorted({f"{u}@{ip}" for u, ip in ssh_pairs}),
        "failed_ips": sorted(failed_ips.items(), key=lambda x: -x[1])[:10],
        "sudo_commands": sudo_commands[:30],
        "notable": notable[:200],
        "notable_ips": sorted(notable_ips),
        "events": events[:500],
    }


def parse_wp_debug_log(path: str) -> dict[str, Any]:
    """Parse un fichier wp-debug.log WordPress."""
    fatal_errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    referenced_files: set[str] = set()
    events: list[dict[str, Any]] = []
    notable: list[str] = []
    total_lines = 0

    for line in _open_log(path):
        total_lines += 1
        m = _WP_DEBUG_REGEX.match(line.strip())
        if not m:
            continue
        ts_raw, severity, msg = m.groups()
        # 12-Oct-2026 10:00:00 UTC -> ISO 8601
        try:
            clean_ts = ts_raw.replace(" UTC", "").strip()
            dt = datetime.datetime.strptime(clean_ts, "%d-%b-%Y %H:%M:%S")
            iso_ts = dt.replace(tzinfo=datetime.timezone.utc).isoformat()
        except Exception:
            iso_ts = ts_raw

        # Trouver les fichiers mentionnés dans le message d'erreur
        for fp in re.findall(r"in\s+(/[^\s:]+)", msg):
            referenced_files.add(fp)

        if "Fatal" in severity or "Parse" in severity:
            fatal_errors.append({"timestamp": iso_ts, "severity": severity, "message": msg})
            events.append(
                {
                    "timestamp": iso_ts,
                    "source": "wp_debug",
                    "event_type": "php_fatal",
                    "description": f"Erreur PHP WordPress [{severity}] : {msg[:120]}",
                    "ip": "",
                    "file": path,
                }
            )
        else:
            warnings.append({"timestamp": iso_ts, "severity": severity, "message": msg})
            for pattern, kind, template in _WP_NOTABLE:
                mw = pattern.search(msg)
                if mw:
                    events.append(
                        {
                            "timestamp": iso_ts,
                            "source": "wp_debug",
                            "event_type": kind,
                            "description": template.format(*mw.groups()),
                            "ip": "",
                            "file": path,
                        }
                    )
                    notable.append(template.format(*mw.groups()))
                    break

    return {
        "log_type": "wp_debug",
        "total_lines": total_lines,
        "fatal_errors": fatal_errors[:50],
        "warnings_count": len(warnings),
        "referenced_files": sorted(referenced_files),
        "notable": notable,
        "events": events[:200],
    }


def _sample_lines(path: str, limit: int = 50, max_chars: int = 64 * 1024) -> list[str]:
    """Premières lignes non vides, en lecture bornée : `can_handle` passe aussi sur des images disque."""
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            text = f.read(max_chars)
    except (OSError, EOFError, zlib.error):  # gzip corrompu : le fichier ne doit pas arrêter le scan
        return []
    lines = text.splitlines()
    if len(text) == max_chars and lines:
        lines.pop()  # dernière ligne coupée par la borne
    return [line.strip() for line in lines if line.strip()][:limit]


def detect_log_type(path: str) -> str:
    """Détecte le type de journal : le contenu prime, car le nom n'est qu'un indice (« access.log » d'un audit SMB)."""
    basename = os.path.basename(path).lower()
    if basename.endswith(".gz"):
        basename = basename[:-3]

    sample = _sample_lines(path)
    if sample and sum(1 for line in sample if _audit_entry(line)) > len(sample) / 2:
        return "file_audit"
    if "access" in basename:
        # Un fichier vide reste classé par son nom ; un contenu d'un autre format, non
        if not sample or any(_ACCESS_LOG_REGEX.match(line) for line in sample):
            return "web_access"
    elif "error" in basename:
        return "web_error"
    elif "wp-debug" in basename or "debug.log" in basename:
        return "wp_debug"
    elif "auth" in basename or "syslog" in basename or "messages" in basename or "secure" in basename:
        return "syslog"

    def matches(*patterns: re.Pattern[str]) -> bool:
        return any(p.match(line) for p in patterns for line in sample)

    if matches(_ACCESS_LOG_REGEX):
        return "web_access"
    if matches(_NGINX_ERROR_REGEX, _APACHE_ERROR_REGEX):
        return "web_error"
    if matches(_WP_DEBUG_REGEX):
        return "wp_debug"
    if matches(_SYSLOG_RFC3164, _SYSLOG_RFC5424):
        return "syslog"
    return "unknown"
