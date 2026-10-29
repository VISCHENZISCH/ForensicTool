"""Analyzer artefacts Linux - bash_history, cron, auth.log, SSH, /proc, persistance, paquets et journaux."""
from __future__ import annotations

import datetime
import glob
import os
import re

from forensic_analyzer.analyzers.linux import bodyfile as bf
from forensic_analyzer.analyzers.linux import logs, packages, persistence
from forensic_analyzer.core import mitre
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("linux_artifacts")

# Patterns pour auth.log : horodatage syslog classique ou RFC 3339 (rsyslog recent)
_AUTH_FAILED = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+\S+\s+sshd\[\d+\]:\s+'
    r'Failed password for (?:invalid user )?(\S+)\s+from\s+(\S+)',
)
_AUTH_SUCCESS = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+\S+\s+sshd\[\d+\]:\s+'
    r'Accepted (?:password|publickey) for (\S+)\s+from\s+(\S+)',
)
_SUDO = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+\S+\s+sudo:\s+(\S+)\s+:.*COMMAND=(.*)',
)

# Commandes suspectes dans bash_history
_SUSPICIOUS_CMDS = [
    r'wget\s+http',
    r'curl\s+.*\|\s*(?:bash|sh)',
    r'nc\s+-[le]',
    r'ncat\s+',
    r'python\s+-c.*socket',
    r'python3?\s+-m\s+http\.server',
    r'base64\s+-d',
    r'chmod\s+[0-7]*[7][0-7]*\s',
    r'chmod\s+\+s\s',
    r'chown\s+root',
    r'crontab\s+-[re]',
    r'iptables\s+-[FX]',
    r'rm\s+-rf\s+/',
    r'/dev/tcp/',
    r'/dev/udp/',
    r'mkfifo',
    r'\.ssh/authorized_keys',
    r'passwd\s+',
    r'useradd\s+',
    r'usermod\s+-aG\s+sudo',
    r'export\s+HISTSIZE=0',
    r'unset\s+HISTFILE',
    r'history\s+-c',
    r'shred\s+',
    r'dd\s+if=/dev/',
    r'tcpdump\s+',
    r'nmap\s+',
    r'masscan\s+',
    r'hydra\s+',
    r'john\s+',
    r'hashcat\s+',
    r'mimikatz',
    r'linpeas',
    r'linenum',
    r'pspy',
]


def parse_bash_history(path: str) -> dict:
    """Parse un fichier bash_history et detecte les commandes suspectes."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        commands = []
        last_ts = ""
        for line in lines:
            line = line.strip()
            if not line: continue
            if line.startswith('#') and line[1:].isdigit():
                try:
                    last_ts = datetime.datetime.fromtimestamp(int(line[1:]), tz=datetime.timezone.utc).isoformat()
                except Exception: pass
                continue
            
            if last_ts:
                commands.append(f"[{last_ts}] {line}")
                last_ts = ""
            else:
                commands.append(line)
        suspicious = []

        compiled = [(re.compile(p, re.IGNORECASE), p) for p in _SUSPICIOUS_CMDS]

        for i, cmd in enumerate(commands):
            for pattern, raw_pattern in compiled:
                if pattern.search(cmd):
                    suspicious.append({
                        "line": i + 1,
                        "command": cmd[:200],
                        "pattern": raw_pattern,
                    })
                    break

        return {
            "total_commands": len(commands),
            "suspicious_commands": len(suspicious),
            "suspicious": suspicious[:100],
            "last_commands": commands[-20:] if commands else [],
        }
    except Exception as exc:
        return {"error": str(exc)}


def _syslog_iso(ts: str, ref: datetime.datetime) -> str:
    """
    Horodatage syslog en ISO 8601. Le format classique n'a pas d'annee : on prend celle
    de la derniere modification du journal, moins un si la date tombe apres (passage d'annee).
    """
    if ts[:4].isdigit():
        return ts
    try:
        dt = datetime.datetime.strptime(f"{ref.year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return ts
    if dt > ref + datetime.timedelta(days=1):
        dt = dt.replace(year=ref.year - 1)
    return dt.isoformat()


def parse_auth_log(path: str) -> dict:
    """Parse un fichier auth.log pour extraire les evenements d'authentification."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        ref = datetime.datetime.fromtimestamp(os.path.getmtime(path))

        failed = []
        for match in _AUTH_FAILED.finditer(content):
            failed.append({
                "timestamp": _syslog_iso(match.group(1), ref),
                "user": match.group(2),
                "source_ip": match.group(3),
            })

        success = []
        for match in _AUTH_SUCCESS.finditer(content):
            success.append({
                "timestamp": _syslog_iso(match.group(1), ref),
                "user": match.group(2),
                "source_ip": match.group(3),
            })

        sudo_cmds = []
        for match in _SUDO.finditer(content):
            sudo_cmds.append({
                "timestamp": _syslog_iso(match.group(1), ref),
                "user": match.group(2),
                "command": match.group(3)[:200],
            })

        # Brute force detection : > 10 fails depuis la meme IP
        from collections import Counter
        ip_fails = Counter(f["source_ip"] for f in failed)
        brute_force_ips = {ip: count for ip, count in ip_fails.items() if count > 10}

        return {
            "failed_logins": len(failed),
            "successful_logins": len(success),
            "sudo_commands": len(sudo_cmds),
            "brute_force_ips": brute_force_ips,
            "failed_details": failed[:100],
            "success_details": success[:100],
            "sudo_details": sudo_cmds[:50],
        }
    except Exception as exc:
        return {"error": str(exc)}


def parse_crontabs(root_path: str = "/") -> list[dict]:
    """Collecte tous les crontabs du systeme."""
    crons = []
    cron_paths = [
        os.path.join(root_path, "etc/crontab"),
        os.path.join(root_path, "etc/cron.d"),
        os.path.join(root_path, "var/spool/cron/crontabs"),
        os.path.join(root_path, "var/spool/cron"),
    ]

    for cpath in cron_paths:
        if os.path.isfile(cpath):
            try:
                with open(cpath, "r", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            crons.append({"source": cpath, "entry": line})
            except OSError as exc:
                log.debug("Crontab illisible '%s' : %s", cpath, exc)
                continue
        elif os.path.isdir(cpath):
            for fname in os.listdir(cpath):
                fpath = os.path.join(cpath, fname)
                if os.path.isfile(fpath):
                    try:
                        with open(fpath, "r", errors="replace") as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    crons.append({"source": fpath, "entry": line})
                    except OSError as exc:
                        log.debug("Crontab illisible '%s' : %s", fpath, exc)
                        continue
    return crons


def parse_ssh_artifacts(root_path: str = "/") -> dict:
    """Analyse les artefacts SSH (cles, known_hosts, authorized_keys)."""
    results: dict = {"keys": [], "known_hosts": [], "authorized_keys": []}

    # Scanner les home directories
    home_base = os.path.join(root_path, "home")
    if os.path.isdir(home_base):
        for user_dir in os.listdir(home_base):
            ssh_dir = os.path.join(home_base, user_dir, ".ssh")
            if not os.path.isdir(ssh_dir):
                continue

            for fname in os.listdir(ssh_dir):
                fpath = os.path.join(ssh_dir, fname)
                if not os.path.isfile(fpath):
                    continue

                try:
                    stat = os.stat(fpath)
                    info = {
                        "user": user_dir,
                        "file": fpath,
                        "size": stat.st_size,
                        "permissions": oct(stat.st_mode)[-3:],
                        "modified": datetime.datetime.fromtimestamp(
                            stat.st_mtime, tz=datetime.timezone.utc
                        ).isoformat(),
                    }

                    if fname == "known_hosts":
                        with open(fpath, "r", errors="replace") as f:
                            hosts = [l.strip().split()[0] for l in f if l.strip()]
                        info["hosts_count"] = len(hosts)
                        results["known_hosts"].append(info)
                    elif fname == "authorized_keys":
                        with open(fpath, "r", errors="replace") as f:
                            keys = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                        info["keys_count"] = len(keys)
                        info["keys_preview"] = [k[:80] for k in keys[:10]]
                        results["authorized_keys"].append(info)
                    elif fname.startswith("id_") or fname.endswith(".pub"):
                        info["type"] = "public" if fname.endswith(".pub") else "private"
                        # Verifier si la cle privee est protegee par passphrase
                        if info["type"] == "private":
                            with open(fpath, "r", errors="replace") as f:
                                content = f.read()
                            info["encrypted"] = "ENCRYPTED" in content
                        results["keys"].append(info)
                except Exception as exc:
                    log.debug("Clé SSH illisible '%s' : %s", fpath, exc)
                    continue

    return results


def parse_proc_maps(root_path: str = "/") -> list[dict]:
    """Analyse /proc/[pid]/maps pour les processus actifs."""
    proc_info = []
    proc_dir = os.path.join(root_path, "proc")

    if not os.path.isdir(proc_dir):
        return proc_info

    for pid_dir in os.listdir(proc_dir):
        if not pid_dir.isdigit():
            continue
        pid = int(pid_dir)
        pid_path = os.path.join(proc_dir, pid_dir)

        try:
            # cmdline
            cmdline_path = os.path.join(pid_path, "cmdline")
            cmdline = ""
            if os.path.isfile(cmdline_path):
                with open(cmdline_path, "r", errors="replace") as f:
                    cmdline = f.read().replace('\x00', ' ').strip()

            # Status
            status_path = os.path.join(pid_path, "status")
            name = ""
            uid = ""
            if os.path.isfile(status_path):
                with open(status_path, "r", errors="replace") as f:
                    for line in f:
                        if line.startswith("Name:"):
                            name = line.split(":", 1)[1].strip()
                        elif line.startswith("Uid:"):
                            uid = line.split(":", 1)[1].strip().split()[0]

            proc_info.append({
                "pid": pid,
                "name": name,
                "cmdline": cmdline[:200],
                "uid": uid,
            })
        except (PermissionError, FileNotFoundError):
            continue

    proc_info.sort(key=lambda x: x["pid"])
    return proc_info

def parse_passwd_shadow(root_path: str = "/") -> dict:
    """Parse /etc/passwd et /etc/shadow."""
    res = {"passwd": [], "shadow": [], "uid_0": []}
    
    passwd_path = os.path.join(root_path, "etc/passwd")
    if os.path.isfile(passwd_path):
        with open(passwd_path, "r", errors="replace") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    user, pwd, uid, gid, comment, home, shell = parts[:7]
                    res["passwd"].append({"user": user, "uid": uid, "shell": shell})
                    if uid == "0":
                        res["uid_0"].append(user)
                        
    shadow_path = os.path.join(root_path, "etc/shadow")
    if os.path.isfile(shadow_path):
        try:
            with open(shadow_path, "r", errors="replace") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        user, pwd = parts[:2]
                        if pwd not in ("*", "!", "!!"):
                            res["shadow"].append({"user": user, "has_hash": True})
        except PermissionError:
            res["shadow_error"] = "Permission Denied"
            
    return res

def parse_syslog(root_path: str = "/") -> dict:
    """Parse syslog/messages pour anomalies (segfault, usb, etc)."""
    logs = []
    for log_name in ["var/log/syslog", "var/log/messages"]:
        p = os.path.join(root_path, log_name)
        if os.path.isfile(p):
            with open(p, "r", errors="replace") as f:
                for line in f:
                    if "segfault" in line or "usb" in line.lower() or "promiscuous" in line:
                        logs.append(line.strip()[:200])
    return {"anomalies": logs}

def find_suid_sgid(root_path: str = "/") -> list:
    """Trouve les binaires SUID/SGID."""
    targets = []
    dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "opt", "tmp", "var/tmp"]
    for d in dirs:
        p = os.path.join(root_path, d)
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        st = os.stat(fp)
                        if (st.st_mode & 0o4000) or (st.st_mode & 0o2000):
                            targets.append(fp)
                    except OSError as exc:
                        log.debug("stat impossible sur %s : %s", fp, exc)
    return targets

def _analyze_incident_artifacts(root: str, bodyfile: str | None, meta: dict, extra: dict,
                                entries: list | None = None, file_hasher=None) -> None:
    """Persistance, integrite des paquets, anomalies de fichiers et journaux (enrichit meta/extra)."""
    techniques: set[str] = set()
    events: list[dict] = []

    if entries is None:
        entries = bf.parse_bodyfile(bodyfile) if bodyfile else []
    body = bf.index_by_path(entries) if entries else None
    if bodyfile:
        meta["Bodyfile"] = f"{len(entries)} entrees ({os.path.basename(bodyfile)})"
    elif entries:
        meta["Metadonnees"] = f"{len(entries)} entrees lues dans l'image disque"

    debian = packages.is_debian_root(root)
    owned = packages.owned_paths(root) if debian else None

    # Persistance systemd
    systemd = persistence.analyze_systemd(root, body, owned)
    suspicious = [u for u in systemd["units"] if u["suspicious"]]
    meta["Unites systemd locales"] = str(len(systemd["units"]))
    for u in suspicious:
        meta[f"[ALERTE] Unite suspecte {u['unit']}"] = f"score {u['score']} : " + " ; ".join(u["reasons"])
        techniques.update(u["mitre"])
        if u["created"]:
            events.append(_event(u["created"], "bodyfile", "unit_created", f"Creation de l'unite {u['unit']}"))
        if u["modified"] and u["modified"] != u["created"]:
            events.append(_event(u["modified"], "bodyfile", "unit_modified", f"Modification de l'unite {u['unit']}"))
        for link in u["enabled_by"]:
            if link["created"]:
                events.append(_event(link["created"], "bodyfile", "unit_enabled", f"Activation : {link['link']}"))
    extra["systemd"] = systemd

    other = persistence.other_persistence(root, owned)
    for item in other:
        if item["severity"] != "info":
            meta[f"[ALERTE] Persistance {item['path']}"] = f"{item['detail']} ({item['mitre']})"
            techniques.add(item["mitre"])
    extra["other_persistence"] = other

    # Integrite des paquets Debian
    if debian:
        dpkg = packages.verify_dpkg(root, body, hasher=file_hasher)
        meta["Integrite paquets (dpkg)"] = (f"{dpkg['checked']} fichiers ({dpkg['conffiles']} conffiles) : "
                                            f"{len(dpkg['modified'])} modifies, {len(dpkg['missing'])} absents")
        if dpkg["modified"]:
            meta["[ALERTE] Fichiers de paquets modifies"] = ", ".join(m["path"] for m in dpkg["modified"][:15])
        extra["dpkg"] = dpkg

    # Anomalies de fichiers (necessitent le bodyfile)
    if entries:
        anomalies = {
            "Fichiers systeme hors root": bf.ownership_anomalies(entries),
            "Fichiers caches (systeme / temporaires)": bf.hidden_entries(entries),
        }
        if debian:
            anomalies["Fichiers hors paquet"] = packages.files_outside_packages(root, entries, bf.PACKAGE_PREFIXES)
        for label, found in anomalies.items():
            if found:
                meta[f"[ALERTE] {label}"] = ", ".join(f"{e.path} (uid {e.uid})" for e in found[:15])
        if anomalies["Fichiers caches (systeme / temporaires)"]:
            techniques.add("T1564.001")
        extra["file_anomalies"] = {k: [_entry_dict(e) for e in v] for k, v in anomalies.items()}

    # Journaux : audit, wtmp/lastlog, journald
    log_dir = os.path.join(root, "var/log")
    audit_path = os.path.join(log_dir, "audit/audit.log")
    if os.path.isfile(audit_path):
        audit = logs.parse_audit_log(audit_path)
        meta["audit.log"] = (f"{len(audit['auth'])} authentifications, {len(audit['auth_failures'])} echecs, "
                             f"{audit['execve_events']} EXECVE")
        units = {os.path.basename(u["unit"]).rsplit(".", 1)[0] for u in suspicious}
        for a in audit["auth"]:
            events.append(_event(a["time"], "audit.log", "auth",
                                 f"Authentification {a.get('acct', '?')} via {a.get('exe', '?')} ({a.get('terminal', '?')})"))
        for svc in audit["services"]:
            if svc.get("unit") in units:
                events.append(_event(svc["time"], "audit.log", svc["type"].lower(), f"{svc['type']} {svc['unit']}"))
        if not audit["execve_events"]:
            meta["Limite audit"] = "Aucun EXECVE journalise : les commandes executees ne sont pas tracees"
        extra["audit"] = audit

    wtmp_path = os.path.join(log_dir, "wtmp")
    if os.path.isfile(wtmp_path):
        wtmp = logs.parse_wtmp(wtmp_path)
        meta["wtmp"] = (f"{sum(r['type'] == 'BOOT' for r in wtmp)} demarrages, "
                        f"{sum(r['type'] == 'USER' for r in wtmp)} sessions")
        for r in wtmp:
            if r["type"] in ("BOOT", "USER"):
                desc = "Demarrage" if r["type"] == "BOOT" else f"Session {r['user']} sur {r['line']}"
                events.append(_event(r["time"], "wtmp", r["type"].lower(), desc + (f" depuis {r['host']}" if r["host"] and r["type"] == "USER" else "")))
        extra["wtmp"] = wtmp
    lastlog_path = os.path.join(log_dir, "lastlog")
    if os.path.isfile(lastlog_path):
        extra["lastlog"] = logs.parse_lastlog(lastlog_path)

    unit_names = {os.path.basename(u["unit"]) for u in suspicious}
    for jdir in logs.find_journal_dirs(root):
        journal = logs.parse_journal(jdir, unit_names)
        if journal:
            meta["journald"] = f"{len(journal['boots'])} demarrages, {len(journal['events'])} evenements retenus"
            for e in journal["events"]:
                events.append(_event(e["time"], "journald", e["source"], e["message"]))
            extra["journal"] = journal

    if any(u["user"] == "root" and u["type"] == "USER" for u in extra.get("wtmp", [])):
        techniques.add("T1078.003")
    if techniques:
        meta["MITRE ATT&CK"] = mitre.summary(techniques)
        extra["mitre"] = mitre.describe(techniques)
    extra["timeline_events"] = sorted(events, key=lambda e: e["timestamp"])


def _event(ts: str, source: str, event_type: str, description: str) -> dict:
    return {"timestamp": ts, "source": source, "event_type": event_type,
            "description": description, "file": "", "details": ""}


def _entry_dict(e: bf.BodyEntry) -> dict:
    return {"path": e.path, "uid": e.uid, "mode": e.mode, "size": e.size,
            "created": bf.utc(e.crtime), "modified": bf.utc(e.mtime), "accessed": bf.utc(e.atime)}


class LinuxArtifactsAnalyzer(BaseAnalyzer):
    """Analyse des artefacts forensiques Linux."""
    name = "linux_artifacts"
    supported_extensions = ()

    def can_handle(self, path: str) -> bool:
        return False  # Active uniquement via CLI

    def analyze(self, path: str, bodyfile: str | None = None,
                entries: list | None = None, file_hasher=None) -> FindingModel | None:
        """
        Analyse un chemin racine (/ ou un montage forensique).
        Le path peut etre :
        - Un fichier specifique (bash_history, auth.log)
        - Un repertoire racine a scanner

        `bodyfile` (sortie de `fls -r -m /`) fournit les proprietaires, liens et
        horodatages d'origine, perdus par une copie tsk_recover. `entries` et
        `file_hasher` les fournissent directement depuis l'image (lecture pytsk3).
        """
        try:
            meta: dict = {"Chemin analyse": path}
            extra: dict = {}

            if os.path.isfile(path):
                basename = os.path.basename(path)

                if "history" in basename or "bash_history" in basename:
                    result = parse_bash_history(path)
                    meta["Type"] = "bash_history"
                    meta["Total commandes"] = str(result.get("total_commands", 0))
                    meta["Commandes suspectes"] = str(result.get("suspicious_commands", 0))
                    for i, s in enumerate(result.get("suspicious", [])[:5]):
                        meta[f"Suspect #{i+1}"] = s["command"][:80]
                    extra["bash_history"] = result

                elif "auth.log" in basename or "secure" in basename:
                    result = parse_auth_log(path)
                    meta["Type"] = "auth.log"
                    meta["Logons echoues"] = str(result.get("failed_logins", 0))
                    meta["Logons reussis"] = str(result.get("successful_logins", 0))
                    meta["Commandes sudo"] = str(result.get("sudo_commands", 0))
                    bf = result.get("brute_force_ips", {})
                    if bf:
                        meta["[ALERTE] IPs brute-force"] = ", ".join(
                            f"{ip}({c})" for ip, c in sorted(bf.items(), key=lambda x: -x[1])[:5]
                        )
                    extra["auth_log"] = result

                else:
                    meta["Type"] = "fichier generique"
                    meta["Taille"] = f"{os.path.getsize(path):,} octets"

            elif os.path.isdir(path):
                meta["Type"] = "Scan complet repertoire racine"

                # bash_history
                history_files = glob.glob(os.path.join(path, "home/*/.bash_history"))
                history_files += glob.glob(os.path.join(path, "root/.bash_history"))
                all_history: dict = {}
                for hf in history_files:
                    all_history[hf] = parse_bash_history(hf)
                total_suspicious = sum(h.get("suspicious_commands", 0)
                                      for h in all_history.values())
                meta["Fichiers bash_history"] = str(len(history_files))
                meta["Total commandes suspectes"] = str(total_suspicious)
                extra["bash_histories"] = all_history

                # auth.log
                auth_paths = [
                    os.path.join(path, "var/log/auth.log"),
                    os.path.join(path, "var/log/secure"),
                ]
                for ap in auth_paths:
                    if os.path.isfile(ap):
                        auth_result = parse_auth_log(ap)
                        meta["auth.log - Echecs"] = str(auth_result.get("failed_logins", 0))
                        meta["auth.log - Succes"] = str(auth_result.get("successful_logins", 0))
                        extra["auth_log"] = auth_result
                        break

                # Crontabs
                crons = parse_crontabs(path)
                meta["Entrees cron"] = str(len(crons))
                extra["crontabs"] = crons

                # SSH
                ssh = parse_ssh_artifacts(path)
                meta["Cles SSH"] = str(len(ssh["keys"]))
                meta["Known hosts"] = str(len(ssh["known_hosts"]))
                meta["Authorized keys"] = str(len(ssh["authorized_keys"]))
                extra["ssh"] = ssh

                # /proc (si systeme live)
                proc_dir = os.path.join(path, "proc")
                if os.path.isdir(proc_dir):
                    procs = parse_proc_maps(path)
                    meta["Processus actifs"] = str(len(procs))
                    extra["processes"] = procs[:200]
                    
                # Nouveaux Artefacts (Passwd, Syslog, SUID, Systemd, WTMP)
                accts = parse_passwd_shadow(path)
                meta["Comptes UID 0 (root)"] = ", ".join(accts["uid_0"])
                meta["Comptes avec mot de passe"] = str(len(accts["shadow"]))
                extra["accounts"] = accts
                
                syslog = parse_syslog(path)
                if syslog["anomalies"]:
                    meta["Syslog Anomalies"] = f"{len(syslog['anomalies'])} (ex: {syslog['anomalies'][0]})"
                extra["syslog_anomalies"] = syslog["anomalies"]
                
                suid = find_suid_sgid(path)
                meta["Fichiers SUID/SGID"] = str(len(suid))
                extra["suid_sgid"] = suid
                
                _analyze_incident_artifacts(path, bodyfile, meta, extra, entries, file_hasher)

            return FindingModel(
                type="linux_artifacts",
                file=os.path.abspath(path),
                metadata=meta,
                extra=extra,
            )
        except Exception as exc:
            log.error("Erreur Linux artifacts '%s' : %s", path, exc)
            return None
