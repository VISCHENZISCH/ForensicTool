"""Comptes et privilèges d'une racine Linux : passwd, shadow, group, sudoers et binaires SUID.

Repères : comptes UID 0 multiples, UID dupliqués, comptes système dotés d'un shell interactif,
mot de passe vide, changements récents de mot de passe (shadow), délégations sudo sans mot
de passe et binaires SUID inattendus (GTFOBins, emplacements inscriptibles).
"""

from __future__ import annotations

import datetime
import glob
import os
import re

from forensic_analyzer.analyzers.linux.bodyfile import BodyEntry, utc

MAX_ACCOUNT_FILE_BYTES = 4 * 1024 * 1024  # passwd / shadow / sudoers d'un serveur : quelques Ko
SYSTEM_UID_MAX = 999  # en dessous : comptes de service (Debian, RHEL)
_INTERACTIVE_SHELLS = ("/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash", "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/sh")
_SERVICE_SHELL_EXPECTED = {"root", "sync", "halt", "shutdown", "postgres", "git", "mysql", "oracle"}
_PRIVILEGED_GROUPS = ("sudo", "wheel", "admin", "root", "docker", "lxd", "disk", "shadow")

# Binaires SUID livrés par les distributions courantes : leur présence n'est pas une anomalie
EXPECTED_SUID = {
    "su", "sudo", "sudoedit", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount", "umount", "ping", "ping6",
    "pkexec", "fusermount", "fusermount3", "ssh-keysign", "dbus-daemon-launch-helper", "Xorg.wrap", "unix_chkpwd",
    "at", "crontab", "wall", "write", "expiry", "chage", "ssh-agent", "polkit-agent-helper-1", "ntfs-3g", "mount.cifs",
    "mount.nfs", "pppd", "snap-confine", "vmware-user-suid-wrapper", "sg", "staprun", "traceroute6.iputils",
    "newuidmap", "newgidmap", "bsd-write", "dotlockfile", "mlocate", "plocate", "utempter", "chrome-sandbox",
    "pam_timestamp_check", "userhelper", "usernetctl", "lockdev", "suexec", "Xorg", "dmcrypt-get-device",
}  # fmt: skip
# Binaires qui, SUID, donnent un shell root (GTFOBins « SUID ») : jamais légitimes ainsi
GTFOBINS_SUID = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "find", "vim", "vi", "nano", "less", "more", "python",
    "python2", "python3", "perl", "ruby", "php", "lua", "node", "nmap", "awk", "gawk", "cp", "mv", "tar", "zip",
    "env", "taskset", "nice", "tee", "dd", "busybox", "socat", "nc", "ncat", "openssl", "gdb", "git", "make", "docker",
    "systemctl", "strace", "time", "timeout", "xargs", "rsync", "base64", "cat", "head", "tail", "ed", "sed", "watch",
}  # fmt: skip
_PYTHON_VERSIONED = re.compile(r"^(?:python|perl|ruby|php|lua)[\d.]*$")
_WRITABLE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/user/")  # nosec B108 - chemins de la preuve
_NOPASSWD_ALL = re.compile(r"^\s*([%\w.-]+)\s+\S+\s*=\s*(?:\([^)]*\)\s*)?NOPASSWD\s*:\s*ALL\b", re.IGNORECASE)
_SUID_SEARCH_DIRS = (
    "bin",
    "sbin",
    "usr/bin",
    "usr/sbin",
    "usr/local/bin",
    "usr/local/sbin",
    "opt",
    "tmp",
    "var/tmp",
    "dev/shm",
    "home",
)


_PASSWD_FIELDS = 7  # nom:mdp:uid:gid:gecos:home:shell
_SHADOW_MIN_FIELDS = 3  # nom:empreinte:dernier changement
_GROUP_FIELDS = 4  # nom:mdp:gid:membres

def _read_lines(path: str) -> list[str]:
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_ACCOUNT_FILE_BYTES)
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()


def _passwd(root: str) -> list[dict]:
    rows = []
    for line in _read_lines(os.path.join(root, "etc/passwd")):
        parts = line.strip().split(":")
        if len(parts) >= _PASSWD_FIELDS and not line.startswith("#"):
            rows.append({"user": parts[0], "pw": parts[1], "uid": parts[2], "gid": parts[3], "home": parts[5], "shell": parts[6]})
    return rows


def _shadow(root: str) -> list[dict]:
    rows = []
    for line in _read_lines(os.path.join(root, "etc/shadow")):
        parts = line.strip().split(":")
        if len(parts) >= _SHADOW_MIN_FIELDS:
            rows.append({"user": parts[0], "hash": parts[1], "lastchg": parts[2]})
    return rows


def _privileged_members(root: str, passwd: list[dict]) -> dict[str, list[str]]:
    """Membres des groupes privilégiés (liste explicite et groupe primaire)."""
    members: dict[str, list[str]] = {}
    gids: dict[str, str] = {}
    for line in _read_lines(os.path.join(root, "etc/group")):
        parts = line.strip().split(":")
        if len(parts) < _GROUP_FIELDS or parts[0] not in _PRIVILEGED_GROUPS:
            continue
        gids[parts[2]] = parts[0]
        users = [u for u in parts[3].split(",") if u]
        if users:
            members[parts[0]] = users
    for p in passwd:
        group = gids.get(p["gid"])
        if group and p["user"] != "root" and p["user"] not in members.get(group, []):
            members.setdefault(group, []).append(p["user"])
    return members


def _days_iso(days: str) -> str:
    if not days.isdigit() or int(days) == 0:
        return ""
    return (datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC) + datetime.timedelta(days=int(days))).isoformat()


def _sudoers_nopasswd(root: str) -> list[dict]:
    """Délégations « NOPASSWD: ALL » hors root : élévation sans aucun secret (T1548.003)."""
    files = [os.path.join(root, "etc/sudoers"), *sorted(glob.glob(os.path.join(root, "etc/sudoers.d/*")))]
    found = []
    for path in files:
        for line in _read_lines(path):
            m = _NOPASSWD_ALL.match(line)
            if m and m.group(1) != "root":
                found.append({"file": "/" + os.path.relpath(path, root), "who": m.group(1), "rule": line.strip()[:200]})
    return found


def analyze_accounts(root: str) -> dict:
    """Anomalies de comptes : [{"label", "detail", "alert", "mitre"}] et événements de chronologie."""
    passwd = _passwd(root)
    shadow = _shadow(root)
    issues: list[dict] = []
    events: list[dict] = []

    def issue(label: str, detail: str, alert: bool, technique: str) -> None:
        issues.append({"label": label, "detail": detail, "alert": alert, "mitre": technique})

    uid0 = [p["user"] for p in passwd if p["uid"] == "0" and p["user"] != "root"]
    if uid0:
        issue("Comptes UID 0 supplémentaires", ", ".join(uid0), True, "T1136.001")
    by_uid: dict[str, list[str]] = {}
    for p in passwd:
        by_uid.setdefault(p["uid"], []).append(p["user"])
    dup = {uid: users for uid, users in by_uid.items() if len(users) > 1 and uid != "0"}
    if dup:
        issue("UID partagés", "; ".join(f"{uid} : {', '.join(u)}" for uid, u in dup.items()), True, "T1078.003")
    shells = [
        f"{p['user']} (uid {p['uid']}, {p['shell']})"
        for p in passwd
        if p["uid"].isdigit() and 0 < int(p["uid"]) <= SYSTEM_UID_MAX
        and p["shell"] in _INTERACTIVE_SHELLS and p["user"] not in _SERVICE_SHELL_EXPECTED
    ]  # fmt: skip
    if shells:
        issue("Comptes de service avec shell interactif", ", ".join(shells), False, "T1078.003")
    empty = [p["user"] for p in passwd if p["pw"] == ""] + [s["user"] for s in shadow if s["hash"] == ""]
    if empty:
        issue("Comptes sans mot de passe", ", ".join(sorted(set(empty))), True, "T1078.003")
    for s in shadow:
        when = _days_iso(s["lastchg"])
        if when and s["hash"] not in ("*", "!", "!!", "!*") and not s["hash"].startswith("!"):
            events.append(_event(when, "shadow", "password_change", f"Dernier changement du mot de passe de {s['user']} (jour)"))
    for item in _sudoers_nopasswd(root):
        issue(f"Sudo sans mot de passe ({item['file']})", f"{item['who']} : {item['rule']}", True, "T1548.003")
    privileged = _privileged_members(root, passwd)
    if privileged:
        issue(
            "Membres des groupes privilégiés", "; ".join(f"{g} : {', '.join(u)}" for g, u in privileged.items()), False, "T1098"
        )
    return {"issues": issues, "events": events, "privileged_groups": privileged}


def _event(ts: str, source: str, kind: str, description: str) -> dict:
    return {"timestamp": ts, "source": source, "event_type": kind, "description": description, "file": "", "details": ""}


def classify_suid(path: str, owned: set[str] | None = None) -> str:
    """Raison pour laquelle un binaire SUID est inattendu, ou "" s'il est banal."""
    name = os.path.basename(path)
    if path.startswith(_WRITABLE_PREFIXES) or "/." in path:
        return "SUID dans un emplacement inscriptible ou caché"
    if name in GTFOBINS_SUID or _PYTHON_VERSIONED.match(name):
        return "SUID sur un binaire qui donne un shell root (GTFOBins)"
    if owned is not None and path not in owned and "/usr" + path not in owned and name not in EXPECTED_SUID:
        return "SUID non déclaré par un paquet"
    return ""


def suid_from_disk(root: str) -> list[str]:
    """Binaires SUID/SGID d'une racine copiée (bits conservés seulement par une copie fidèle)."""
    found = []
    for d in _SUID_SEARCH_DIRS:
        for dirpath, _, files in os.walk(os.path.join(root, d)):
            for f in files:
                fp = os.path.join(dirpath, f)
                try:
                    st = os.lstat(fp)
                except OSError:
                    continue
                if st.st_mode & 0o6000 and not os.path.islink(fp):
                    found.append("/" + os.path.relpath(fp, root))
    return found


def suid_from_bodyfile(entries: list[BodyEntry]) -> list[str]:
    """SUID/SGID d'après le mode du bodyfile (« r/rrwsr-xr-x ») : fidèle même après tsk_recover."""
    found = []
    for e in entries:
        perms = e.mode.split("/")[-1]
        if not e.deleted and perms.startswith("r") and ("s" in perms[1:].lower()[2::3] or perms[3:4] in "sS" and perms[3:4]):
            found.append(e.path)
    return found


def unexpected_suid(paths: list[str], owned: set[str] | None, entries: dict[str, BodyEntry] | None = None) -> list[dict]:
    result = []
    for path in sorted(set(paths)):
        reason = classify_suid(path, owned)
        if reason:
            entry = entries.get(path) if entries else None
            result.append({"path": path, "reason": reason, "modified": utc(entry.mtime) if entry else ""})
    return result
