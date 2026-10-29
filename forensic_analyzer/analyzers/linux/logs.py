"""Journaux Linux hors ligne : audit.log, wtmp, lastlog et journald.

wtmp et lastlog sont lus en Python pur (structures glibc x86-64), sans dépendre
de `last`. journald est lu via `journalctl --directory`.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import struct
import subprocess

from forensic_analyzer.utils.logger import get_logger

log = get_logger("linux_logs")

_AUDIT_TS = re.compile(r"audit\((\d+)\.(\d+):")
_AUDIT_TYPE = re.compile(r"type=(\w+)")
_AUDIT_FIELDS = re.compile(r"\b(unit|op|grantors|acct|exe|terminal|res|addr|comm)=(\"[^\"]*\"|[^ ']+)")

_UTMP_SIZE = 384
_UTMP_TYPES = {1: "RUN_LVL", 2: "BOOT", 5: "INIT", 6: "LOGIN", 7: "USER", 8: "DEAD"}
_LASTLOG_SIZE = 292

# Messages journald utiles à l'enquête (hors démarrages/arrêts de services, filtrés à part)
_JOURNAL_PATTERNS = re.compile(
    r"ROOT LOGIN|\(to \w+\)|session opened|Accepted (password|publickey)|Failed password"
    r"|System is powering down|The system will reboot|Gained carrier"
)
_UNIT_EVENT = re.compile(r"^(Started|Stopped|Starting|Stopping) (\S+?)(?: - |\.{3}|\.$)")


def _iso(seconds: float) -> str:
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).isoformat()


def _cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def parse_audit_log(path: str) -> dict:
    """Authentifications, échecs, démarrages/arrêts d'unités et nombre d'EXECVE."""
    auth, failures, services = [], [], []
    execve = 0
    with open(path, errors="replace") as f:
        for line in f:
            ts, ty = _AUDIT_TS.search(line), _AUDIT_TYPE.search(line)
            if not ts or not ty:
                continue
            kind = ty.group(1)
            if kind == "EXECVE":
                execve += 1
                continue
            fields = {k: v.strip('"') for k, v in _AUDIT_FIELDS.findall(line)}
            event = {"time": _iso(int(ts.group(1)) + int(ts.group(2)) / 1000), "type": kind, **fields}
            if kind == "USER_AUTH":
                (auth if fields.get("res") == "success" else failures).append(event)
            elif kind in ("SERVICE_START", "SERVICE_STOP"):
                services.append(event)
    return {"auth": auth, "auth_failures": failures, "services": services, "execve_events": execve}


def parse_wtmp(path: str) -> list[dict]:
    """Enregistrements BOOT / USER / RUN_LVL d'un wtmp glibc x86-64."""
    with open(path, "rb") as f:
        data = f.read()
    records = []
    for off in range(0, len(data) - _UTMP_SIZE + 1, _UTMP_SIZE):
        rec = data[off:off + _UTMP_SIZE]
        kind = _UTMP_TYPES.get(struct.unpack("<h", rec[:2])[0])
        if kind not in ("BOOT", "USER", "RUN_LVL"):
            continue
        records.append({
            "time": _iso(struct.unpack("<i", rec[340:344])[0]),
            "type": kind,
            "line": _cstr(rec[8:40]),
            "user": _cstr(rec[44:76]),
            "host": _cstr(rec[76:332]),
        })
    return records


def parse_lastlog(path: str) -> list[dict]:
    """Dernière connexion par UID (lastlog glibc x86-64)."""
    with open(path, "rb") as f:
        data = f.read()
    entries = []
    for uid in range(len(data) // _LASTLOG_SIZE):
        rec = data[uid * _LASTLOG_SIZE:(uid + 1) * _LASTLOG_SIZE]
        ts = struct.unpack("<i", rec[:4])[0]
        if ts:
            entries.append({"uid": uid, "time": _iso(ts), "line": _cstr(rec[4:36]), "host": _cstr(rec[36:292])})
    return entries


def parse_journal(journal_dir: str, units_of_interest: set[str] | None = None) -> dict:
    """
    Démarrages, connexions, su, arrêts et événements des unités d'intérêt.

    `journal_dir` est le dossier contenant les fichiers .journal (var/log/journal/<machine-id>).
    """
    cmd = ["journalctl", f"--directory={journal_dir}", "-o", "json", "--no-pager"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        log.warning("journalctl introuvable : journal systemd non analysé.")
        return {}
    except subprocess.TimeoutExpired:
        log.warning("journalctl trop long sur '%s'.", journal_dir)
        return {}
    if proc.returncode != 0 and not proc.stdout:
        log.warning("journalctl a échoué : %s", proc.stderr.strip()[:200])
        return {}

    boots: dict[str, dict] = {}
    events = []
    units = units_of_interest or set()
    for line in proc.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = int(entry.get("__REALTIME_TIMESTAMP", 0)) / 1e6
        boot_id = entry.get("_BOOT_ID", "")
        boot = boots.setdefault(boot_id, {"boot_id": boot_id, "first": ts, "last": ts})
        boot["first"], boot["last"] = min(boot["first"], ts), max(boot["last"], ts)

        message = entry.get("MESSAGE")
        if not isinstance(message, str):
            continue
        unit_event = _UNIT_EVENT.match(message)
        if _JOURNAL_PATTERNS.search(message) or (unit_event and unit_event.group(2) in units):
            events.append({
                "time": _iso(ts),
                "boot_id": boot_id,
                "source": entry.get("SYSLOG_IDENTIFIER", ""),
                "message": message[:300],
            })

    ordered = sorted(boots.values(), key=lambda b: b["first"])
    for i, b in enumerate(ordered):
        b["index"] = i - len(ordered) + 1  # même convention que journalctl --list-boots
        b["first"], b["last"] = _iso(b["first"]), _iso(b["last"])
    return {"boots": ordered, "events": events}


def find_journal_dirs(root: str) -> list[str]:
    """Dossiers var/log/journal/<machine-id> d'une racine."""
    base = os.path.join(root, "var/log/journal")
    if not os.path.isdir(base):
        return []
    return [os.path.join(base, d) for d in sorted(os.listdir(base))
            if os.path.isdir(os.path.join(base, d))]
