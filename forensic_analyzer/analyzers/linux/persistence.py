"""Chasse à la persistance Linux : unités systemd suspectes et emplacements classiques.

Fonctionne sur une racine montée ou extraite. Avec un bodyfile, les propriétaires,
les liens symboliques et les dates de création reflètent l'image d'origine.
"""
from __future__ import annotations

import glob
import os

from forensic_analyzer.analyzers.linux.bodyfile import BodyEntry, utc

_UNIT_SUFFIXES = (".service", ".timer", ".socket", ".path")
_UNIT_DIRS = ("etc/systemd/system", "etc/systemd/user")
_TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/")

# Répertoires où tout fichier non déclaré par un paquet est une persistance potentielle
_WATCHED_DIRS = {
    "etc/cron.d": "T1053.003",
    "etc/cron.hourly": "T1053.003",
    "etc/cron.daily": "T1053.003",
    "etc/cron.weekly": "T1053.003",
    "etc/cron.monthly": "T1053.003",
    "var/spool/cron/crontabs": "T1053.003",
    "etc/profile.d": "T1546.004",
    "etc/sudoers.d": "T1548.003",
    "etc/update-motd.d": "T1546.004",
    "etc/init.d": "T1037.004",
}
_BENIGN_NAMES = {".placeholder", "README"}


def parse_unit(text: str) -> dict[str, dict[str, list[str]]]:
    """Parse un fichier d'unité systemd : {section: {clé: [valeurs]}}."""
    sections: dict[str, dict[str, list[str]]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
        elif "=" in line and current is not None:
            key, value = line.split("=", 1)
            current.setdefault(key.strip(), []).append(value.strip())
    return sections


def _exec_binary(exec_start: str) -> str:
    """Premier argument d'ExecStart, sans les préfixes spéciaux de systemd (-, @, +, !)."""
    cmd = exec_start.lstrip("-@+!:").split()
    return cmd[0] if cmd else ""


def _is_link(root: str, rel: str, body: dict[str, BodyEntry] | None) -> tuple[bool, BodyEntry | None]:
    entry = body.get("/" + rel) if body else None
    if entry is not None:
        return entry.is_link, entry
    return os.path.islink(os.path.join(root, rel)), None


def analyze_systemd(root: str, body: dict[str, BodyEntry] | None = None,
                    owned: set[str] | None = None) -> dict:
    """
    Repère les unités suspectes et les liens d'activation.

    Retourne {"units": [...], "enabled": {unité: [liens]}} ; chaque unité porte un
    score, les raisons et les techniques ATT&CK associées.
    """
    enabled: dict[str, list[dict]] = {}
    unit_files: list[str] = []
    for unit_dir in _UNIT_DIRS:
        base = os.path.join(root, unit_dir)
        for dirpath, _, files in os.walk(base):
            for name in files:
                if not name.endswith(_UNIT_SUFFIXES):
                    continue
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                is_link, entry = _is_link(root, rel, body)
                if is_link or os.path.basename(dirpath).endswith((".wants", ".requires")):
                    enabled.setdefault(name, []).append({
                        "link": "/" + rel,
                        "created": utc(entry.crtime) if entry else "",
                    })
                    continue
                unit_files.append(rel)

    # Liens d'activation connus seulement par les métadonnées (absents d'une extraction partielle)
    if body:
        seen = {link["link"] for links in enabled.values() for link in links}
        for entry in body.values():
            if (entry.is_link and not entry.deleted and entry.path not in seen
                    and entry.path.startswith(tuple("/" + d + "/" for d in _UNIT_DIRS))):
                enabled.setdefault(os.path.basename(entry.path), []).append(
                    {"link": entry.path, "created": utc(entry.crtime)})

    units = []
    for rel in unit_files:
        try:
            with open(os.path.join(root, rel), errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        if "[" not in text:
            continue  # lien symbolique restauré en fichier par tsk_recover, sans bodyfile
        unit = parse_unit(text)
        service = unit.get("Service", {})
        exec_starts = service.get("ExecStart", [])
        binary = _exec_binary(exec_starts[0]) if exec_starts else ""
        name = os.path.basename(rel)
        entry = body.get("/" + rel) if body else None
        bin_entry = body.get(binary) if body and binary else None

        reasons, techniques, score = [], {"T1543.002"}, 0
        hidden = [c for c in binary.split("/") if c.startswith(".")]
        if hidden:
            score += 3
            reasons.append(f"Binaire dans un répertoire caché ({binary})")
            techniques.add("T1564.001")
        if binary.startswith(_TEMP_DIRS):
            score += 3
            reasons.append(f"Binaire dans un emplacement inscriptible ({binary})")
        if owned is not None and binary and binary not in owned and "/usr" + binary not in owned:
            score += 2
            reasons.append("Binaire déclaré par aucun paquet")
        if owned is not None and "/" + rel not in owned and name.startswith("systemd-"):
            score += 2
            reasons.append("Nom imitant une unité systemd officielle")
            techniques.update({"T1036.004", "T1036.005"})
        if entry is not None and entry.uid != 0:
            score += 3
            reasons.append(f"Unité appartenant à l'UID {entry.uid}")
        if bin_entry is not None and bin_entry.uid != 0:
            score += 2
            reasons.append(f"Binaire appartenant à l'UID {bin_entry.uid}")
        if "always" in service.get("Restart", []):
            score += 1
            reasons.append("Relance automatique (Restart=always)")
        if not service.get("User"):
            reasons.append("Exécuté en root (pas de User=)")
        if name in enabled:
            score += 1
            reasons.append("Activée au démarrage")

        units.append({
            "unit": "/" + rel,
            "exec_start": exec_starts,
            "binary": binary,
            "wanted_by": unit.get("Install", {}).get("WantedBy", []),
            "owner_uid": entry.uid if entry else None,
            "created": utc(entry.crtime) if entry else "",
            "modified": utc(entry.mtime) if entry else "",
            "enabled_by": enabled.get(name, []),
            "score": score,
            "suspicious": score >= 3,
            "reasons": reasons,
            "mitre": sorted(techniques) if score >= 3 else [],
        })
    units.sort(key=lambda u: -u["score"])
    return {"units": units, "enabled": enabled}


def other_persistence(root: str, owned: set[str] | None = None) -> list[dict]:
    """ld.so.preload, rc.local, authorized_keys et fichiers non déclarés dans les répertoires surveillés."""
    findings = []

    preload = os.path.join(root, "etc/ld.so.preload")
    if os.path.isfile(preload) and os.path.getsize(preload) > 0:
        with open(preload, errors="replace") as f:
            libs = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        findings.append({"path": "/etc/ld.so.preload", "detail": ", ".join(libs),
                         "severity": "critique", "mitre": "T1574.006"})

    if os.path.isfile(os.path.join(root, "etc/rc.local")):
        findings.append({"path": "/etc/rc.local", "detail": "Script exécuté au démarrage",
                         "severity": "moyenne", "mitre": "T1037.004"})

    key_files = glob.glob(os.path.join(root, "root/.ssh/authorized_keys*"))
    key_files += glob.glob(os.path.join(root, "home/*/.ssh/authorized_keys*"))
    for kf in key_files:
        with open(kf, errors="replace") as f:
            keys = [l for l in f if l.strip() and not l.startswith("#")]
        findings.append({"path": "/" + os.path.relpath(kf, root), "detail": f"{len(keys)} clé(s)",
                         "severity": "moyenne", "mitre": "T1098.004"})

    for rel_dir, technique in _WATCHED_DIRS.items():
        base = os.path.join(root, rel_dir)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            path = f"/{rel_dir}/{name}"
            if name in _BENIGN_NAMES or (owned is not None and path in owned):
                continue
            findings.append({
                "path": path,
                "detail": "Non déclaré par un paquet" if owned is not None else "À vérifier",
                "severity": "haute" if owned is not None else "info",
                "mitre": technique,
            })
    return findings
