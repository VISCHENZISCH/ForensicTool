"""Analyzer Windows Registry hives (SYSTEM, SAM, NTUSER.DAT)."""
from __future__ import annotations

import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("registry")

try:
    from Registry import Registry as RegistryParser
    HAS_REGISTRY = True
except ImportError:
    HAS_REGISTRY = False
    class DummyRegistry:
        pass
    RegistryParser = DummyRegistry

# Clés d'intérêt forensique
_FORENSIC_KEYS = {
    "NTUSER.DAT": [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        r"Software\Microsoft\Internet Explorer\TypedURLs",
        r"Software\Microsoft\Office",
    ],
    "SYSTEM": [
        r"ControlSet001\Services",
        r"ControlSet001\Control\ComputerName\ComputerName",
        r"ControlSet001\Control\TimeZoneInformation",
        r"Setup",
        r"MountedDevices",
    ],
    "SAM": [
        r"SAM\Domains\Account\Users",
    ],
    "SOFTWARE": [
        r"Microsoft\Windows\CurrentVersion\Run",
        r"Microsoft\Windows\CurrentVersion\RunOnce",
        r"Microsoft\Windows NT\CurrentVersion",
        r"Microsoft\Windows\CurrentVersion\Uninstall",
    ],
}


def _walk_key(key, depth: int = 0, max_depth: int = 3) -> list[dict]:
    """Parcourt recursivement une cle de registre."""
    results = []
    try:
        for value in key.values():
            try:
                results.append({
                    "path": key.path(),
                    "name": value.name(),
                    "type": str(value.value_type()),
                    "value": str(value.value())[:200],
                    "depth": depth,
                })
            except Exception:
                continue

        if depth < max_depth:
            for subkey in key.subkeys():
                try:
                    results.extend(_walk_key(subkey, depth + 1, max_depth))
                except Exception:
                    continue
    except Exception:
        pass
    return results


def _detect_persistence(entries: list[dict]) -> list[dict]:
    """Detecte les mecanismes de persistance dans le registre."""
    persistence = []
    run_paths = {"run", "runonce", "runservicesonce", "runservices"}

    for entry in entries:
        path_lower = entry.get("path", "").lower()
        # Autorun keys
        for run_key in run_paths:
            if run_key in path_lower:
                persistence.append({
                    "type": "Autorun",
                    "key": entry["path"],
                    "name": entry.get("name", ""),
                    "value": entry.get("value", "")[:200],
                })
                break

        # Services
        if "\\services\\" in path_lower and entry.get("name", "").lower() == "imagepath":
            persistence.append({
                "type": "Service",
                "key": entry["path"],
                "name": entry.get("name", ""),
                "value": entry.get("value", "")[:200],
            })

    return persistence


class RegistryAnalyzer(BaseAnalyzer):
    """Analyse des ruches de registre Windows."""
    name = "registry"
    supported_extensions = ('.dat', '.DAT')

    def can_handle(self, path: str) -> bool:
        # Verifier le nom du fichier (SAM, SYSTEM, NTUSER.DAT, SOFTWARE)
        basename = os.path.basename(path).upper()
        return basename in ("SAM", "SYSTEM", "NTUSER.DAT", "SOFTWARE", "SECURITY")

    def analyze(self, path: str) -> FindingModel | None:
        if not HAS_REGISTRY:
            log.error("python-registry requis - pip install python-registry")
            return None
        try:
            reg = RegistryParser.Registry(path)
            basename = os.path.basename(path).upper()

            meta: dict = {
                "Fichier": os.path.basename(path),
                "Taille": f"{os.path.getsize(path):,} octets",
                "Type hive": basename,
            }

            all_entries: list[dict] = []

            # Chercher les cles d'interet
            target_keys = _FORENSIC_KEYS.get(basename, [])
            if not target_keys:
                # Fallback : scanner les cles connues de tous les types
                for keys in _FORENSIC_KEYS.values():
                    target_keys.extend(keys)

            for key_path in target_keys:
                try:
                    key = reg.open(key_path)
                    entries = _walk_key(key, max_depth=2)
                    all_entries.extend(entries)
                    meta[f"Cle: {key_path}"] = f"{len(entries)} valeurs"
                except Exception:
                    continue

            # Detection de persistance
            persistence = _detect_persistence(all_entries)
            if persistence:
                meta["Mecanismes de persistance"] = str(len(persistence))
                for i, p in enumerate(persistence[:5]):
                    meta[f"Persistance #{i+1}"] = f"[{p['type']}] {p['name']}: {p['value'][:80]}"

            meta["Total valeurs analysees"] = str(len(all_entries))

            return FindingModel(
                type="registry",
                file=os.path.abspath(path),
                metadata=meta,
                extra={
                    "entries": all_entries[:500],
                    "persistence": persistence,
                    "hive_type": basename,
                },
            )
        except Exception as exc:
            log.error("Erreur Registry '%s' : %s", os.path.basename(path), exc)
            return None
