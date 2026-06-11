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
        r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        r"Software\Microsoft\Office",
    ],
    "SYSTEM": [
        r"ControlSet001\Services",
        r"ControlSet001\Control\ComputerName\ComputerName",
        r"ControlSet001\Control\TimeZoneInformation",
        r"ControlSet001\Enum\USBSTOR",
        r"ControlSet001\Services\bam\State\UserSettings",
        r"ControlSet001\Services\dam\UserSettings",
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
        r"Microsoft\Windows NT\CurrentVersion\AppCompatFlags\AppCompatCache",
        r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
        r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged",
    ],
    "AMCACHE.HVE": [
        r"Root\File",
        r"Root\Programs",
        r"Root\InventoryApplicationFile",
    ]
}


def _walk_key(key, depth: int = 0, max_depth: int = 3) -> list[dict]:
    """Parcourt recursivement une cle de registre."""
    results = []
    try:
        try:
            ts = key.timestamp().isoformat() if hasattr(key, 'timestamp') else ""
        except: ts = ""
        
        import codecs
        for value in key.values():
            try:
                v_name = value.name()
                
                # ROT13 pour UserAssist
                if "UserAssist" in key.path() and v_name:
                    try: v_name = codecs.decode(v_name, 'rot_13')
                    except: pass
                    
                v_val = str(value.value())[:500]
                
                # Détection clés anormales
                suspect = False
                val_lower = v_val.lower()
                if "\\appdata\\local\\temp\\" in val_lower or "\\programdata\\" in val_lower or "c:\\users\\public\\" in val_lower:
                    if ".exe" in val_lower or ".ps1" in val_lower or ".bat" in val_lower or ".dll" in val_lower:
                        suspect = True
                if "powershell" in val_lower and ("-enc" in val_lower or "hidden" in val_lower or "bypass" in val_lower):
                    suspect = True
                if len(v_name) > 30 and " " not in v_name: # Random encoded name
                    suspect = True
                    
                results.append({
                    "path": key.path(),
                    "name": v_name,
                    "type": str(value.value_type()),
                    "value": v_val,
                    "timestamp": ts,
                    "depth": depth,
                    "suspect": suspect
                })
            except Exception as exc:
                pass  # TODO: log.debug(exc)
                continue

        if depth < max_depth:
            for subkey in key.subkeys():
                try:
                    results.extend(_walk_key(subkey, depth + 1, max_depth))
                except Exception as exc:
                    pass  # TODO: log.debug(exc)
                    continue
    except Exception as exc:
        pass  # TODO: log.debug(exc)
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
        # Verifier le nom du fichier (SAM, SYSTEM, NTUSER.DAT, SOFTWARE, AMCACHE)
        basename = os.path.basename(path).upper()
        return basename in ("SAM", "SYSTEM", "NTUSER.DAT", "SOFTWARE", "SECURITY", "AMCACHE.HVE")

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
                except Exception as exc:
                    pass  # TODO: log.debug(exc)
                    continue

            # Detection de persistance
            persistence = _detect_persistence(all_entries)
            if persistence:
                meta["Mecanismes de persistance"] = str(len(persistence))
                for i, p in enumerate(persistence[:5]):
                    meta[f"Persistance #{i+1}"] = f"[{p['type']}] {p['name']}: {p['value'][:80]}"

            # Extract Suspects
            suspects = [e for e in all_entries if e.get("suspect")]
            if suspects:
                meta["[ALERTE] Clés Suspectes"] = f"{len(suspects)} détectées"
                for i, s in enumerate(suspects[:3]):
                    meta[f"Suspect #{i+1}"] = f"{s['name']} -> {s['value'][:50]} (Mis à jour: {s['timestamp']})"

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
