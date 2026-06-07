"""Analyzer memoire - wrapper Volatility3 pour dumps RAM."""
from __future__ import annotations
import os
import subprocess
import json
import shutil
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("memory")

# Plugins Volatility3 a executer
_PLUGINS = {
    "pslist":    "windows.pslist.PsList",
    "pstree":    "windows.pstree.PsTree",
    "cmdline":   "windows.cmdline.CmdLine",
    "netscan":   "windows.netscan.NetScan",
    "dlllist":   "windows.dlllist.DllList",
    "handles":   "windows.handles.Handles",
    "malfind":   "windows.malfind.Malfind",
    "hivelist":  "windows.registry.hivelist.HiveList",
    "hashdump":  "windows.hashdump.Hashdump",
    "filescan":  "windows.filescan.FileScan",
}

_LINUX_PLUGINS = {
    "pslist":    "linux.pslist.PsList",
    "pstree":    "linux.pstree.PsTree",
    "bash":      "linux.bash.Bash",
    "lsof":      "linux.lsof.Lsof",
    "ifconfig":  "linux.ifconfig.Ifconfig",
    "mount":     "linux.mountinfo.MountInfo",
}


def _find_vol3() -> str | None:
    """Cherche l'executable vol3 / volatility3 dans le PATH."""
    for name in ("vol", "vol3", "volatility3", "python -m volatility3"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _run_vol3_plugin(vol3_path: str, dump_path: str, plugin: str,
                     timeout: int = 120) -> dict:
    """Execute un plugin Volatility3 et retourne le resultat parse."""
    cmd = [vol3_path, "-f", dump_path, "-r", "json", plugin]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return {
                "success": False,
                "plugin": plugin,
                "error": result.stderr[:500] if result.stderr else "Code retour non-zero",
            }

        try:
            data = json.loads(result.stdout)
            return {"success": True, "plugin": plugin, "data": data}
        except json.JSONDecodeError:
            # Vol3 peut sortir du texte, pas du JSON
            lines = result.stdout.strip().split('\n')
            return {
                "success": True,
                "plugin": plugin,
                "data": lines[:200],
                "format": "text",
            }
    except subprocess.TimeoutExpired:
        return {"success": False, "plugin": plugin, "error": "Timeout"}
    except Exception as exc:
        return {"success": False, "plugin": plugin, "error": str(exc)}


def _detect_injected_processes(malfind_data: dict) -> list[dict]:
    """Analyse les resultats malfind pour detecter les injections."""
    injected = []
    if not malfind_data.get("success"):
        return injected

    data = malfind_data.get("data", [])
    if isinstance(data, list):
        for entry in data[:50]:
            if isinstance(entry, dict):
                injected.append({
                    "pid": entry.get("PID", "?"),
                    "process": entry.get("Process", "?"),
                    "address": entry.get("Start VPN", "?"),
                    "protection": entry.get("Protection", "?"),
                })
    return injected


def _extract_strings_from_dump(dump_path: str, patterns: list[str] | None = None,
                                max_results: int = 500) -> list[str]:
    """Extrait les chaines interessantes du dump memoire."""
    import re

    default_patterns = [
        r'password[\s:=]+\S+',
        r'username[\s:=]+\S+',
        r'https?://\S+',
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        r'NTLM\s+\S+',
        r'Bearer\s+\S+',
        r'Authorization:\s+\S+',
    ]
    search_patterns = patterns or default_patterns

    found = []
    try:
        # Lire par chunks pour economiser la memoire
        chunk_size = 10 * 1024 * 1024  # 10 Mo
        compiled = [re.compile(p.encode(), re.IGNORECASE) for p in search_patterns]

        with open(dump_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for pattern in compiled:
                    for match in pattern.finditer(chunk):
                        decoded = match.group().decode('utf-8', 'replace')
                        if decoded not in found:
                            found.append(decoded)
                        if len(found) >= max_results:
                            return found
    except Exception as exc:
        log.warning("Erreur extraction strings memoire : %s", exc)

    return found


class MemoryAnalyzer(BaseAnalyzer):
    """Analyse de dumps memoire via Volatility3."""
    name = "memory"
    supported_extensions = ('.raw', '.mem', '.dmp', '.vmem', '.lime')

    def analyze(self, path: str, plugins: list[str] | None = None,
                os_type: str = "windows") -> FindingModel | None:
        vol3 = _find_vol3()

        meta: dict = {
            "Fichier dump": os.path.basename(path),
            "Taille dump": f"{os.path.getsize(path):,} octets",
            "OS cible": os_type,
            "Volatility3": vol3 or "NON TROUVE",
        }

        extra: dict = {}

        if vol3:
            plugin_map = _LINUX_PLUGINS if os_type == "linux" else _PLUGINS
            target_plugins = plugins or ["pslist", "cmdline", "netscan", "malfind"]

            results = {}
            for pname in target_plugins:
                if pname not in plugin_map:
                    continue
                log.info("Execution vol3 plugin : %s", pname)
                result = _run_vol3_plugin(vol3, path, plugin_map[pname])
                results[pname] = result

                if result["success"]:
                    data = result.get("data", [])
                    count = len(data) if isinstance(data, list) else 1
                    meta[f"Plugin {pname}"] = f"{count} resultats"
                else:
                    meta[f"Plugin {pname}"] = f"ERREUR: {result.get('error', '?')[:80]}"

            extra["vol3_results"] = results

            # Analyse des injections
            if "malfind" in results:
                injected = _detect_injected_processes(results["malfind"])
                meta["Processus injectes"] = str(len(injected))
                extra["injected_processes"] = injected

        # Extraction de strings / credentials dans le dump
        log.info("Extraction de chaines sensibles du dump...")
        sensitive_strings = _extract_strings_from_dump(path, max_results=200)
        meta["Chaines sensibles trouvees"] = str(len(sensitive_strings))
        extra["sensitive_strings"] = sensitive_strings[:100]

        return FindingModel(
            type="memory",
            file=os.path.abspath(path),
            metadata=meta,
            extra=extra,
        )
