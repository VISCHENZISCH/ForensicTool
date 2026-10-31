"""Analyzer mémoire - wrapper Volatility3 pour dumps RAM."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from forensic_analyzer.analyzers.disk import layout
from forensic_analyzer.core import mitre
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel, severity_if_alerts
from forensic_analyzer.utils.logger import get_logger

log = get_logger("memory")

# Plugins Volatility3 à exécuter
_PLUGINS = {
    "pslist":    "windows.pslist.PsList",
    "pstree":    "windows.pstree.PsTree",
    "cmdline":   "windows.cmdline.CmdLine",
    "netscan":   "windows.netscan.NetScan",
    "dlllist":   "windows.dlllist.DllList",
    "handles":   "windows.handles.Handles",
    "malfind":   "windows.malfind.Malfind",
    "hivelist":  "windows.registry.hivelist.HiveList",
    "printkey":  "windows.registry.printkey.PrintKey",
    "hashdump":  "windows.hashdump.Hashdump",
    "filescan":  "windows.filescan.FileScan",
    "dumpfiles": "windows.dumpfiles.DumpFiles",
    "ssdt":      "windows.ssdt.SSDT",
}

_LINUX_PLUGINS = {
    "pslist":         "linux.pslist.PsList",
    "psscan":         "linux.psscan.PsScan",
    "pstree":         "linux.pstree.PsTree",
    "psaux":          "linux.psaux.PsAux",
    "bash":           "linux.bash.Bash",
    "envars":         "linux.envars.Envars",
    "lsof":           "linux.lsof.Lsof",
    "sockstat":       "linux.sockstat.Sockstat",
    "ifconfig":       "linux.ip.Addr",
    "mount":          "linux.mountinfo.MountInfo",
    "malfind":        "linux.malware.malfind.Malfind",
    "hidden_modules": "linux.malware.hidden_modules.Hidden_modules",
    "check_syscall":  "linux.malware.check_syscall.Check_syscall",
    "ebpf":           "linux.ebpf.EBPF",
}

_DEFAULT_WINDOWS = ["pslist", "pstree", "cmdline", "netscan", "dlllist", "malfind",
                    "handles", "filescan", "hivelist", "ssdt"]
# Suite de triage Linux : processus (dont cachés), commandes, réseau et contrôles anti-rootkit
_DEFAULT_LINUX = ["pslist", "psscan", "psaux", "bash", "sockstat", "malfind",
                  "hidden_modules", "check_syscall", "ebpf"]

_TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
_SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 6666, 6667, 8888, 9001}


_LINUX_BANNER = re.compile(rb"Linux version (\d+\.\d+[\w.+-]*) \([\x20-\x7e]{1,200}")


def detect_memory_os(path: str, chunk: int = 16 * 1024 * 1024) -> tuple[str, str]:
    """
    (os, bannière) : cherche la bannière du noyau Linux dans le dump, sinon Windows par défaut.

    La lecture se fait par blocs chevauchants et s'arrête à la première bannière trouvée.
    """
    overlap = 512
    with open(path, "rb") as f:
        tail = b""
        for block in iter(lambda: f.read(chunk), b""):
            window = tail + block
            m = _LINUX_BANNER.search(window)
            if m:
                return "linux", m.group(0).decode("utf-8", "replace")
            tail = window[-overlap:]
    return "windows", ""


def find_symbols_dir(dump_path: str) -> str | None:
    """Dossier « symbols » (ISF Volatility) à côté du dump, s'il existe."""
    candidate = os.path.join(os.path.dirname(os.path.abspath(dump_path)), "symbols")
    return candidate if os.path.isdir(candidate) else None


def _find_vol3() -> str | None:
    """Cherche l'exécutable vol3 / volatility3 dans le PATH."""
    for name in ("vol", "vol3", "volatility3", "python -m volatility3"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _run_vol3_plugin(vol3_path: str, dump_path: str, plugin: str,
                     timeout: int = 300, output_dir: str = None,
                     symbols_dir: str | None = None) -> dict:
    """Execute un plugin Volatility3 et retourne le résultat parse."""
    cmd = [vol3_path, "-q", "-f", dump_path, "-r", "json"]
    if symbols_dir:
        # Profil ISF du noyau (indispensable pour Linux)
        cmd.extend(["-s", symbols_dir])
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        cmd.extend(["-o", output_dir])
    cmd.append(plugin)
    
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
                # La 1re ligne de stderr est la bannière "Volatility 3 Framework x.y"
                "error": "\n".join(l for l in result.stderr.splitlines()
                                   if not l.startswith("Volatility 3 Framework"))[:500]
                         if result.stderr else "Code retour non-zero",
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
    """Analyse les résultats malfind pour détecter les injections."""
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

def _detect_ssdt_hooks(ssdt_data: dict) -> list[dict]:
    """Analyse les résultats SSDT pour détecter les hooks rootkits."""
    hooks = []
    if not ssdt_data.get("success"):
        return hooks

    data = ssdt_data.get("data", [])
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                # Un hook SSDT est généralement indiqué si l'adresse pointe hors du kernel (ex: module suspect)
                module = entry.get("Module", "").lower()
                if module and module != "ntoskrnl.exe" and module != "win32k.sys":
                    hooks.append({
                        "index": entry.get("Index", "?"),
                        "function": entry.get("Function", "?"),
                        "module": module,
                    })
    return hooks


def _rows(result: dict | None) -> list[dict]:
    if not result or not result.get("success") or not isinstance(result.get("data"), list):
        return []
    return [r for r in result["data"] if isinstance(r, dict)]


def _is_real_task(row: dict) -> bool:
    """psscan récupère aussi des structures corrompues (PID <= 0, nom vide ou non imprimable)."""
    comm = str(row.get("COMM", ""))
    return isinstance(row.get("PID"), int) and row["PID"] > 0 and comm.isprintable() and comm != ""


def analyze_linux_results(results: dict) -> tuple[dict, dict, set[str]]:
    """Corrélations sur les sorties Volatility Linux : (meta, extra, techniques ATT&CK)."""
    meta: dict = {}
    extra: dict = {}
    techniques: set[str] = set()

    pslist = _rows(results.get("pslist"))
    psscan = _rows(results.get("psscan"))
    if pslist and psscan:
        known = {r["PID"] for r in pslist}
        hidden = [r for r in psscan if _is_real_task(r) and r.get("EXIT_STATE") != "EXIT_DEAD"
                  and r["PID"] not in known]
        exited = [r for r in psscan if _is_real_task(r) and r.get("EXIT_STATE") == "EXIT_DEAD"]
        meta["Processus cachés (psscan hors pslist)"] = str(len(hidden))
        meta["Tâches terminées (psscan)"] = str(len(exited))
        if hidden:
            meta["[ALERTE] Processus cachés"] = ", ".join(f"{r['COMM']} ({r['PID']})" for r in hidden[:10])
            techniques.add("T1014")
        extra["hidden_processes"] = hidden
        extra["exited_tasks"] = exited

    suspicious_procs = []
    for r in _rows(results.get("psaux")):
        args = str(r.get("ARGS", ""))
        exe = args.split()[0] if args else ""
        hidden_dir = any(c.startswith(".") for c in exe.split("/")[:-1])
        if hidden_dir or exe.startswith(_TEMP_DIRS):
            suspicious_procs.append({"pid": r.get("PID"), "ppid": r.get("PPID"), "comm": r.get("COMM"), "args": args})
    if suspicious_procs:
        meta["[ALERTE] Processus lancés depuis un emplacement cache/temporaire"] = ", ".join(
            f"{p['comm']} ({p['pid']}) {p['args']}" for p in suspicious_procs[:10])
        techniques.add("T1564.001")
    extra["suspicious_processes"] = suspicious_procs

    sockets = []
    for r in _rows(results.get("sockstat")):
        if r.get("Family") not in ("AF_INET", "AF_INET6"):
            continue
        dst = str(r.get("Destination Addr", ""))
        try:
            dport = int(r.get("Destination Port", 0))
        except (TypeError, ValueError):
            dport = 0
        if dst not in ("0.0.0.0", "::", "", "127.0.0.1", "::1") or dport in _SUSPICIOUS_PORTS:
            sockets.append({"pid": r.get("PID"), "process": r.get("Process Name"), "proto": r.get("Proto"),
                            "src": f"{r.get('Source Addr')}:{r.get('Source Port')}",
                            "dst": f"{dst}:{dport}", "state": r.get("State")})
    if "sockstat" in results:
        meta["Connexions réseau distantes"] = str(len(sockets))
        if any(int(s["dst"].rsplit(":", 1)[1]) in _SUSPICIOUS_PORTS for s in sockets):
            techniques.add("T1571")
    extra["remote_sockets"] = sockets

    syscalls = _rows(results.get("check_syscall"))
    if syscalls:
        hooked = [r for r in syscalls if not str(r.get("Handler Symbol") or "").startswith("__")]
        meta["Appels système"] = f"{len(syscalls) - len(hooked)}/{len(syscalls)} handlers vers le noyau"
        if hooked:
            meta["[ALERTE] Appels système détournés"] = str(len(hooked))
            techniques.add("T1014")
        extra["hooked_syscalls"] = hooked

    if "hidden_modules" in results and results["hidden_modules"].get("success"):
        mods = _rows(results["hidden_modules"])
        meta["Modules noyau cachés"] = str(len(mods))
        if mods:
            techniques.add("T1014")
        extra["hidden_modules"] = mods

    if "malfind" in results and results["malfind"].get("success"):
        injected = _rows(results["malfind"])
        meta["Régions injectées (malfind)"] = str(len(injected))
        if injected:
            techniques.add("T1055")

    if "ebpf" in results and results["ebpf"].get("success"):
        progs = _rows(results["ebpf"])
        meta["Programmes eBPF chargés"] = str(len(progs))
        extra["ebpf_programs"] = progs

    commands = _rows(results.get("bash"))
    if commands:
        meta["Commandes bash en mémoire"] = str(len(commands))
        techniques.add("T1059.004")
        extra["bash_commands"] = commands

    # Événements dates pour la chronologie consolidée
    created = {r["PID"]: r.get("CREATION TIME", "") for r in pslist}
    events = []
    for p in suspicious_procs:
        if created.get(p["pid"]):
            events.append(_event(created[p["pid"]], "process_created",
                                 f"Processus {p['comm']} (PID {p['pid']}, PPID {p['ppid']}) : {p['args']}"))
    for c in commands:
        if c.get("CommandTime"):
            events.append(_event(c["CommandTime"], "bash_command",
                                 f"Commande bash ({c.get('Process')} {c.get('PID')}) : {c.get('Command')}"))
    extra["timeline_events"] = events

    return meta, extra, techniques


def _event(ts: str, event_type: str, description: str) -> dict:
    return {"timestamp": ts, "source": "memory", "event_type": event_type,
            "description": description, "file": "", "details": ""}


def _extract_strings_from_dump(dump_path: str, patterns: list[str] | None = None,
                                max_results: int = 500) -> list[str]:
    """Extrait les chaînes intéressantes du dump mémoire."""
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

    found = set()
    try:
        # Lire par chunks pour économiser la mémoire
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
                            found.add(decoded)
                        if len(found) >= max_results:
                            return list(found)
    except Exception as exc:
        log.warning("Erreur extraction strings mémoire : %s", exc)

    return list(found)


class MemoryAnalyzer(BaseAnalyzer):
    """Analyse de dumps mémoire via Volatility3."""
    name = "memory"
    heavy = True
    supported_extensions = ('.raw', '.mem', '.dmp', '.vmem', '.lime')

    def can_handle(self, path: str) -> bool:
        # .raw est ambigu : une image disque (table de partitions, système de fichiers) n'est pas un dump
        return super().can_handle(path) and not layout.is_disk_image(path)

    def analyze(self, path: str, plugins: list[str] | None = None,
                os_type: str | None = None, symbols_dir: str | None = None) -> FindingModel | None:
        vol3 = _find_vol3()
        banner = ""
        if not os_type:
            os_type, banner = detect_memory_os(path)
            log.info("OS détecté pour %s : %s", os.path.basename(path), os_type)
        if os_type == "linux" and not symbols_dir:
            symbols_dir = find_symbols_dir(path)

        meta: dict = {
            "Fichier dump": os.path.basename(path),
            "Taille dump": f"{os.path.getsize(path):,} octets",
            "OS cible": os_type + (" (détection automatique)" if banner else ""),
            "Volatility3": vol3 or "NON TROUVE",
        }
        if banner:
            meta["Noyau"] = banner[:150]
        if symbols_dir:
            meta["Symboles (ISF)"] = symbols_dir
        elif os_type == "linux":
            meta["Symboles (ISF)"] = "aucun (--mem-symbols ou dossier 'symbols' à côté du dump)"

        extra: dict = {}

        if vol3:
            plugin_map = _LINUX_PLUGINS if os_type == "linux" else _PLUGINS
            
            # Si non spécifié, on lance une suite standard
            target_plugins = plugins or (_DEFAULT_LINUX if os_type == "linux" else _DEFAULT_WINDOWS)

            results = {}
            out_dir = f"{path}_vol3_dumps" if "dumpfiles" in target_plugins else None
            
            for pname in target_plugins:
                if pname not in plugin_map:
                    continue
                log.info("Exécution vol3 plugin : %s", pname)
                result = _run_vol3_plugin(vol3, path, plugin_map[pname], output_dir=out_dir,
                                          symbols_dir=symbols_dir)
                results[pname] = result

                if result["success"]:
                    data = result.get("data", [])
                    count = len(data) if isinstance(data, list) else 1
                    meta[f"Plugin {pname}"] = f"{count} résultats"
                else:
                    meta[f"Plugin {pname}"] = f"ERREUR: {result.get('error', '?')[:80]}"

            extra["vol3_results"] = results

            if os_type == "linux":
                linux_meta, linux_extra, techniques = analyze_linux_results(results)
                meta.update(linux_meta)
                extra.update(linux_extra)
                if techniques:
                    meta["MITRE ATT&CK"] = mitre.summary(techniques)
                    extra["mitre"] = mitre.describe(techniques)

            # Analyse des injections (Malfind & Process Hollowing)
            elif "malfind" in results:
                injected = _detect_injected_processes(results["malfind"])
                if injected:
                    meta["[ALERTE] Processus injectés"] = str(len(injected))
                extra["injected_processes"] = injected
                
            # Analyse des hooks SSDT (Rootkits)
            if "ssdt" in results:
                hooks = _detect_ssdt_hooks(results["ssdt"])
                if hooks:
                    meta["[ALERTE] Hooks SSDT (Rootkit)"] = str(len(hooks))
                extra["ssdt_hooks"] = hooks

        # Extraction de strings / credentials dans le dump
        log.info("Extraction de chaînes sensibles du dump...")
        sensitive_strings = _extract_strings_from_dump(path, max_results=200)
        meta["Chaînes sensibles trouvées"] = str(len(sensitive_strings))
        extra["sensitive_strings"] = sensitive_strings[:100]

        return FindingModel(
            type="memory",
            file=os.path.abspath(path),
            metadata=meta,
            extra=extra,
            severity=severity_if_alerts(meta, "critique"),
        )
