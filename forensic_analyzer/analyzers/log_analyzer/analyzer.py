"""Analyzer pour les journaux texte Linux et Web (Nginx, Apache, Syslog, Auth, WordPress)."""

from __future__ import annotations

import os
from typing import Any

from forensic_analyzer.core import mitre
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel, severity_if_alerts
from forensic_analyzer.utils.logger import get_logger
from .parsers import (
    detect_log_type,
    parse_file_audit_log,
    parse_syslog_file,
    parse_web_access_log,
    parse_web_error_log,
    parse_wp_debug_log,
)

log = get_logger("log_analyzer")

_MAX_DENIED_SHOWN = 8


class LogAnalyzer(BaseAnalyzer):
    """Analyse des journaux texte système et applicatifs (Web, Syslog, Auth, WP)."""

    name = "log_analyzer"
    supported_extensions = (".log", ".txt", ".gz")

    def can_handle(self, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        basename = os.path.basename(path).lower()

        if basename in ("eve.json", "fast.log"):
            return False

        known_names = (
            "syslog",
            "messages",
            "auth.log",
            "secure",
            "nginx-access.log",
            "nginx-error.log",
            "access.log",
            "error.log",
            "wp-debug.log",
            "debug.log",
        )
        if any(k in basename for k in known_names):
            return True

        if basename.endswith((".log", ".log.1", ".log.gz", ".txt")):
            return True

        return detect_log_type(path) != "unknown"

    def analyze(self, path: str) -> FindingModel | None:
        try:
            log_type = detect_log_type(path)
            if log_type == "unknown":
                log.debug("Type de log non reconnu pour '%s'", path)
                return None

            log.info("Analyse du journal [%s] : %s", log_type, os.path.basename(path))

            meta: dict[str, Any] = {
                "Format": log_type,
            }
            extra: dict[str, Any] = {
                "log_type": log_type,
                "timeline_events": [],
                "iocs": {"ips": set(), "urls": set()},
            }
            incomplete: list[str] = []
            level = "élevé"

            if log_type == "file_audit":
                res = parse_file_audit_log(path)
                _audit_metadata(res, meta)
                extra["details"] = res
                extra["timeline_events"] = res["events"]
                extra["iocs"]["ips"] = set(res["offender_ips"])
                if res["mass_renames"]:
                    level = "critique"
                    extra["mitre"] = mitre.describe(["T1486"])
                incomplete.extend(_unparsed(res))

            elif log_type == "web_access":
                res = parse_web_access_log(path)
                incomplete.extend(_unparsed(res))
                meta["Total requêtes"] = f"{res['valid_entries']:,}"
                meta["Adresses IP uniques"] = str(res["unique_ips"])
                if res["top_ips"]:
                    meta["Top IP sources"] = ", ".join(f"{ip} ({cnt})" for ip, cnt in res["top_ips"][:5])
                if res["suspicious_requests"]:
                    meta["[ALERTE] Attaques web détectées"] = (
                        f"{len(res['suspicious_requests'])} (ex: {res['suspicious_requests'][0]['attack']})"
                    )
                if res["webshell_hits"]:
                    meta["[ALERTE] Accès Webshell"] = f"{len(res['webshell_hits'])} requête(s) vers un webshell !"
                if res["scanners"]:
                    meta["[ALERTE] Scanners automatisés"] = ", ".join(res["scanners"][:5])
                for bf in res["brute_force"]:
                    outcome = "RÉUSSI (HTTP 302)" if bf["succeeded"] else "sans succès"
                    meta[f"[ALERTE] Brute-force {bf['ip']}"] = (
                        f"{bf['attempts']} tentatives ({bf['first'][11:19]} → {bf['last'][11:19]}), {outcome}"
                    )
                if res["uploads"]:
                    meta["[ALERTE] Téléversements"] = ", ".join(f"{u['ip']} → {u['uri']}" for u in res["uploads"][:3])
                if res["webshell_commands"]:
                    meta["[ALERTE] Commandes via webshell"] = " ; ".join(c["command"] for c in res["webshell_commands"][:8])
                for ex in res["exfiltration"]:
                    meta[f"[ALERTE] Exfiltration {ex['uri'].rsplit('/', 1)[-1]}"] = (
                        f"téléchargé par {ex['ip']} ({ex['bytes'] / 1024 / 1024:.1f} Mo)"
                    )
                if res["attackers"]:
                    meta["IP offensives"] = ", ".join(res["attackers"])

                extra["details"] = res
                extra["timeline_events"] = res.get("events", [])
                # Indicateurs : IP qui ont agi comme attaquant, pas les clients les plus actifs
                extra["iocs"]["ips"] = set(res["attackers"])

            elif log_type == "web_error":
                res = parse_web_error_log(path)
                meta["Total lignes d'erreur"] = f"{res['total_lines']:,}"
                if res["error_levels"]:
                    meta["Niveaux d'erreur"] = ", ".join(f"{lvl}: {cnt}" for lvl, cnt in res["error_levels"].items())
                for i, err in enumerate(res["suspicious_errors"][:8], 1):
                    client = f" (client {err['client']})" if err.get("client") else ""
                    meta[f"[ALERTE] Erreur serveur #{i}"] = (
                        f"{str(err['timestamp'])[:19]} [{err['level']}] {err['message']}{client}"
                    )
                if res["client_errors"]:
                    meta["Top clients en erreur"] = ", ".join(f"{ip} ({cnt})" for ip, cnt in res["client_errors"][:5])

                extra["details"] = res
                extra["timeline_events"] = res.get("events", [])
                extra["iocs"]["ips"] = {ip for ip, _ in res["client_errors"]}

            elif log_type == "syslog":
                res = parse_syslog_file(path)
                meta["Lignes analysées"] = f"{res['total_lines']:,}"
                meta["Échecs d'authentification"] = str(res["auth_failures"])
                meta["Succès d'authentification"] = str(res["auth_successes"])
                if res["ssh_sources"]:
                    meta["Comptes / sources SSH"] = f"{len(res['ssh_sources'])} : " + ", ".join(res["ssh_sources"][:8])
                meta["Commandes SUDO"] = str(len(res["sudo_commands"]))
                if res["failed_ips"]:
                    meta["[ALERTE] Top IPs brute-force (SSH)"] = ", ".join(f"{ip} ({cnt})" for ip, cnt in res["failed_ips"][:5])
                if res["sudo_commands"]:
                    meta["Commandes sudo"] = " ; ".join(
                        f"{c['user']} : {c['command'][:80]} ({'REFUSÉE' if c['denied'] else 'exécutée'})"
                        for c in res["sudo_commands"][:5]
                    )
                for i, n in enumerate([n for n in res["notable"] if n["alert"]][:8], 1):
                    meta[f"[ALERTE] Événement #{i}"] = f"{n['timestamp'][:19]} {n['description']}"

                extra["details"] = res
                extra["timeline_events"] = res.get("events", [])
                extra["iocs"]["ips"] = {ip for ip, _ in res["failed_ips"]} | set(res["notable_ips"])

            elif log_type == "wp_debug":
                res = parse_wp_debug_log(path)
                meta["Lignes de debug"] = f"{res['total_lines']:,}"
                meta["Erreurs fatales PHP"] = str(len(res["fatal_errors"]))
                meta["Avertissements PHP"] = str(res["warnings_count"])
                if res["referenced_files"]:
                    meta["Fichiers PHP impliqués"] = ", ".join(os.path.basename(f) for f in res["referenced_files"][:5])
                if res["fatal_errors"]:
                    meta["[ALERTE] Dernière erreur fatale"] = res["fatal_errors"][-1]["message"][:100]
                for i, note in enumerate(res["notable"][:8], 1):
                    meta[f"[ALERTE] Événement WordPress #{i}"] = note

                extra["details"] = res
                extra["timeline_events"] = res.get("events", [])
                extra["referenced_files"] = res["referenced_files"]

            # Convert sets to sorted lists in extra["iocs"]
            extra["iocs"]["ips"] = sorted(list(extra["iocs"]["ips"]))
            extra["iocs"]["urls"] = sorted(list(extra["iocs"]["urls"]))

            return FindingModel(
                type="log_analysis",
                file=os.path.abspath(path),
                metadata=meta,
                extra=extra,
                severity=severity_if_alerts(meta, level),
                incomplete=incomplete,
            )
        except Exception as exc:
            log.error("Erreur d'analyse sur le journal '%s' : %s", path, exc)
            return None


def _unparsed(res: dict[str, Any]) -> list[str]:
    missed = res["total_lines"] - res["valid_entries"]
    return [f"{missed} ligne(s) sur {res['total_lines']} au format non reconnu"] if missed else []


def _audit_metadata(res: dict[str, Any], meta: dict[str, Any]) -> None:
    meta["Lignes d'audit"] = f"{res['valid_entries']:,}"
    if res["accounts"]:
        meta["Comptes et postes"] = ", ".join(res["accounts"][:10])
    offenders = set()
    for m in res["mass_renames"]:
        offenders.add(m["user"])
        shares = ", ".join(m["shares"]) or "?"
        extensions = f", extension {', '.join(m['extensions'])}" if m["extensions"] else ""
        meta[f"[ALERTE] Renommage de masse par {m['user']}"] = (
            f"{m['total']} fichiers sur le poste {m['host'] or '?'}, partage {shares}, "
            f"en {m['seconds']} s ({m['first'][11:19]} → {m['last'][11:19]} UTC){extensions}"
        )
    for d in res["denied"][:_MAX_DENIED_SHOWN]:
        key = "[ALERTE] Accès refusé" if d["user"] in offenders else "Accès refusé"
        meta[f"{key} {d['timestamp'][11:19]}"] = f"{d['user']} sur {d['host']} : {d['path']} (partage {d['share'] or '?'})"
    if res["denied_total"] > _MAX_DENIED_SHOWN:
        meta["Accès refusés (total)"] = str(res["denied_total"])
    if res["responses"]:
        meta["Actions de confinement"] = "\n".join(f"{r['timestamp'][11:19]} {r['description']}" for r in res["responses"][:10])
