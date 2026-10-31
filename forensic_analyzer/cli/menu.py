"""
Menu interactif principal pour Forensic Analyzer.
Style : ASCII art, codes couleur ANSI, sans rich.
"""
from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import os
import shutil
import time

from forensic_analyzer.core.correlation import correlate
from forensic_analyzer.core.scanner import auto_scan, default_registry, targeted_scan
from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.output import ui
from forensic_analyzer.utils.exports import export_root, new_case_dir

# Option -> (libelle, "module:Classe" ou action spéciale, invite)
# Les modules d'analyse sont chargés à l'écran de démarrage, pas à l'import du menu.
_MENU_DISPATCH = {
    "1":  ("PDF - Métadonnées",   "pdf:PDFAnalyzer",                         "Fichier PDF ou dossier"),
    "2":  ("Image / EXIF",        "image:ImageAnalyzer",                     "Image ou dossier"),
    "3":  ("Coordonnées GPS",     "gps:GPSAnalyzer",                         "Image ou dossier"),
    "4":  ("Extraction Strings",  "strings:StringsAnalyzer",                 "Fichier binaire ou dossier"),
    "5":  ("Historique Firefox",  "firefox:FirefoxHistoryAnalyzer",          "places.sqlite ou dossier de profil"),
    "6":  ("Cookies Firefox",     "firefox:FirefoxCookiesAnalyzer",          "cookies.sqlite ou dossier de profil"),
    "7":  ("Artefacts Chromium",  "chromium:ChromiumAnalyzer",               "Base Chromium (History, Cookies...) ou dossier de profil"),
    "8":  ("Stéganographie",      "stego:StegoAnalyzer",                     "Image / WAV ou dossier"),
    "9":  ("File Carving",        "carving:CarvingAnalyzer",                 "Fichier (.dd, .img, .bin, .raw...) ou dossier"),
    "10": ("Analyse PCAP",        "pcap:PCAPAnalyzer",                       "Capture (.pcap, .pcapng, .cap) ou dossier"),
    "11": ("Triage Malware (PE)", "malware:MalwareAnalyzer",                 "Exécutable (.exe, .dll, .sys) ou dossier"),
    "12": ("Windows Event Logs",  "evtx:EVTXAnalyzer",                       "Fichier .evtx ou dossier"),
    "13": ("Registre Windows",    "registry:RegistryAnalyzer",               "Ruche (SAM, SYSTEM, NTUSER.DAT) ou dossier"),
    "14": ("Artefacts Linux",     "linux:LinuxArtifactsAnalyzer",            "Racine du système ou fichier (bash_history, auth.log)"),
    "15": ("Analyse mémoire RAM", "memory:MemoryAnalyzer",                   "Dump mémoire ou dossier"),
    "16": ("Forensique disque",   "disk:DiskAnalyzer",                       "Image disque ou dossier"),
    "17": ("Exécution Windows",   "windows_execution:WindowsExecutionAnalyzer", "Prefetch (.pf) / LNK ou dossier"),
    "18": ("Scan YARA",           "yara:YARAAnalyzer",                       None),
    "19": ("Extraction IOC",      "ioc:IOCAnalyzer",                         "Fichier ou dossier"),
    "20": ("Timeline DFIR",       "timeline:TimelineAnalyzer",               None),
    "21": ("Journaux Web / Système", "log_analyzer:LogAnalyzer",             "Journal (access.log, error.log, syslog, auth.log, wp-debug.log, .gz) ou dossier"),
    "22": ("Détection Webshell",  "webshell:WebshellAnalyzer",               "Script (.php, .phtml...) ou dossier"),
    "23": ("Rapport Nmap (XML)",  "nmap:NmapAnalyzer",                       "Rapport nmap -oX ou dossier"),
}

# Fichiers que le scan automatique n'a pu attribuer à aucun module pendant la session
_SESSION_SKIPPED: list[str] = []
_SESSION_NOTES: list[str] = []
_SESSION_ERRORS: list[str] = []

# Classes chargées par _boot_sequence ; une option absente est indisponible
_LOADED: dict[str, type] = {}

_LIBRARIES = [
    # (module, distribution pip, fonctionnalité, options du menu inutilisables sans elle)
    ("scapy", "scapy", "Réseau (PCAP)", ("10",)),
    ("yara", "yara-python", "Règles YARA", ("18",)),
    ("pefile", "pefile", "Binaires PE", ()),
    ("Evtx", "python-evtx", "Journaux EVTX", ("12",)),
    ("Registry", "python-registry", "Ruches du registre", ("13",)),
    ("pytsk3", "pytsk3", "Images disque (TSK)", ()),
    ("capstone", "capstone", "Désassemblage", ()),
    ("PIL", "Pillow", "Images / stéganographie", ("2",)),
    ("exifread", "ExifRead", "EXIF / GPS", ("3",)),
    ("pypdf", "pypdf", "Métadonnées PDF", ()),
    ("LnkParse3", "LnkParse3", "Raccourcis LNK", ()),
    ("pyscca", "libscca-python", "Prefetch", ()),
    ("oletools", "oletools", "Macros VBA", ()),
    ("volatility3", "volatility3", "Mémoire (Volatility 3)", ()),
    ("weasyprint", "weasyprint", "Export PDF", ()),
]

_TOOLS = [
    # (libelle, exécutables possibles, fonctionnalité, options du menu inutilisables sans lui)
    ("tshark", ("tshark",), "Identités / JA3 (PCAP)", ()),
    ("fls", ("fls",), "Bodyfile disque (repli TSK)", ()),
    ("volatility", ("vol", "vol3", "volatility3"), "Analyse mémoire", ("15",)),
    ("capa", ("capa",), "Capacités des binaires", ()),
    ("steghide", ("steghide",), "Stégano JPEG / WAV", ()),
]


def _disabled_label(options: tuple[str, ...]) -> str:
    return "[" + ", ".join(options) + "] indisponible" if options else "fonction réduite"


def _run_analysis(analyzer, path: str, **kwargs) -> list[FindingModel]:
    """Execute un analyzer sur un fichier et affiche le résultat."""
    ui.status("Analyse en cours...")
    try:
        result = analyzer.analyze(path, **kwargs) if kwargs else analyzer.analyze(path)
    except Exception as exc:
        ui.error(f"Erreur d'analyse : {exc}")
        return []
    results = [r for r in (result if isinstance(result, list) else [result]) if r]
    if not results:
        ui.warning("Aucun résultat pour ce fichier.")
        return []
    ui.success("Analyse terminée avec succès.")
    for res in results:
        ui.render_finding(res)
    return results


def _run_on_path(analyzer, path: str, **kwargs) -> list[FindingModel]:
    """Fichier : analyse directe. Dossier : seuls les fichiers du type de l'analyzer, comme le scan [88]."""
    if os.path.isfile(path) or analyzer.takes_directory:
        return _run_analysis(analyzer, path, **kwargs)

    ui.status(f"Analyse en cours de : {path}")
    report = targeted_scan(analyzer, path, **kwargs)
    if not report.findings:
        ui.warning("Aucun fichier de ce type dans le dossier.")
        return []
    for finding in report.findings:
        ui.render_finding(finding)
    ui.render_summary(report)
    return report.findings


def _handle_export(session_findings: list[FindingModel]) -> None:
    """Gère le sous-menu d'export."""
    if not session_findings:
        ui.warning("Aucun résultat en mémoire à exporter.")
        return

    from forensic_analyzer.analyzers.timeline import TimelineAnalyzer

    # Vue transverse ajoutée à chaque export : correlation puis chronologie consolidée
    base = [f for f in session_findings if f.type not in ("correlation", "timeline")]
    correlation = correlate(base)
    enriched = base + ([correlation] if correlation else [])
    timeline = TimelineAnalyzer().build_from_report(ReportModel.from_findings(enriched))
    if timeline.extra.get("events"):
        enriched.append(timeline)
    report = ReportModel.from_findings(enriched, skipped_files=list(_SESSION_SKIPPED), scan_notes=list(_SESSION_NOTES),
                                       analysis_errors=list(_SESSION_ERRORS))
    ui.export_menu()

    choice = ui.prompt("export").upper()

    if choice == "R":
        return

    exporters = {
        "J": ("forensic_analyzer.output.json_exporter", "JSONExporter", "JSON de sortie (.json)", "Rapport JSON"),
        "H": ("forensic_analyzer.output.html_exporter", "HTMLExporter", "HTML de sortie (.html)", "Rapport HTML interactif"),
        "C": ("forensic_analyzer.output.csv_exporter", "CSVExporter", "CSV de sortie (.csv)", "Timeline CSV"),
        "P": ("forensic_analyzer.output.pdf_exporter", "PDFExporter", "PDF de sortie (.pdf)", "Rapport PDF"),
    }
    if choice in exporters:
        module, cls, what, label = exporters[choice]
        path = ui.prompt_input(f"Entrez le chemin du fichier {what}")
        if path:
            try:
                target = getattr(importlib.import_module(module), cls)().export(report, path)
                ui.success(f"{label} exporté dans : {target}")
            except Exception as exc:   # le menu reste utilisable après un export raté
                ui.error(f"{label} non exporté : {type(exc).__name__} : {exc}")

    elif choice == "G":
        path = ui.prompt_input("Entrez le chemin du graphe HTML de sortie (.html)")
        if path and correlation:
            from forensic_analyzer.output.graph_renderer import render_correlation_graph
            os.makedirs(export_root(), exist_ok=True)
            target_path = os.path.join(export_root(), os.path.basename(path))
            if render_correlation_graph(correlation, target_path):
                ui.success(f"Graphe de corrélation exporté dans : {target_path}")
            else:
                ui.warning("Aucun indicateur partagé entre sources : graphe non généré.")
        elif path:
            ui.warning("Aucun indicateur extrait : graphe non généré.")

    elif choice == "S":
        from forensic_analyzer.output.rules_generator import DefenseRulesGenerator
        outputs = DefenseRulesGenerator().generate(report, output_dir=os.path.join(export_root(), "rules"))
        if outputs:
            ui.success(f"{len(outputs)} fichier(s) de règles et STIX exportés dans {os.path.join(export_root(), 'rules')}")
        else:
            ui.warning("Aucun indicateur exploitable : pas de règle générée.")

    else:
        ui.error("Option d'export invalide.")


def _boot_sequence() -> dict[str, str]:
    """
    Vérifications réelles du démarrage : bibliothèques, outils externes, puis chargement
    des modules d'analyse. Retourne les options indisponibles et leur cause.
    """
    start = time.perf_counter()
    ok = total = warnings = 0
    disabled: dict[str, str] = {}
    ui.clear_screen()

    ui.boot_section("Bibliothèques")
    for module, dist, role, options in _LIBRARIES:
        try:
            present = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            present = False
        try:
            version = importlib.metadata.version(dist) if present else "absente"
        except importlib.metadata.PackageNotFoundError:
            version = "installée"
        ui.boot_item(present, dist, version, role if present else f"{role} : {_disabled_label(options)}")
        if not present:
            disabled.update(dict.fromkeys(options, f"bibliothèque {dist} absente (pip install {dist})"))
        total += 1
        ok += present
        warnings += not present

    ui.boot_section("Outils externes (optionnels)")
    for label, names, role, options in _TOOLS:
        path = next((p for p in map(shutil.which, names) if p), None)
        ui.boot_item(bool(path), label, path or ("absent" if options else "absent : repli interne"),
                     role if path or not options else f"{role} : {_disabled_label(options)}")
        if not path:
            disabled.update(dict.fromkeys(options, f"outil {label} introuvable dans le PATH"))
            warnings += bool(options)
        total += 1
        ok += bool(path)

    targets = {entry[1] for entry in _MENU_DISPATCH.values()}
    modules = sorted({t.split(":")[0] for t in targets})
    failures: dict[str, str] = {}
    for module in modules:
        try:
            loaded = importlib.import_module(f"forensic_analyzer.analyzers.{module}")
        except Exception as exc:
            failures[module] = f"{type(exc).__name__}: {exc}"
            continue
        for target in targets:
            if target.startswith(f"{module}:"):
                _LOADED[target] = getattr(loaded, target.split(":")[1])
    if failures:
        ui.boot_section("Modules d'analyse")
    for module, reason in failures.items():
        ui.boot_item(False, module, "non chargé", reason)
    total += len(modules)
    ok += len(modules) - len(failures)
    warnings += len(failures)

    ui.boot_footer(ok, total, warnings, time.perf_counter() - start)
    ui.wait_for_key()
    for key, entry in _MENU_DISPATCH.items():
        module = entry[1].split(":")[0]
        if module in failures:
            disabled.setdefault(key, f"module {module} non chargé : {failures[module]}")
    return disabled


def interactive_loop() -> None:
    """Boucle interactive principale."""
    unavailable = _boot_sequence()
    new_case_dir("session")

    session_findings: list[FindingModel] = []

    while True:
        ui.banner()
        ui.menu(frozenset(unavailable))

        choice = ui.prompt("menu")

        if not choice:
            continue

        # Normaliser les choix à deux chiffres comme 01-09 en 1-9, tout en gardant 00
        if choice.isdigit() and choice != "00":
            choice = str(int(choice))

        if choice == "00" or choice == "0":
            print()
            ui.info("Fermeture de Forensic Analyzer.")
            if session_findings:
                ui.warning(f"Vous avez {len(session_findings)} analyse(s) en mémoire.")
                ans = ui.prompt_input("Voulez-vous exporter les résultats avant de quitter ? (o/n)", required=False)
                if ans and ans.lower() in ("o", "oui", "y", "yes"):
                    _handle_export(session_findings)
            print()
            break

        if choice == "88":
            path = ui.prompt_file("Entrez le chemin du fichier ou dossier à scanner")
            if path is None:
                continue

            ui.status(f"Scan automatique en cours de : {path}")
            report = auto_scan(path, default_registry())

            for finding in report.findings:
                ui.render_finding(finding)
                session_findings.append(finding)
            _SESSION_SKIPPED.extend(f for f in report.skipped_files if f not in _SESSION_SKIPPED)
            _SESSION_NOTES.extend(n for n in report.scan_notes if n not in _SESSION_NOTES)
            _SESSION_ERRORS.extend(e for e in report.analysis_errors if e not in _SESSION_ERRORS)

            ui.render_summary(report)
            # Vue transverse de la session : corrélation puis chronologie, reprises dans les exports
            from forensic_analyzer.analyzers.timeline import TimelineAnalyzer
            session_findings[:] = [f for f in session_findings if f.type not in ("correlation", "timeline")]
            correlation = correlate(session_findings)
            if correlation:
                session_findings.append(correlation)
            timeline = TimelineAnalyzer().build_from_report(ReportModel.from_findings(session_findings))
            if timeline.extra.get("events"):
                session_findings.append(timeline)
            ui.render_conclusion(ReportModel.from_findings(session_findings, skipped_files=list(_SESSION_SKIPPED),
                                                           scan_notes=list(_SESSION_NOTES),
                                                           analysis_errors=list(_SESSION_ERRORS)))
            ui.wait_for_key()
            continue

        if choice == "99":
            _handle_export(session_findings)
            ui.wait_for_key()
            continue

        if choice not in _MENU_DISPATCH:
            ui.error("Option invalide. Veuillez choisir un numéro du menu.")
            ui.wait_for_key()
            continue

        if choice in unavailable:
            ui.error(f"Option {choice} indisponible : {unavailable[choice]}.")
            ui.wait_for_key()
            continue

        _, target, prompt_msg = _MENU_DISPATCH[choice]
        cls = _LOADED[target]

        if choice == "20":
            if not session_findings:
                ui.warning("Aucun résultat en mémoire pour construire la timeline : "
                           "lancez d'abord une analyse (option 1 à 23 ou scan automatique 88).")
                ui.wait_for_key()
                continue
            ui.status("Corrélation et construction de la timeline unifiée...")
            # Une seule vue transverse à jour : les précédentes ne nourrissent pas la nouvelle
            session_findings[:] = [f for f in session_findings if f.type not in ("correlation", "timeline")]
            correlation = correlate(session_findings)
            if correlation:
                ui.render_finding(correlation)
                session_findings.append(correlation)
            result = cls().build_from_report(ReportModel.from_findings(session_findings))
            if result.extra.get("events"):
                ui.render_finding(result)
                session_findings.append(result)
            else:
                ui.warning("Aucun événement daté dans les résultats en mémoire.")
            ui.wait_for_key()
            continue

        if choice == "18":
            rules_path = ui.prompt_file("Entrez le chemin du fichier ou dossier de règles YARA (.yar)")
            if rules_path is None:
                continue
            target_path = ui.prompt_file("Entrez le chemin du fichier ou dossier à scanner")
            if target_path is None:
                continue
            session_findings.extend(_run_on_path(cls(rules_path), target_path))
            ui.wait_for_key()
            continue

        path = ui.prompt_file(f"Chemin : {prompt_msg}")
        if path is None:
            continue

        kwargs = {}
        if choice == "15":
            plugins_str = ui.prompt_input("Plugins Volatility3 (optionnels, séparés par des virgules)", required=False)
            os_type = ui.prompt_input("OS cible (windows/linux, défaut : détection automatique)", required=False) or None
            symbols = None
            if os_type == "linux":
                symbols = ui.prompt_input("Dossier des symboles ISF (optionnel)", required=False) or None
            kwargs = {"plugins": plugins_str.split(",") if plugins_str else None,
                      "os_type": os_type, "symbols_dir": symbols}
        elif choice == "14" and os.path.isdir(path):
            kwargs["bodyfile"] = ui.prompt_input("Bodyfile TSK de l'image (optionnel, fls -r -m /)", required=False) or None

        session_findings.extend(_run_on_path(cls(), path, **kwargs))
        ui.wait_for_key()
