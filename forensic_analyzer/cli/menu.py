"""
Menu interactif principal pour Forensic Analyzer.
Style : ASCII art, codes couleur ANSI, sans rich.
"""
from __future__ import annotations
import os
import sys

from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.output import ui
from forensic_analyzer.output.ui import C
from forensic_analyzer.output.json_exporter import JSONExporter
from forensic_analyzer.output.html_exporter import HTMLExporter
from forensic_analyzer.output.csv_exporter import CSVExporter
from forensic_analyzer.output.pdf_exporter import PDFExporter
from forensic_analyzer.analyzers.timeline_analyzer import TimelineAnalyzer

#Imports analyzers
from forensic_analyzer.analyzers.pdf_analyzer import PDFAnalyzer
from forensic_analyzer.analyzers.image_analyzer import ImageAnalyzer
from forensic_analyzer.analyzers.gps_analyzer import GPSAnalyzer
from forensic_analyzer.analyzers.strings_analyzer import StringsAnalyzer
from forensic_analyzer.analyzers.firefox_analyzer import (
    FirefoxHistoryAnalyzer, FirefoxCookiesAnalyzer,
)
from forensic_analyzer.analyzers.stego_analyzer import StegoAnalyzer
from forensic_analyzer.analyzers.carving_analyzer import CarvingAnalyzer
from forensic_analyzer.analyzers.pcap_analyzer import PCAPAnalyzer
from forensic_analyzer.analyzers.memory_analyzer import MemoryAnalyzer
from forensic_analyzer.analyzers.disk_analyzer import DiskAnalyzer
from forensic_analyzer.analyzers.evtx_analyzer import EVTXAnalyzer
from forensic_analyzer.analyzers.registry_analyzer import RegistryAnalyzer
from forensic_analyzer.analyzers.linux_artifacts_analyzer import LinuxArtifactsAnalyzer
from forensic_analyzer.analyzers.yara_analyzer import YARAAnalyzer
from forensic_analyzer.analyzers.ioc_analyzer import IOCAnalyzer

from forensic_analyzer.core.pipeline import AnalyzerRegistry
from forensic_analyzer.core.scanner import auto_scan


# Dispatch mapping for menu options
_MENU_DISPATCH = {
    "1":  ("PDF - Metadonnees",     lambda: PDFAnalyzer(),           "Entrez le chemin du fichier PDF"),
    "2":  ("Image / EXIF",          lambda: ImageAnalyzer(),          "Entrez le chemin de l'image"),
    "3":  ("Coordonnees GPS",       lambda: GPSAnalyzer(),            "Entrez le chemin de l'image"),
    "4":  ("Extraction Strings",    lambda: StringsAnalyzer(),        "Entrez le chemin du fichier binaire"),
    "5":  ("Historique Firefox",    lambda: FirefoxHistoryAnalyzer(), "Entrez le chemin de places.sqlite"),
    "6":  ("Cookies Firefox",       "cookies"),
    "7":  ("Steganographie",        lambda: StegoAnalyzer(),          "Entrez le chemin de l'image"),
    "8":  ("File Carving",          lambda: CarvingAnalyzer(),        "Entrez le chemin du fichier a analyser"),
    "9":  ("Analyse PCAP",          lambda: PCAPAnalyzer(),           "Entrez le chemin du fichier .pcap"),
    "10": ("Windows Event Logs",    lambda: EVTXAnalyzer(),           "Entrez le chemin du fichier .evtx"),
    "11": ("Registre Windows",      lambda: RegistryAnalyzer(),       "Entrez le chemin de la ruche (SAM, SYSTEM, NTUSER.DAT)"),
    "12": ("Artefacts Linux",       lambda: LinuxArtifactsAnalyzer(), "Entrez le chemin de la racine ou du fichier"),
    "13": ("Analyse Memoire RAM",   "memory"),
    "14": ("Forensique Disque",     lambda: DiskAnalyzer(),           "Entrez le chemin de l'image disque (.dd)"),
    "15": ("Scan YARA",             "yara"),
    "16": ("Extraction IOC",        lambda: IOCAnalyzer(),            "Entrez le chemin du fichier a scanner"),
    "17": ("Timeline DFIR",         "timeline"),
}


def _run_analysis(analyzer, path: str, **kwargs) -> FindingModel | None:
    """Execute un analyzer et affiche le resultat."""
    ui.status("Analyse en cours...")
    try:
        # Check if analyze supports multiple kwargs
        import inspect
        sig = inspect.signature(analyzer.analyze)
        if len(sig.parameters) > 1:
            result = analyzer.analyze(path, **kwargs)
        else:
            result = analyzer.analyze(path)
    except Exception as exc:
        ui.error(f"Erreur d'analyse : {exc}")
        return None

    if result is None:
        ui.warning("Aucun resultat pour ce fichier.")
        return None

    ui.success("Analyse terminee avec succes.")
    ui.render_finding(result)
    return result


def _handle_export(session_findings: list[FindingModel]) -> None:
    """Gere le sous-menu d'export."""
    if not session_findings:
        ui.warning("Aucun resultat en memoire a exporter.")
        return

    report = ReportModel.from_findings(session_findings)
    ui.export_menu()

    choice = ui.prompt("export").upper()

    if choice == "R":
        return

    if choice == "J":
        path = ui.prompt_input("Entrez le chemin du fichier JSON de sortie (.json)")
        if path:
            filename = os.path.basename(path)
            target_path = os.path.join("export", filename)
            JSONExporter().export(report, path)
            ui.success(f"Rapport JSON exporte avec succes dans : {target_path}")

    elif choice == "H":
        path = ui.prompt_input("Entrez le chemin du fichier HTML de sortie (.html)")
        if path:
            filename = os.path.basename(path)
            target_path = os.path.join("export", filename)
            # Add timeline automatically to HTML if possible
            timeline = TimelineAnalyzer().build_from_report(report)
            if timeline:
                augmented = ReportModel.from_findings(session_findings + [timeline])
            else:
                augmented = report
            HTMLExporter().export(augmented, path)
            ui.success(f"Rapport HTML interactif exporte dans : {target_path}")

    elif choice == "C":
        path = ui.prompt_input("Entrez le chemin du fichier CSV de sortie (.csv)")
        if path:
            filename = os.path.basename(path)
            target_path = os.path.join("export", filename)
            CSVExporter().export(report, path)
            ui.success(f"Timeline CSV exportee dans : {target_path}")

    elif choice == "P":
        path = ui.prompt_input("Entrez le chemin du fichier PDF de sortie (.pdf)")
        if path:
            filename = os.path.basename(path)
            target_path = os.path.join("export", filename)
            PDFExporter().export(report, path)
            ui.success(f"Rapport PDF exporte dans : {target_path}")

    else:
        ui.error("Option d'export invalide.")


def interactive_loop() -> None:
    """Boucle interactive principale."""
    session_findings: list[FindingModel] = []

    while True:
        ui.banner()
        ui.menu()

        choice = ui.prompt("menu")

        if not choice:
            continue

        # Normaliser les choix à deux chiffres comme 01-09 en 1-9, tout en gardant 00
        if choice.isdigit() and choice != "00":
            choice = str(int(choice))

        # Quitter
        if choice == "00" or choice == "0":
            print()
            ui.info("Fermeture de Forensic Analyzer.")
            if session_findings:
                ui.warning(f"Vous avez {len(session_findings)} analyse(s) en memoire.")
                ans = ui.prompt_input("Voulez-vous exporter les resultats avant de quitter ? (o/n)", required=False)
                if ans and ans.lower() in ("o", "oui", "y", "yes"):
                    _handle_export(session_findings)
            print()
            break

        # Scan automatique
        if choice == "88":
            path = ui.prompt_file("Entrez le chemin du fichier ou dossier a scanner")
            if path is None:
                continue

            registry = AnalyzerRegistry()
            registry.register_all(
                PDFAnalyzer(), ImageAnalyzer(), StegoAnalyzer(),
                PCAPAnalyzer(), EVTXAnalyzer(), RegistryAnalyzer(),
                MemoryAnalyzer(), DiskAnalyzer(),
            )
            ui.status(f"Scan automatique en cours de : {path}")
            report = auto_scan(path, registry)

            for finding in report.findings:
                ui.render_finding(finding)
                session_findings.append(finding)

            ui.render_summary(report)
            ui.wait_for_key()
            continue

        # Exporter rapport
        if choice == "99":
            _handle_export(session_findings)
            ui.wait_for_key()
            continue

        # Dispatch standard
        if choice not in _MENU_DISPATCH:
            ui.error("Option invalide. Veuillez choisir un nombre du menu.")
            continue

        item = _MENU_DISPATCH[choice]
        label = item[0]
        action = item[1]

        # Cas Timeline
        if action == "timeline":
            if not session_findings:
                ui.warning("Aucun résultat en mémoire pour construire la timeline.")
                continue
            ui.status("Correlation et construction de la timeline unifiee...")
            report = ReportModel.from_findings(session_findings)
            result = TimelineAnalyzer().build_from_report(report)
            if result:
                ui.render_finding(result)
                session_findings.append(result)
            else:
                ui.warning("Aucun evenement temporel trouve dans les resultats.")
            ui.wait_for_key()
            continue

        # Cas YARA
        if action == "yara":
            rules_path = ui.prompt_file("Entrez le chemin du fichier ou dossier de regles YARA (.yar)")
            if rules_path is None:
                continue
            target_path = ui.prompt_file("Entrez le chemin du fichier ou dossier a scanner")
            if target_path is None:
                continue

            analyzer = YARAAnalyzer(rules_path)
            res = _run_analysis(analyzer, target_path)
            if res:
                session_findings.append(res)
            ui.wait_for_key()
            continue

        # Cas Cookies Firefox (besoin de la classe specifique car partage le meme script)
        if action == "cookies":
            path = ui.prompt_file("Entrez le chemin du fichier cookies.sqlite")
            if path is None:
                continue
            analyzer = FirefoxCookiesAnalyzer()
            res = _run_analysis(analyzer, path)
            if res:
                session_findings.append(res)
            ui.wait_for_key()
            continue

        # Cas Memoire
        if action == "memory":
            path = ui.prompt_file("Entrez le chemin du dump memoire (.raw)")
            if path is None:
                continue
            plugins_str = ui.prompt_input("Plugins Volatility3 (optionnels, separes par virgule)", required=False)
            os_type = ui.prompt_input("OS cible (windows/linux, defaut: windows)", required=False) or "windows"
            plugins = plugins_str.split(",") if plugins_str else None

            analyzer = MemoryAnalyzer()
            res = _run_analysis(analyzer, path, plugins=plugins, os_type=os_type)
            if res:
                session_findings.append(res)
            ui.wait_for_key()
            continue

        # Cas standard
        prompt_msg = item[2]
        path = ui.prompt_file(prompt_msg)
        if path is None:
            continue

        analyzer = action()
        res = _run_analysis(analyzer, path)
        if res:
            session_findings.append(res)
        ui.wait_for_key()

