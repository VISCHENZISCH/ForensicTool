#!/usr/bin/env python3
"""
Couche CLI pour Forensic Analyzer.
- Sans arguments : lance le menu interactif
- Avec arguments : mode CLI (argparse)
"""

import argparse
import os

from forensic_analyzer.utils.version import tool_identity


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="forensic-analyzer",
        description="Forensic Analyzer -- Suite forensique modulaire",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Chaque option d'analyse accepte un fichier ou un dossier : dans un dossier,
seuls les fichiers du type demandé sont analysés (--pdf ./preuves -> les PDF).

Exemples :
  python main.py                               # Menu interactif
  python main.py --scan ./evidence             # Scan automatique
  python main.py --pdf doc.pdf --export-html rapport.html
  python main.py --pe ./preuves                # Tous les exécutables PE du dossier
  python main.py --pcap capture.pcap --export-json rapport.json
  python main.py --stego image.png
  python main.py --yara rules/ --scan ./samples

Code de sortie : 0 rien à signaler, 1 analyse ou vérification incomplète,
2 preuve altérée, 3 menace de gravité élevée ou critique.
        """,
    )

    # Analyses fichiers
    g1 = p.add_argument_group("Analyse de fichiers")
    g1.add_argument("--scan",    metavar="CHEMIN",  help="Scan automatique d'un fichier ou d'un dossier")
    g1.add_argument("--pdf",     metavar="FICHIER", help="Métadonnées PDF")
    g1.add_argument("--office",  metavar="FICHIER", help="Documents Office : macros, DDE, modèles distants")
    g1.add_argument("--image",   metavar="FICHIER", help="Métadonnées EXIF d'une image")
    g1.add_argument("--gps",     metavar="FICHIER", help="Coordonnées GPS EXIF")
    g1.add_argument("--strings", metavar="FICHIER", help="Chaînes imprimables d'un binaire")
    g1.add_argument("--fh",      metavar="SQLITE",  help="Historique Firefox (places.sqlite)")
    g1.add_argument("--fc",      metavar="SQLITE",  help="Cookies Firefox (cookies.sqlite)")
    g1.add_argument("--chromium", metavar="SQLITE", help="Artefacts Chromium (Chrome/Edge)")

    # Analyse avancée
    g2 = p.add_argument_group("Analyse avancée")
    g2.add_argument("--stego",   metavar="IMAGE",   help="Stéganographie (LSB, DCT, alpha)")
    g2.add_argument("--carve",   metavar="FICHIER", help="File carving et détection de polyglottes")
    g2.add_argument("--pcap",    metavar="PCAP",    help="Analyse réseau PCAP/PCAPNG")
    g2.add_argument("--pe",      metavar="EXE",     help="Triage Malware (PE/Entropie)")
    g2.add_argument("--elf",     metavar="BINAIRE", help="Analyse statique d'un binaire Linux (ELF)")
    g2.add_argument("--logs",    metavar="JOURNAL", help="Journaux web / système (access, error, syslog, auth, wp-debug)")
    g2.add_argument("--webshell", metavar="SCRIPT", help="Détection de webshell (PHP...)")
    g2.add_argument("--nmap",    metavar="XML",     help="Rapport nmap (-oX)")

    # Analyse système
    g3 = p.add_argument_group("Analyse système")
    g3.add_argument("--mem",      metavar="DUMP",   help="Dump mémoire RAM")
    g3.add_argument("--mem-os",   choices=["windows", "linux"], default=None,
                    help="OS du dump (défaut : détection automatique)")
    g3.add_argument("--mem-plugins", metavar="LIST", help="Plugins Volatility3 (virgule)")
    g3.add_argument("--mem-symbols", metavar="DOSSIER", help="Symboles ISF Volatility3 (requis pour Linux)")
    g3.add_argument("--disk",     metavar="IMAGE",  help="Image disque (MFT, ext4, ADS)")
    g3.add_argument("--evtx",     metavar="EVTX",   help="Windows Event Logs")
    g3.add_argument("--registry", metavar="HIVE",   help="Ruche registre Windows")
    g3.add_argument("--winexec",  metavar="PF/LNK", help="Artefacts d'exécution (Prefetch, LNK)")
    g3.add_argument("--linux",    metavar="CHEMIN",  help="Artefacts Linux (racine montée ou extraite)")
    g3.add_argument("--bodyfile", metavar="FICHIER", help="Bodyfile TSK (fls -r -m /) de l'image, avec --linux")
    g3.add_argument("--verify-hashes", metavar="MANIFESTE",
                    help="Vérifier les empreintes des preuves (format sha256sum) avant et après l'analyse")
    g3.add_argument("--evidence-dir", metavar="DOSSIER",
                    help="Dossier racine des preuves pour résoudre les chemins relatifs du manifeste")

    # Threat Hunting
    g4 = p.add_argument_group("Threat Hunting")
    g4.add_argument("--yara", metavar="RÈGLES", help="Règles YARA (.yar ou dossier)")
    g4.add_argument("--ioc",  metavar="FICHIER", help="Extraction IOC automatique")
    g4.add_argument("--update", action="store_true", help="Mettre à jour l'application depuis le dépôt distant")
    g4.add_argument("--version", action="version", version=tool_identity(),
                    help="Version et commit de l'outil (aussi inscrits dans chaque rapport)")
    g4.add_argument("--online", action="store_true",
                    help="Autoriser les services en ligne : MalwareBazaar, VirusTotal, géocodage OSM")

    # Export
    g5 = p.add_argument_group("Export")
    g5.add_argument("--export-json", metavar="JSON", help="Export JSON")
    g5.add_argument("--export-html", metavar="HTML", help="Export HTML interactif")
    g5.add_argument("--export-csv",  metavar="CSV",  help="Export CSV timeline DFIR")
    g5.add_argument("--export-pdf",  metavar="PDF",  help="Export PDF")
    g5.add_argument("--export-graph", metavar="HTML",
                    help="Graphe interactif de la chaîne de compromission (indicateurs partagés)")
    g5.add_argument("--export-rules", action="store_true", help="Règles YARA, Suricata, Sigma et bundle STIX 2.1 dans export/rules/")
    g5.add_argument("--export-dir", metavar="DOSSIER", help="Dossier de destination pour les exports (défaut : export/)")

    return p


def cli_dispatch():
    """Mode CLI avec argparse."""
    # Imports ici : le menu interactif charge ses modules lui-même, à l'écran de démarrage
    from forensic_analyzer.analyzers.carving import CarvingAnalyzer
    from forensic_analyzer.analyzers.chromium import ChromiumAnalyzer
    from forensic_analyzer.analyzers.disk import DiskAnalyzer
    from forensic_analyzer.analyzers.elf import ELFAnalyzer
    from forensic_analyzer.analyzers.evtx import EVTXAnalyzer
    from forensic_analyzer.analyzers.firefox import (
        FirefoxCookiesAnalyzer, FirefoxHistoryAnalyzer)
    from forensic_analyzer.analyzers.gps import GPSAnalyzer
    from forensic_analyzer.analyzers.image import ImageAnalyzer
    from forensic_analyzer.analyzers.integrity import IntegrityAnalyzer
    from forensic_analyzer.analyzers.ioc import IOCAnalyzer
    from forensic_analyzer.analyzers.linux import \
        LinuxArtifactsAnalyzer
    from forensic_analyzer.analyzers.memory import MemoryAnalyzer
    from forensic_analyzer.analyzers.pcap import PCAPAnalyzer
    from forensic_analyzer.analyzers.office import OfficeAnalyzer
    from forensic_analyzer.analyzers.pdf import PDFAnalyzer
    from forensic_analyzer.analyzers.malware import MalwareAnalyzer as PEAnalyzer
    from forensic_analyzer.analyzers.registry import RegistryAnalyzer
    from forensic_analyzer.analyzers.stego import StegoAnalyzer
    from forensic_analyzer.analyzers.strings import StringsAnalyzer
    from forensic_analyzer.analyzers.timeline import TimelineAnalyzer
    from forensic_analyzer.analyzers.windows_execution import \
        WindowsExecutionAnalyzer
    from forensic_analyzer.analyzers.yara import YARAAnalyzer
    from forensic_analyzer.analyzers.log_analyzer import LogAnalyzer
    from forensic_analyzer.analyzers.nmap import NmapAnalyzer
    from forensic_analyzer.analyzers.webshell import WebshellAnalyzer
    from forensic_analyzer.core.correlation import correlate
    from forensic_analyzer.core.scanner import auto_scan, default_registry, files_for
    from forensic_analyzer.models.finding import AnalysisError, ReportModel, fingerprint, recheck
    from forensic_analyzer.output.csv_exporter import CSVExporter
    from forensic_analyzer.output.graph_renderer import render_correlation_graph
    from forensic_analyzer.output.html_exporter import HTMLExporter
    from forensic_analyzer.output.json_exporter import JSONExporter
    from forensic_analyzer.output.pdf_exporter import PDFExporter
    from forensic_analyzer.output.plain_renderer import PlainRenderer
    from forensic_analyzer.output.rich_renderer import RichRenderer
    from forensic_analyzer.utils.deps import HAS_RICH
    from forensic_analyzer.utils.network import set_online
    from forensic_analyzer.utils.exports import export_root, output_path
    from forensic_analyzer.output import ui

    parser = build_parser()
    args = parser.parse_args()

    # Un sous-dossier par analyse dans export/ (ou --export-dir), pour ne pas mélanger les affaires
    from forensic_analyzer.utils.exports import new_case_dir, set_export_root
    if args.export_dir:
        set_export_root(args.export_dir)
    else:
        target = next((v for v in (args.scan, args.linux, args.disk, args.mem, args.pcap, args.pe, args.elf,
                                   args.evtx, args.registry, args.pdf, args.office, args.image, args.ioc, args.logs,
                                   args.webshell, args.nmap) if v), "analyse")
        new_case_dir(target)

    if getattr(args, 'update', False):
        from forensic_analyzer.core.updater import Updater
        Updater().check_and_update()
        return

    if args.online:
        set_online(True)

    renderer = RichRenderer() if HAS_RICH else PlainRenderer()

    registry = default_registry()

    findings = []

    if args.verify_hashes:
        res = IntegrityAnalyzer().analyze(args.verify_hashes, phase="initiale", evidence_dir=args.evidence_dir)
        if res:
            findings.append(res)

    skipped: list[str] = []
    notes: list[str] = []
    errors: list = []
    evidence: dict = {}
    if args.scan:
        report = auto_scan(args.scan, registry)
        findings.extend(report.findings)
        skipped, notes, errors = report.skipped_files, report.scan_notes, list(report.analysis_errors)
        evidence.update((r.file, r) for r in report.evidence)

    simple_analyzers = [
        (args.pdf,     PDFAnalyzer),
        (args.office,  OfficeAnalyzer),
        (args.image,   ImageAnalyzer),
        (args.gps,     GPSAnalyzer),
        (args.strings, StringsAnalyzer),
        (args.fh,      FirefoxHistoryAnalyzer),
        (args.fc,      FirefoxCookiesAnalyzer),
        (args.stego,   StegoAnalyzer),
        (args.carve,   CarvingAnalyzer),
        (args.pcap,    PCAPAnalyzer),
        (args.evtx,    EVTXAnalyzer),
        (args.registry, RegistryAnalyzer),
        (args.disk,    DiskAnalyzer),
        (args.ioc,     IOCAnalyzer),
        (args.pe,      PEAnalyzer),
        (args.elf,     ELFAnalyzer),
        (args.chromium, ChromiumAnalyzer),
        (args.winexec, WindowsExecutionAnalyzer),
        (args.logs,    LogAnalyzer),
        (args.webshell, WebshellAnalyzer),
        (args.nmap,    NmapAnalyzer),
    ]

    def run(analyzer, path: str, **kwargs) -> None:
        """Fichier, ou dossier filtre sur le type de l'analyzer (--pdf DOSSIER : seulement les PDF)."""
        for f in files_for(analyzer, path):
            if os.path.isfile(f) and f not in evidence:
                evidence[f] = fingerprint(f)   # empreinte avant analyse
            try:
                res = analyzer.analyze(f, **kwargs)
            except Exception as exc:   # garder les résultats déjà obtenus et le dire dans le rapport
                ui.error(f"{analyzer.name} a échoué sur {f} : {exc}")
                errors.append(AnalysisError.of(analyzer.name, f, exc))
                continue
            findings.extend(r for r in (res if isinstance(res, list) else [res]) if r)

    for arg_val, cls in simple_analyzers:
        if arg_val:
            run(cls(), arg_val)

    if args.linux:
        run(LinuxArtifactsAnalyzer(), args.linux, bodyfile=args.bodyfile)

    if args.mem:
        plugins = args.mem_plugins.split(",") if args.mem_plugins else None
        run(MemoryAnalyzer(), args.mem, plugins=plugins, os_type=args.mem_os, symbols_dir=args.mem_symbols)

    if args.yara:
        targets = [t for t in (args.scan, args.pdf, args.office, args.image, args.stego, args.carve,
                               args.pcap, args.disk, args.evtx, args.registry, args.linux,
                               args.ioc, args.pe, args.elf, args.strings, args.mem) if t]
        if targets:
            yara = YARAAnalyzer(args.yara)
            for target in dict.fromkeys(targets):
                try:
                    res = yara.analyze(target)
                except Exception as exc:
                    ui.error(f"YARA a échoué sur {target} : {exc}")
                    errors.append(AnalysisError.of("yara", target, exc))
                    continue
                if res:
                    findings.append(res)
        else:
            ui.info("Indiquez une cible à scanner avec YARA (--scan ou une autre option d'analyse).")

    if args.verify_hashes:
        res = IntegrityAnalyzer().analyze(args.verify_hashes, phase="finale", evidence_dir=args.evidence_dir)
        if res:
            findings.append(res)

    # Vue transverse : indicateurs partagés entre sources, puis chronologie consolidée
    correlation = correlate(findings) if findings else None
    if correlation:
        findings.append(correlation)
    records = recheck([r for r in evidence.values() if r])
    context = dict(skipped_files=skipped, scan_notes=notes, analysis_errors=errors, evidence=records)
    report = ReportModel.from_findings(findings, **context)
    tl = TimelineAnalyzer().build_from_report(report) if findings else None
    if tl and tl.extra.get("events"):
        findings.append(tl)
        report = ReportModel.from_findings(findings, **context)

    renderer.render_report(report)

    export_failed = False
    for wanted, exporter in ((args.export_json, JSONExporter), (args.export_html, HTMLExporter),
                             (args.export_csv, CSVExporter), (args.export_pdf, PDFExporter)):
        if not wanted:
            continue
        if not report.findings:
            ui.warning(f"Aucun résultat : {wanted} n'a pas été écrit.")
            continue
        try:
            ui.success(f"Exporté : {exporter().export(report, wanted)}")
        except Exception as exc:   # un exporteur en échec n'empêche pas les suivants
            ui.error(f"Export {wanted} impossible : {type(exc).__name__} : {exc}")
            export_failed = True
    try:
        if args.export_graph and correlation:
            render_correlation_graph(correlation, output_path(args.export_graph))
        if getattr(args, 'export_rules', False) and report.findings:
            from forensic_analyzer.output.rules_generator import DefenseRulesGenerator
            DefenseRulesGenerator().generate(report, output_dir=os.path.join(export_root(), "rules"))
    except Exception as exc:
        ui.error(f"Export du graphe ou des règles impossible : {type(exc).__name__} : {exc}")
        export_failed = True

    return exit_code(report, export_failed)


def exit_code(report, export_failed: bool = False) -> int:
    """
    Par priorité : 2 preuve altérée (manifeste, ou modifiée pendant l'analyse) ; 3 menace de gravité élevée ou critique ; 1 quelque chose n'a
    pas pu être analysé ou vérifié (preuve introuvable, PDF chiffré, module ou export en échec) ;
    0 rien à signaler. Fondé sur les champs severity / incomplete, jamais sur les libellés affichés.
    """
    if any(f.type == "evidence_integrity" and f.severity == "critique" for f in report.findings) or \
            any(r.changed_during_analysis for r in report.evidence):
        return 2
    if any(f.severity in ("élevé", "critique") for f in report.findings if f.type != "evidence_integrity"):
        return 3
    incomplete = any(f.incomplete for f in report.findings)
    return 1 if export_failed or report.analysis_errors or incomplete else 0

def main():
    """Point d'entrée : menu interactif par défaut, CLI si arguments."""
    import sys

    from forensic_analyzer.utils.margin import MarginStdout
    sys.stdout = MarginStdout(sys.stdout, margin=4)
    sys.stderr = MarginStdout(sys.stderr, margin=4)

    if len(sys.argv) > 1:
        sys.exit(cli_dispatch() or 0)
    else:
        from forensic_analyzer.cli.menu import interactive_loop
        interactive_loop()



if __name__ == "__main__":
    main()
