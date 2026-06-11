#!/usr/bin/env python3
# coding: utf-8
"""
Couche CLI pour Forensic Analyzer.
- Sans arguments : lance le menu interactif
- Avec arguments : mode CLI (argparse)
"""

import argparse

from forensic_analyzer.analyzers.carving import CarvingAnalyzer
from forensic_analyzer.analyzers.chromium import ChromiumAnalyzer
from forensic_analyzer.analyzers.disk import DiskAnalyzer
from forensic_analyzer.analyzers.evtx import EVTXAnalyzer
from forensic_analyzer.analyzers.firefox import (
    FirefoxCookiesAnalyzer, FirefoxHistoryAnalyzer)
from forensic_analyzer.analyzers.gps import GPSAnalyzer
from forensic_analyzer.analyzers.image import ImageAnalyzer
from forensic_analyzer.analyzers.ioc import IOCAnalyzer
from forensic_analyzer.analyzers.linux import \
    LinuxArtifactsAnalyzer
from forensic_analyzer.analyzers.memory import MemoryAnalyzer
from forensic_analyzer.analyzers.pcap import PCAPAnalyzer
from forensic_analyzer.analyzers.pdf import PDFAnalyzer
from forensic_analyzer.analyzers.ids import IDSAnalyzer
from forensic_analyzer.analyzers.malware import MalwareAnalyzer as PEAnalyzer
from forensic_analyzer.analyzers.registry import RegistryAnalyzer
from forensic_analyzer.analyzers.stego import StegoAnalyzer
from forensic_analyzer.analyzers.strings import StringsAnalyzer
from forensic_analyzer.analyzers.timeline import TimelineAnalyzer
from forensic_analyzer.analyzers.windows_execution import \
    WindowsExecutionAnalyzer
from forensic_analyzer.analyzers.yara import YARAAnalyzer
from forensic_analyzer.core.pipeline import AnalyzerRegistry
from forensic_analyzer.core.scanner import auto_scan
from forensic_analyzer.models.finding import ReportModel
from forensic_analyzer.output.csv_exporter import CSVExporter
from forensic_analyzer.output.html_exporter import HTMLExporter
from forensic_analyzer.output.json_exporter import JSONExporter
from forensic_analyzer.output.pdf_exporter import PDFExporter
from forensic_analyzer.output.plain_renderer import PlainRenderer
from forensic_analyzer.output.rich_renderer import RichRenderer
from forensic_analyzer.utils.deps import HAS_RICH


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="forensic-analyzer",
        description="Forensic Analyzer -- Suite forensique modulaire",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python main.py                               # Menu interactif
  python main.py --scan ./evidence             # Scan automatique
  python main.py --pdf doc.pdf --export-html rapport.html
  python main.py --pcap capture.pcap --export-json rapport.json
  python main.py --stego image.png
  python main.py --yara rules/ --scan ./samples
        """,
    )

    # Analyses fichiers
    g1 = p.add_argument_group("Analyse de fichiers")
    g1.add_argument("--scan",    metavar="CHEMIN",  help="Scan auto d'un fichier ou dossier")
    g1.add_argument("--pdf",     metavar="FICHIER", help="Metadonnees PDF")
    g1.add_argument("--image",   metavar="FICHIER", help="Metadonnees EXIF d'une image")
    g1.add_argument("--gps",     metavar="FICHIER", help="Coordonnees GPS EXIF")
    g1.add_argument("--strings", metavar="FICHIER", help="Chaines imprimables d'un binaire")
    g1.add_argument("--fh",      metavar="SQLITE",  help="Historique Firefox (places.sqlite)")
    g1.add_argument("--fc",      metavar="SQLITE",  help="Cookies Firefox (cookies.sqlite)")
    g1.add_argument("--chromium", metavar="SQLITE", help="Artefacts Chromium (Chrome/Edge)")

    # Analyse avancee
    g2 = p.add_argument_group("Analyse avancee")
    g2.add_argument("--stego",   metavar="IMAGE",   help="Steganographie (LSB, DCT, alpha)")
    g2.add_argument("--carve",   metavar="FICHIER", help="File carving et polyglot detection")
    g2.add_argument("--pcap",    metavar="PCAP",    help="Analyse reseau PCAP/PCAPNG")
    g2.add_argument("--pe",      metavar="EXE",     help="Triage Malware (PE/Entropie)")

    # Analyse systeme
    g3 = p.add_argument_group("Analyse systeme")
    g3.add_argument("--mem",      metavar="DUMP",   help="Dump memoire RAM")
    g3.add_argument("--mem-os",   choices=["windows", "linux"], default="windows")
    g3.add_argument("--mem-plugins", metavar="LIST", help="Plugins Volatility3 (virgule)")
    g3.add_argument("--disk",     metavar="IMAGE",  help="Image disque (MFT, ext4, ADS)")
    g3.add_argument("--evtx",     metavar="EVTX",   help="Windows Event Logs")
    g3.add_argument("--registry", metavar="HIVE",   help="Ruche registre Windows")
    g3.add_argument("--winexec",  metavar="PF/LNK", help="Artefacts Execution (Prefetch, LNK)")
    g3.add_argument("--linux",    metavar="CHEMIN",  help="Artefacts Linux")

    # Threat Hunting
    g4 = p.add_argument_group("Threat Hunting")
    g4.add_argument("--yara", metavar="REGLES", help="Regles YARA (.yar ou dossier)")
    g4.add_argument("--ioc",  metavar="FICHIER", help="Extraction IOC automatique")

    # Export
    g5 = p.add_argument_group("Export")
    g5.add_argument("--export-json", metavar="JSON", help="Export JSON")
    g5.add_argument("--export-html", metavar="HTML", help="Export HTML interactif")
    g5.add_argument("--export-csv",  metavar="CSV",  help="Export CSV timeline DFIR")
    g5.add_argument("--export-pdf",  metavar="PDF",  help="Export PDF")
    g5.add_argument("--export-rules", action="store_true", help="Générer des règles YARA et Suricata à partir des IOCs trouvés")

    return p


def cli_dispatch():
    """Mode CLI avec argparse."""
    parser = build_parser()
    args = parser.parse_args()

    renderer = RichRenderer() if HAS_RICH else PlainRenderer()

    registry = AnalyzerRegistry()
    registry.register_all(
        PDFAnalyzer(), ImageAnalyzer(), StegoAnalyzer(),
        PCAPAnalyzer(), EVTXAnalyzer(), RegistryAnalyzer(),
        MemoryAnalyzer(), DiskAnalyzer(), PEAnalyzer(),
        ChromiumAnalyzer(), WindowsExecutionAnalyzer(),
        IDSAnalyzer(),
    )

    findings = []

    if args.scan:
        report = auto_scan(args.scan, registry)
        findings.extend(report.findings)

    simple_analyzers = [
        (args.pdf,     PDFAnalyzer),
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
        (args.linux,   LinuxArtifactsAnalyzer),
        (args.disk,    DiskAnalyzer),
        (args.ioc,     IOCAnalyzer),
        (args.pe,      PEAnalyzer),
        (args.chromium, ChromiumAnalyzer),
        (args.winexec, WindowsExecutionAnalyzer),
    ]

    for arg_val, cls in simple_analyzers:
        if arg_val:
            res = cls().analyze(arg_val)
            if res:
                findings.append(res)

    if args.mem:
        plugins = args.mem_plugins.split(",") if args.mem_plugins else None
        res = MemoryAnalyzer().analyze(args.mem, plugins=plugins, os_type=args.mem_os)
        if res:
            findings.append(res)

    if args.yara:
        target = (args.scan or args.pdf or args.image or args.stego
                  or args.pcap or args.disk or args.evtx
                  or args.registry or args.linux or args.ioc)
        if target:
            res = YARAAnalyzer(args.yara).analyze(target)
            if res:
                findings.append(res)
        else:
            from forensic_analyzer.output import ui
            ui.info("Specifiez une cible a scanner avec YARA via --scan ou autre.")

    report = ReportModel.from_findings(findings)

    if args.export_csv or args.export_html or args.export_pdf:
        tl = TimelineAnalyzer().build_from_report(report)
        if tl:
            findings.append(tl)
            report = ReportModel.from_findings(findings)

    renderer.render_report(report)

    if args.export_json and report.findings:
        JSONExporter().export(report, args.export_json)
    if args.export_html and report.findings:
        HTMLExporter().export(report, args.export_html)
    if args.export_csv and report.findings:
        CSVExporter().export(report, args.export_csv)
    if args.export_pdf and report.findings:
        PDFExporter().export(report, args.export_pdf)
        
    if getattr(args, 'export_rules', False) and report.findings:
        from forensic_analyzer.output.rules_generator import DefenseRulesGenerator
        # Générer dans le dossier courant ou un sous-dossier rules_export/
        DefenseRulesGenerator().generate(report, output_dir="rules_export")

def main():
    """Point d'entree : menu interactif par defaut, CLI si arguments."""
    import sys

    from forensic_analyzer.utils.margin import MarginStdout
    sys.stdout = MarginStdout(sys.stdout, margin=4)
    sys.stderr = MarginStdout(sys.stderr, margin=4)

    if len(sys.argv) > 1:
        cli_dispatch()
    else:
        from forensic_analyzer.cli.menu import interactive_loop
        interactive_loop()



if __name__ == "__main__":
    main()
