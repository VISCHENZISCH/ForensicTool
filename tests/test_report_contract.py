"""Contrat de contenu des rapports : ce que l'analyse a produit doit se retrouver dans chaque sortie.

Terminal, HTML et PDF sont vérifiés sur le même rapport : métadonnées complètes (sans troncature),
alertes en synthèse, empreintes des preuves, fichiers ignorés, indicateurs, faits de chronologie.
"""
from __future__ import annotations

import html
import re

import pytest

from forensic_analyzer.core.correlation import correlate
from forensic_analyzer.models.finding import FindingModel, ReportModel

ATTACKER = "203.0.113.42"
LONG_COMMAND = "mysqldump -uwp -pwpPass2025! wordpress | gzip > /var/www/html/wp-content/uploads/dump.sql.gz ; " * 5


@pytest.fixture
def report(tmp_path):
    from forensic_analyzer.analyzers.timeline import TimelineAnalyzer

    evidence = tmp_path / "preuves"
    evidence.mkdir()
    (evidence / "nginx-access.log").write_text("x")
    (evidence / "x.php").write_text("<?php system($_GET['c']); ?>")
    findings = [
        FindingModel(type="log_analysis", file=str(evidence / "nginx-access.log"),
                     metadata={"Format": "web_access",
                               f"[ALERTE] Brute-force {ATTACKER}": "2401 tentatives, RÉUSSI (HTTP 302)",
                               "[ALERTE] Commandes via webshell": LONG_COMMAND,
                               "User-Agent observé": "<script>alert(document.domain)</script>"},
                     extra={"iocs": {"ips": [ATTACKER]}, "log_type": "web_access",
                            "timeline_events": [{"timestamp": "2026-10-25T06:48:00+00:00", "source": "web_access",
                                                 "event_type": "brute_force", "ip": ATTACKER,
                                                 "description": f"Début du brute-force web depuis {ATTACKER}"}],
                            "details": {"webshell_commands": [{"shell": "/wp-content/uploads/x.php", "command": "whoami"}]}}),
        FindingModel(type="webshell_analysis", file=str(evidence / "x.php"),
                     metadata={"[ALERTE] Verdict": "WEBSHELL DÉTECTÉ"}),
        FindingModel(type="pcap", file=str(evidence / "nginx-access.log"),
                     metadata={"C2 Beacons détectés": "1"},
                     extra={"http_attack": {"attackers": [ATTACKER]},
                            "timeline": [{"time": "2026-10-25T07:21:00+00:00", "type": "EXFILTRATION",
                                          "desc": f"Téléchargement de dump.sql.gz par {ATTACKER}"}]}),
    ]
    correlation = correlate(findings)
    findings.append(correlation)
    timeline = TimelineAnalyzer().build_from_report(ReportModel.from_findings(findings))
    findings.append(timeline)
    return ReportModel.from_findings(findings, skipped_files=[str(evidence / "CONSTAT.md")])


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def _section(page: str, start: str, end: str) -> str:
    return page[page.index(f'id="{start}"'):page.index(f'id="{end}"')]


def test_html_contains_everything_the_analysis_produced(report):
    from forensic_analyzer.core import iocs
    from forensic_analyzer.output.html_exporter import build_interactive_html

    page = build_interactive_html(report)
    for f in report.findings:
        for key, value in f.metadata.items():
            assert html.escape(str(key)) in page, key
            assert html.escape(str(value)) in page, (key, "valeur tronquée ou absente")
    synthese = _section(page, "synthese", "perimetre")
    for f in report.findings:
        for key in (k for k in f.metadata if k.startswith("[ALERTE]")):
            assert html.escape(key.replace("[ALERTE]", "").strip()) in synthese, key
    perimetre = _section(page, "perimetre", "chronologie")
    for f in report.findings:
        if f.metadata.get("SHA-256"):
            assert f.metadata["SHA-256"] in perimetre
    assert "CONSTAT.md" in page[page.index('id="limites"'):]
    for ioc in iocs.collect(report.findings):
        assert html.escape(ioc.value) in _section(page, "indicateurs", "constats")
    timeline = next(f for f in report.findings if f.type == "timeline")
    for fact in timeline.extra["facts"]:
        assert html.escape(fact["description"]) in _section(page, "chronologie", "indicateurs")


def test_html_is_self_contained_and_escapes_evidence(report):
    from forensic_analyzer.output.html_exporter import build_interactive_html

    page = build_interactive_html(report)
    assert "<script>alert(document.domain)</script>" not in page
    assert not re.search(r'<(?:link|img|script)[^>]+(?:src|href)="(?:https?:)?//', page)   # aucune ressource distante
    assert page.count("<script>") == 1                                                   # seul le script du thème


def test_terminal_shows_every_metadata_entry(report, capsys):
    from forensic_analyzer.output import ui

    for f in report.findings:
        ui.render_finding(f)
    out = _flat(re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out))
    for f in report.findings:
        for key, value in f.metadata.items():
            assert _flat(str(key))[:28] in out, key                   # clé alignée sur 28 colonnes
            assert _flat(str(value)) in out, (key, "valeur absente du terminal")


def test_pdf_contains_alerts_hashes_and_skipped_files(report, tmp_path, monkeypatch):
    pytest.importorskip("weasyprint")
    pypdf = pytest.importorskip("pypdf")
    from forensic_analyzer.output.pdf_exporter import PDFExporter

    monkeypatch.chdir(tmp_path)
    PDFExporter().export(report, "r.pdf")
    text = "".join(page.extract_text() for page in pypdf.PdfReader(tmp_path / "export" / "r.pdf").pages)
    compact = re.sub(r"\s+", "", text)
    for f in report.findings:
        for key in (k for k in f.metadata if k.startswith("[ALERTE]")):
            assert re.sub(r"\s+", "", key.replace("[ALERTE]", "")) in compact, key
        if f.metadata.get("SHA-256"):
            assert f.metadata["SHA-256"] in compact
    assert "CONSTAT.md" in compact
