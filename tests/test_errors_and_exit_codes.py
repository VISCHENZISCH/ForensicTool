"""Échecs d'analyse visibles dans le rapport, exports à l'endroit demandé, code de sortie."""
from __future__ import annotations

import hashlib
import subprocess
import sys

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.core.pipeline import AnalyzerRegistry, run_pipeline
from forensic_analyzer.models.finding import FindingModel


class _Crashing(BaseAnalyzer):
    name = "plante"
    supported_extensions = (".bin",)

    def analyze(self, path):
        raise ValueError("structure inattendue")


class _Working(BaseAnalyzer):
    name = "marche"
    supported_extensions = (".bin",)

    def analyze(self, path):
        return FindingModel(type="test", file=path, metadata={"ok": "1"})


def test_module_failure_is_reported_not_hidden(tmp_path):
    evidence = tmp_path / "preuve.bin"
    evidence.write_bytes(b"x")
    report = run_pipeline([str(evidence)], AnalyzerRegistry().register_all(_Crashing(), _Working()))
    assert report.total == 1                                       # l'autre module a tourné
    err, = report.analysis_errors
    assert (err.module, err.file, err.error, err.message) == ("plante", str(evidence), "ValueError", "structure inattendue")


def test_report_timestamp_is_utc():
    from forensic_analyzer.models.finding import ReportModel
    assert ReportModel.from_findings([]).timestamp.endswith("+00:00")


def test_export_path_with_folder_is_respected(tmp_path, monkeypatch):
    from forensic_analyzer.models.finding import ReportModel
    from forensic_analyzer.output.json_exporter import JSONExporter

    monkeypatch.chdir(tmp_path)
    report = ReportModel.from_findings([FindingModel(type="t", file="/f", metadata={})])
    assert JSONExporter().export(report, str(tmp_path / "affaire" / "r.json")) == str(tmp_path / "affaire" / "r.json")
    assert (tmp_path / "affaire" / "r.json").is_file()


def _cli(tmp_path, *args):
    return subprocess.run([sys.executable, "-m", "forensic_analyzer.cli.main", *args, "--export-dir", str(tmp_path / "out")],
                          capture_output=True, text=True, cwd=tmp_path,
                          env={"PYTHONPATH": str(__import__("pathlib").Path(__file__).parents[1]), "PATH": "/usr/bin:/bin"})


def test_exit_code_signals_altered_evidence(tmp_path):
    (tmp_path / "disk.img").write_bytes(b"modifie")
    manifest = tmp_path / "m.sha256"
    manifest.write_text(f"{hashlib.sha256(b'originale').hexdigest()}  disk.img\n")
    assert _cli(tmp_path, "--verify-hashes", str(manifest)).returncode == 2
    manifest.write_text(f"{hashlib.sha256(b'modifie').hexdigest()}  disk.img\n")
    assert _cli(tmp_path, "--verify-hashes", str(manifest)).returncode == 0


def test_exit_code_signals_unverifiable_evidence(tmp_path):
    manifest = tmp_path / "m.sha256"
    manifest.write_text(f"{hashlib.sha256(b'x').hexdigest()}  absent.img\n")
    assert _cli(tmp_path, "--verify-hashes", str(manifest)).returncode == 1


def test_exit_code_ignores_wording():
    from forensic_analyzer.cli.main import exit_code
    from forensic_analyzer.models.finding import ReportModel

    renamed = FindingModel(type="evidence_integrity", file="/m", metadata={"Verdict": "libellé reformulé"},
                           severity="critique")
    assert exit_code(ReportModel.from_findings([renamed])) == 2
    partial = FindingModel(type="pdf_analysis", file="/p", metadata={}, incomplete=["PDF chiffré"])
    assert exit_code(ReportModel.from_findings([partial])) == 1


def test_exit_code_signals_detected_threats():
    from forensic_analyzer.cli.main import exit_code
    from forensic_analyzer.models.finding import ReportModel

    webshell = FindingModel(type="webshell_analysis", file="/x.php", metadata={}, severity="critique")
    assert exit_code(ReportModel.from_findings([webshell])) == 3
    clean = FindingModel(type="webshell_analysis", file="/y.php", metadata={}, severity="info")
    assert exit_code(ReportModel.from_findings([clean])) == 0


def test_every_alerting_module_sets_a_severity(tmp_path):
    from forensic_analyzer.analyzers.webshell import WebshellAnalyzer

    shell = tmp_path / "x.php"
    shell.write_text("<?php system($_GET['c']); ?>")
    benign = tmp_path / "index.php"
    benign.write_text("<?php echo 'bonjour'; ?>")
    assert WebshellAnalyzer().analyze(str(shell)).severity == "critique"
    assert WebshellAnalyzer().analyze(str(benign)).severity == "info"


def test_evidence_is_hashed_before_analysis_and_rechecked(tmp_path):
    from forensic_analyzer.core.pipeline import AnalyzerRegistry, run_pipeline

    class _Tampering(BaseAnalyzer):   # module défectueux qui écrit dans la preuve
        name = "modifie"
        supported_extensions = (".bin",)

        def analyze(self, path):
            with open(path, "ab") as f:
                f.write(b"!")
            return None

    evidence = tmp_path / "preuve.bin"
    evidence.write_bytes(b"original")
    report = run_pipeline([str(evidence)], AnalyzerRegistry().register(_Tampering()))
    record, = report.evidence
    assert record.sha256 == hashlib.sha256(b"original").hexdigest() and record.hashed_at.endswith("+00:00")
    assert record.changed_during_analysis

    from forensic_analyzer.cli.main import exit_code
    assert exit_code(report) == 2


def test_file_type_is_detected_once_per_file(tmp_path, monkeypatch):
    import zipfile
    from forensic_analyzer.utils import magic

    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("x.txt", "x")
    opened = []
    real = zipfile.ZipFile
    monkeypatch.setattr(magic.zipfile, "ZipFile", lambda *a, **k: opened.append(1) or real(*a, **k))
    for _ in range(40):
        magic.get_file_magic_extension(str(archive))
    assert len(opened) == 1


def test_oversized_pcap_is_reported_not_loaded(tmp_path, monkeypatch):
    import pytest
    pcap_mod = pytest.importorskip("forensic_analyzer.analyzers.pcap.analyzer")
    monkeypatch.setattr(pcap_mod, "MAX_PCAP_BYTES", 10)
    capture = tmp_path / "gros.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 100)
    f = pcap_mod.PCAPAnalyzer().analyze(str(capture))
    assert f.incomplete and "tshark" in f.metadata["[ATTENTION] Non analysé"]


def test_every_analyzer_sets_a_severity():
    """Garde-fou : un nouveau module qui ne renseigne pas severity serait invisible pour le code de sortie."""
    import glob
    import os

    root = os.path.join(os.path.dirname(__file__), "..", "forensic_analyzer", "analyzers")
    sources = {os.path.basename(os.path.dirname(p)): open(p, encoding="utf-8").read()
               for p in glob.glob(os.path.join(root, "*", "analyzer.py"))}
    assert sources and not [name for name, code in sources.items() if "severity" not in code]


def test_report_names_the_exact_tool_version():
    from forensic_analyzer import __version__
    from forensic_analyzer.models.finding import ReportModel

    assert ReportModel.from_findings([]).tool.startswith(f"Forensic Analyzer {__version__}")
