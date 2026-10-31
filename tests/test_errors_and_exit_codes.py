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
