"""Tests du registre d'analyzers et du pipeline."""
from __future__ import annotations

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.core.pipeline import AnalyzerRegistry, run_pipeline
from forensic_analyzer.core.scanner import collect_targets
from forensic_analyzer.models.finding import FindingModel

JPEG_HEADER = b"\xFF\xD8\xFF\xE0" + b"\x00" * 32


class DummyAnalyzer(BaseAnalyzer):
    def __init__(self, name: str, extensions: tuple[str, ...]) -> None:
        self.name = name
        self.supported_extensions = extensions

    def analyze(self, path: str) -> FindingModel | None:
        return FindingModel(type=self.name, file=path)


class FailingAnalyzer(DummyAnalyzer):
    def analyze(self, path: str) -> FindingModel | None:
        raise RuntimeError("boom")


def test_can_handle_is_case_insensitive(tmp_path):
    evidence = tmp_path / "disk.e01"
    evidence.write_bytes(b"EVF\x09\x0d\x0a\xff\x00")
    assert DummyAnalyzer("disk", (".E01",)).can_handle(str(evidence))


def test_magic_bytes_override_extension(tmp_path):
    fake_pdf = tmp_path / "invoice.pdf"
    fake_pdf.write_bytes(b"MZ" + b"\x00" * 64)
    assert not DummyAnalyzer("pdf", (".pdf",)).can_handle(str(fake_pdf))
    assert DummyAnalyzer("pe", (".exe",)).can_handle(str(fake_pdf))


def test_analyzer_without_extensions_never_matches(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"\x00")
    assert not DummyAnalyzer("manual", ()).can_handle(str(f))


def test_all_matching_analyzers_run(tmp_path):
    img = tmp_path / "photo.jpg"
    img.write_bytes(JPEG_HEADER)
    registry = AnalyzerRegistry().register_all(
        DummyAnalyzer("image", (".jpg",)),
        DummyAnalyzer("gps", (".jpg",)),
        DummyAnalyzer("stego", (".jpg", ".png")),
        DummyAnalyzer("pcap", (".pcap",)),
    )

    report = run_pipeline([str(img)], registry)

    assert sorted(f.type for f in report.findings) == ["gps", "image", "stego"]
    assert report.total == 3


def test_failing_analyzer_does_not_block_others(tmp_path):
    img = tmp_path / "photo.jpg"
    img.write_bytes(JPEG_HEADER)
    registry = AnalyzerRegistry().register_all(
        FailingAnalyzer("broken", (".jpg",)),
        DummyAnalyzer("image", (".jpg",)),
    )

    report = run_pipeline([str(img)], registry)

    assert [f.type for f in report.findings] == ["image"]


def test_missing_file_is_skipped(tmp_path):
    registry = AnalyzerRegistry().register(DummyAnalyzer("any", (".txt",)))
    report = run_pipeline([str(tmp_path / "absent.txt")], registry)
    assert report.total == 0


def test_collect_targets_walks_directory(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.evtx").write_bytes(b"x")
    (tmp_path / "sub" / "b.pf").write_bytes(b"x")
    targets = collect_targets(str(tmp_path))
    assert [t.rsplit("/", 1)[-1] for t in targets] == ["a.evtx", "b.pf"]
