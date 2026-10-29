"""Non-regression des bugs trouves en faisant tourner chaque module sur des preuves synthetiques."""
from __future__ import annotations

import datetime
import os

import pytest

from forensic_analyzer.analyzers.evtx import EVTXAnalyzer
from forensic_analyzer.analyzers.linux.analyzer import _syslog_iso, parse_auth_log
from forensic_analyzer.analyzers.pcap.timeline import build_attack_timeline
from forensic_analyzer.analyzers.windows_execution import WindowsExecutionAnalyzer
from forensic_analyzer.core import iocs
from forensic_analyzer.models.finding import FindingModel, ReportModel, compute_hashes
from forensic_analyzer.output.rules_generator import DefenseRulesGenerator

PIL = pytest.importorskip("PIL.Image")


def test_gps_date_is_extracted(tmp_path):
    from PIL.TiffImagePlugin import IFDRational as R
    from forensic_analyzer.analyzers.gps import GPSAnalyzer

    path = tmp_path / "photo.jpg"
    exif = PIL.Exif()
    exif[0x8825] = {1: "N", 2: (R(48), R(51), R(24)), 3: "E", 4: (R(2), R(17), R(40)),
                    29: "2026:10:01", 7: (R(10), R(0), R(0))}
    PIL.new("RGB", (8, 8)).save(path, exif=exif)

    meta = GPSAnalyzer().analyze(str(path)).metadata
    assert meta["Date/Heure GPS (UTC)"] == "2026/10/01 10:00:00 UTC"


def test_stego_finds_message_spread_over_rgb(tmp_path):
    from forensic_analyzer.analyzers.stego import StegoAnalyzer

    img = PIL.new("RGB", (64, 64), (200, 200, 200))
    px = img.load()
    bits = iter("".join(f"{b:08b}" for b in b"SECRET:flag{lsb_hidden_message}" * 4))
    for y in range(64):
        for x in range(64):
            px[x, y] = tuple((c & ~1) | int(next(bits, "0")) for c in px[x, y])
    path = tmp_path / "logo.png"
    img.save(path)

    meta = StegoAnalyzer().analyze(str(path)).metadata
    assert meta["Verdict"].startswith("STEGO CERTAINE")
    assert "flag{lsb_hidden_message}" in meta["Strings LSB (RGB entrelace)"]


def test_plain_image_stays_clean(tmp_path):
    from forensic_analyzer.analyzers.stego import StegoAnalyzer

    path = tmp_path / "plain.png"
    PIL.new("RGB", (64, 64), (120, 30, 200)).save(path)
    assert StegoAnalyzer().analyze(str(path)).metadata["Verdict"] == "CLEAN"


def test_pcap_timeline_reads_c2_ip_from_connection():
    scapy = pytest.importorskip("scapy.all")
    pkt = scapy.IP(src="10.0.0.5", dst="185.220.101.42") / scapy.TCP(dport=443, flags="S")
    pkt.time = 1_790_000_000
    beacons = {"beacons": [{"connection": "10.0.0.5 -> 185.220.101.42:443",
                            "detail": "Beacon suspect : intervalle ~60s, jitter 0%"}]}
    timeline = build_attack_timeline([pkt], [], beacons)
    assert [e["type"] for e in timeline] == ["C2 CONNECT"]


def test_evtx_never_writes_next_to_evidence(tmp_path, monkeypatch):
    pytest.importorskip("Evtx")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    log = evidence / "Security.evtx"
    log.write_bytes(b"ElfFile\x00" + b"\x00" * 4000)
    monkeypatch.chdir(tmp_path)

    res = EVTXAnalyzer().analyze(str(log))
    assert os.listdir(evidence) == ["Security.evtx"]
    assert res.metadata["Timeline Exportée"].startswith("export")
    assert "Avertissement" in res.metadata


def test_prefetch_name_keeps_single_extension(tmp_path):
    pf = tmp_path / "CMD.EXE-1234ABCD.pf"
    pf.write_bytes(b"MAM\x04" + b"\x00" * 200)
    meta = WindowsExecutionAnalyzer().analyze(str(pf)).metadata
    assert meta["Exécutable Source"] == "CMD.EXE"
    assert "Avertissement" in meta


def test_syslog_year_comes_from_log_mtime(tmp_path):
    ref = datetime.datetime(2026, 1, 5, 12, 0)
    assert _syslog_iso("Sep 21 09:59:01", ref) == "2025-09-21T09:59:01"  # passage d'annee
    assert _syslog_iso("Jan  3 08:00:00", ref) == "2026-01-03T08:00:00"
    assert _syslog_iso("2026-01-03T08:00:00+01:00", ref) == "2026-01-03T08:00:00+01:00"

    log = tmp_path / "auth.log"
    log.write_text("2026-01-03T08:00:00.123+01:00 web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n")
    assert parse_auth_log(str(log))["failed_details"][0]["timestamp"].startswith("2026-01-03T08:00:00")


def test_browser_history_is_not_an_ioc():
    chrome = FindingModel(type="chromium_artifacts", file="History", extra={"chromium_urls": [
        {"url": "https://www.google.com/search?q=x"},
        {"url": "http://185.220.101.42/x"},
        {"url": "https://cdn.example.org/tool.exe"},
    ]})
    firefox = FindingModel(type="firefox_places", file="places.sqlite", extra={
        "history": [{"url": "https://www.wikipedia.org/"}], "suspects": ["https://pastebin.com/raw/abc"]})
    values = {i.value for i in iocs.collect([chrome, firefox])}
    assert "www.google.com" not in values and "www.wikipedia.org" not in values
    assert {"185.220.101.42", "cdn.example.org", "pastebin.com"} <= values


def test_generated_yara_compiles_with_duplicate_binary(tmp_path):
    yara = pytest.importorskip("yara")
    binary = {"type": "elf_analysis", "metadata": {"SHA-256": "a" * 64, "[ALERTE] Reseau": "connect()"},
              "extra": {"iocs": {"ips": ["185.220.101.42"], "paths": ["/tmp/.x/kworkerd"]}}}
    report = ReportModel.from_findings([
        FindingModel(file="/evidence/kworkerd", **binary),
        FindingModel(file="/export/extractions/img/tmp/.x/kworkerd", **binary),
        FindingModel(file="/other/kworkerd", **{**binary, "metadata": {**binary["metadata"], "SHA-256": "b" * 64}}),
    ])
    out = DefenseRulesGenerator().generate(report, output_dir=str(tmp_path))
    yara.compile(filepath=out["yara"])
    text = open(out["yara"]).read()
    assert text.count("rule FA_ELF_kworkerd {") == 1 and "rule FA_ELF_kworkerd_2 {" in text


def test_hash_cache_follows_file_changes(tmp_path):
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"one")
    first = compute_hashes(str(path))["SHA-256"]
    path.write_bytes(b"two!")
    assert compute_hashes(str(path))["SHA-256"] != first


def test_pe_with_version_info_is_fully_parsed():
    import pip._vendor.distlib as distlib
    from forensic_analyzer.analyzers.malware import MalwareAnalyzer
    from forensic_analyzer.analyzers.malware.pe_parser import parse_pe_file

    exe = os.path.join(os.path.dirname(distlib.__file__), "t64.exe")
    if not os.path.isfile(exe):
        pytest.skip("lanceur distlib absent")
    info = parse_pe_file(exe)
    assert "error" not in info and info["version_strings"]
    finding = MalwareAnalyzer().analyze(exe)
    assert "Architecture" in finding.metadata
    # FileVersion "1.1.0.14" n'est pas une IP
    assert not finding.extra.get("strings_iocs", {}).get("ips")


def test_suricata_url_rule_is_anchored_on_host(tmp_path):
    elf = FindingModel(type="elf_analysis", file="/e/implant", extra={"iocs": {"urls": ["http://185.220.101.42/x"]}})
    out = DefenseRulesGenerator().generate(ReportModel.from_findings([elf]), output_dir=str(tmp_path))
    rule = next(l for l in open(out["suricata"]) if "http.uri" in l)
    assert 'http.host; content:"185.220.101.42"' in rule and 'http.uri; content:"/x"' in rule
