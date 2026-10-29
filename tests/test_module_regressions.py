"""Non-regression des bugs trouves en faisant tourner chaque module sur des preuves synthétiques."""
from __future__ import annotations

import datetime
import json
import os
import re

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
    assert _syslog_iso("Sep 21 09:59:01", ref) == "2025-09-21T09:59:01"  # passage d'année
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
    binary = {"type": "elf_analysis", "metadata": {"SHA-256": "a" * 64, "[ALERTE] Réseau": "connect()"},
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


def _pdf(tmp_path, name: str, body: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(b"%PDF-1.5\n" + body + b"\ntrailer<</Root 1 0 R>>\n%%EOF\n")
    return str(path)


def _flate(obj: int, data: bytes, extra: bytes = b"") -> bytes:
    import zlib
    z = zlib.compress(data)
    return (b"%d 0 obj<</Length %d/Filter/FlateDecode%s>>stream\n" % (obj, len(z), extra)) + z + b"\nendstream endobj\n"


def test_pdf_scoring_flags_malicious_documents(tmp_path):
    from forensic_analyzer.analyzers.pdf import PDFAnalyzer

    def score(path):
        meta = PDFAnalyzer().analyze(path).metadata
        return int(meta["Niveau de Menace (Scoring PDF)"].split("/")[0]), meta

    js_open = _pdf(tmp_path, "js.pdf", b"1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n"
                                        b"2 0 obj<</S/JavaScript/JS(app.alert(1))>>endobj")
    s, meta = score(js_open)
    assert s >= 45 and "Critique" in meta["PDF Actions"]

    obfuscated = _pdf(tmp_path, "obf.pdf", b"1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n"
                                           b"2 0 obj<</S/J#61vaScript/J#53 3 0 R>>endobj\n"
                                           + _flate(3, b"var s=unescape('%u9090%u9090%u9090');eval(s);"))
    s, meta = score(obfuscated)
    assert s >= 90 and "Noms obfusqués" in meta and "Shellcode" in meta

    launch = _pdf(tmp_path, "launch.pdf", b"1 0 obj<</Type/Catalog/OpenAction<</S/Launch/F(cmd.exe)>>>>endobj")
    assert score(launch)[0] >= 40

    attached = _pdf(tmp_path, "att.pdf", b"1 0 obj<</Type/Catalog/Names<</EmbeddedFiles 2 0 R>>>>endobj")
    assert "Fichiers Embarqués" in score(attached)[1]


def test_pdf_scoring_ignores_benign_structures(tmp_path):
    from forensic_analyzer.analyzers.pdf import PDFAnalyzer

    benign = _pdf(tmp_path, "benign.pdf",
                  b"1 0 obj<</Type/Catalog/OpenAction[3 0 R/Fit]/JSomething 1>>endobj\n"
                  + _flate(2, b"BT /F1 12 Tf (Rapport annuel) Tj ET\n" * 200 + b"\x90" * 64)  # octets 0x90 bruts
                  + b"4 0 obj<</Length 4096/Filter/DCTDecode>>stream\n" + os.urandom(4096) + b"\nendstream endobj\n")
    meta = PDFAnalyzer().analyze(benign).metadata
    assert meta["Niveau de Menace (Scoring PDF)"].startswith("5/100")
    assert "Shellcode" not in meta and "/JS" not in meta.get("Tags PDF Suspects", "")


def test_pdf_actions_hidden_in_object_stream(tmp_path):
    from forensic_analyzer.analyzers.pdf import PDFAnalyzer

    objects = b"2 0 3 40 <</S/JavaScript/JS(app.alert(1))>> <</Type/Catalog/OpenAction 2 0 R>>"
    hidden = _pdf(tmp_path, "objstm.pdf", _flate(5, objects, b"/Type/ObjStm/N 2/First 8"))
    meta = PDFAnalyzer().analyze(hidden).metadata
    assert "Critique" in meta["PDF Actions"]


def test_pdf_js_bytes_inside_binary_stream_are_ignored(tmp_path):
    from forensic_analyzer.analyzers.pdf import PDFAnalyzer

    image = os.urandom(2000) + b"/JS\x91" + os.urandom(2000)
    path = _pdf(tmp_path, "img.pdf", b"1 0 obj<</Length 4004/Filter/DCTDecode>>stream\n" + image + b"\nendstream endobj")
    assert "PDF Actions" not in PDFAnalyzer().analyze(path).metadata


def test_stego_finds_message_in_wav_lsb(tmp_path):
    import struct
    import wave
    from forensic_analyzer.analyzers.stego import StegoAnalyzer

    bits = [int(b) for c in b"SECRET:flag{audio_lsb_message}" for b in f"{c:08b}"]
    samples = [(1000 + 7 * i) & ~1 | (bits[i] if i < len(bits) else 0) for i in range(4000)]
    path = tmp_path / "voice.wav"
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(struct.pack(f"<{len(samples)}h", *samples))

    meta = StegoAnalyzer().analyze(str(path)).metadata
    assert "flag{audio_lsb_message}" in meta["Message LSB (audio)"]
    assert meta["Verdict"] == "STEGO PROBABLE"


def test_folder_keeps_only_files_of_the_chosen_type(tmp_path):
    from forensic_analyzer.analyzers.ioc import IOCAnalyzer
    from forensic_analyzer.analyzers.linux import LinuxArtifactsAnalyzer
    from forensic_analyzer.analyzers.pdf import PDFAnalyzer
    from forensic_analyzer.core.scanner import files_for

    (tmp_path / "sub").mkdir()
    (tmp_path / "a.pdf").write_bytes(b"%PDF-1.4\n%%EOF\n")
    (tmp_path / "sub" / "renamed.bin").write_bytes(b"%PDF-1.7\n%%EOF\n")   # PDF reconnu par sa signature
    (tmp_path / "notes.txt").write_text("185.220.101.42")
    (tmp_path / "fake.pdf").write_bytes(b"MZ\x90\x00" + b"\x00" * 60)      # exécutable déguisé en PDF

    assert sorted(os.path.basename(f) for f in files_for(PDFAnalyzer(), str(tmp_path))) == ["a.pdf", "renamed.bin"]
    assert files_for(PDFAnalyzer(), str(tmp_path / "a.pdf")) == [str(tmp_path / "a.pdf")]
    assert len(files_for(IOCAnalyzer(), str(tmp_path))) == 4               # tout fichier
    assert files_for(LinuxArtifactsAnalyzer(), str(tmp_path)) == [str(tmp_path)]  # la racine elle-même


def test_lnk_and_chromium_downloads_reach_the_timeline():
    from forensic_analyzer.analyzers.timeline.analyzer import build_timeline

    # LnkParse3 fournit un datetime, pas une chaîne
    lnk = FindingModel(type="lnk_shortcut", file="evil.lnk",
                       metadata={"Date Création (LNK)": datetime.datetime(2026, 9, 21, 10, 0)})
    chrome = FindingModel(type="chromium_artifacts", file="History", extra={"chromium_downloads": [
        {"fichier": "C:\\\\Users\\\\bob\\\\mimikatz.zip", "date": "2026-09-21 10:05:00", "taille_octets": 1, "danger_type": 1}]})
    sources = {e["file"] for e in build_timeline(ReportModel.from_findings([lnk, chrome]))}
    assert {"evil.lnk", "History"} <= sources


def test_timeline_tokens_ignore_accents():
    from forensic_analyzer.core.timeline import _tokens

    assert _tokens({"description": "Création de l'unité /etc/x.service"}) == \
        _tokens({"description": "Creation de l'unite /etc/x.service"})


# Audit de sécurité : preuves malveillantes


def test_graph_tooltips_cannot_inject_html(tmp_path):
    pytest.importorskip("pyvis")
    from forensic_analyzer.core.correlation import correlate
    from forensic_analyzer.output.graph_renderer import render_correlation_graph

    evil = "http://185.220.101.42/x?href=<img/src=x/onerror=alert(1)>"
    findings = [FindingModel(type="elf_analysis", file="/e/implant", extra={"iocs": {"urls": [evil]}}),
                FindingModel(type="ioc", file="/e/notes.txt", extra={"iocs": {"urls": [evil]}})]
    out = render_correlation_graph(correlate(findings), str(tmp_path / "g.html"))
    page = open(out).read()
    # Seules les infobulles passent par innerHTML (libellés et identifiants : dessin sur canevas)
    nodes = json.loads(re.search(r"nodes = new vis\.DataSet\((.*?)\);", page, re.S).group(1))
    assert "popup.innerHTML" in page   # mode HTML bien déclenché par "href"
    assert all("<" not in n["title"] for n in nodes)


def test_terminal_output_neutralizes_escape_sequences(capsys):
    from forensic_analyzer.output import ui

    evil = "a\x1b[1A\x1b[2K\x1b]52;c;cHduZWQ=\x07b"
    ui.render_finding(FindingModel(type="pdf_analysis", file="/e/" + evil, metadata={"Author": evil},
                                   extra={"strings": [evil]}))
    ui.error(evil)
    out = capsys.readouterr().out
    assert "\x1b[1A" not in out and "\x1b]52" not in out and "\x07" not in out
    assert "\\x1b]52" in out


def test_csv_exports_cannot_carry_formulas(tmp_path, monkeypatch):
    import csv
    from forensic_analyzer.output.csv_exporter import CSVExporter

    monkeypatch.chdir(tmp_path)
    linux = FindingModel(type="linux_artifacts", file="/e/root", extra={"timeline_events": [
        {"timestamp": "2026-09-21T10:00:00", "source": "bash_history", "event_type": "command",
         "description": "=HYPERLINK(\"http://evil\",\"x\")", "details": "+cmd|' /C calc'!A0"}]})
    CSVExporter().export(ReportModel.from_findings([linux]), "t.csv")
    rows = list(csv.DictReader(open(tmp_path / "export" / "t.csv")))
    assert rows[0]["description"].startswith("'=") and rows[0]["details"].startswith("'+")


def test_browser_databases_never_touch_evidence(tmp_path):
    import hashlib
    import sqlite3
    from forensic_analyzer.analyzers.firefox import FirefoxHistoryAnalyzer

    src = tmp_path / "src"
    src.mkdir()
    conn = sqlite3.connect(src / "places.sqlite")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.executescript("""
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT);
        CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INT, visit_date INT, visit_type INT);
        INSERT INTO moz_places VALUES (1, 'http://only-in-wal.example', 't', 1);
        INSERT INTO moz_historyvisits VALUES (1, 1, 1790000000000000, 1);""")
    conn.commit()
    evidence = tmp_path / "profil?mode=rwc#x"   # nom de dossier qui détournait l'URI SQLite
    evidence.mkdir()
    for name in ("places.sqlite", "places.sqlite-wal"):
        (evidence / name).write_bytes((src / name).read_bytes())
    conn.close()

    def state():
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in tmp_path.iterdir() if p.is_file()} | \
               {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in evidence.iterdir()}
    before = state()
    finding = FirefoxHistoryAnalyzer().analyze(str(evidence / "places.sqlite"))
    assert [e["url"] for e in finding.extra["history"]] == ["http://only-in-wal.example"]
    assert state() == before


def test_manifest_found_in_evidence_stays_in_its_folder(tmp_path):
    from forensic_analyzer.core.integrity import verify_manifest

    secret = tmp_path / "secret.key"
    secret.write_text("cle privee")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "disk.img").write_bytes(b"img")
    manifest = evidence / "manifest.sha256"
    manifest.write_text(f"{'0' * 64}  disk.img\n{'0' * 64}  ../secret.key\n{'0' * 64}  {secret}\n")

    confined = {r["file"]: r["status"] for r in verify_manifest(str(manifest), confined=True)["results"]}
    assert confined["../secret.key"] == confined[str(secret)] == "HORS PÉRIMÈTRE"
    assert confined["disk.img"] == "DIFFÉRENT"
    trusted = verify_manifest(str(manifest))["results"]
    assert all(r["status"] != "HORS PÉRIMÈTRE" for r in trusted)


def test_ioc_regexes_stay_linear_on_hostile_strings():
    import time
    from forensic_analyzer.analyzers.ioc.analyzer import extract_iocs
    from forensic_analyzer.utils.strings_extractor import categorize_strings

    hostile = ["http://" + "a." * 50000, "a" * 50000 + "@" + "a" * 50000]
    start = time.perf_counter()
    for s in hostile:
        extract_iocs(s)
        categorize_strings([(0, s)])
    assert time.perf_counter() - start < 5
    assert extract_iocs("ecrire a admin@evil-corp.com")["emails"] == ["admin@evil-corp.com"]


def test_updater_runs_git_in_the_tool_repository(monkeypatch, tmp_path):
    import subprocess
    from forensic_analyzer.core import updater

    monkeypatch.chdir(tmp_path)
    calls = []

    class Done:
        returncode, stdout, stderr = 1, "", ""

    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: calls.append(kw.get("cwd")) or Done())
    monkeypatch.setattr(updater.os.path, "isdir", lambda p: True)
    updater.Updater().check_and_update()
    assert calls and all(c == updater._REPO for c in calls)
