"""Lecture directe d'image, corrélation, chronologie consolidée, désassemblage et règles."""
from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess

import pytest

from forensic_analyzer.analyzers.disk import layout
from forensic_analyzer.core.correlation import correlate
from forensic_analyzer.core.timeline import consolidate
from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.output.rules_generator import DefenseRulesGenerator

IMPLANT = "/usr/lib/systemd/.cache/evil"


# 1. Lecture directe d'une image disque (pytsk3)

@pytest.fixture
def ext4_image(tmp_path):
    pytest.importorskip("pytsk3")
    if not shutil.which("mke2fs"):
        pytest.skip("mke2fs absent")
    src = tmp_path / "src"
    files = {
        "etc/hostname": "victim\n",
        "etc/systemd/system/systemd-evil.service":
            f"[Service]\nExecStart={IMPLANT}\nRestart=always\n[Install]\nWantedBy=multi-user.target\n",
        IMPLANT.lstrip("/"): "\x7fELF not really\n",
        "var/lib/dpkg/info/base.list": "/etc/hostname\n",
        "var/lib/dpkg/info/base.md5sums": "",
    }
    for rel, content in files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    img = evidence / "disk.img"
    subprocess.run(["mke2fs", "-q", "-t", "ext4", "-d", str(src), "-F", str(img), "8M"], check=True)
    return img


def test_disk_image_is_analyzed_without_extraction(ext4_image, tmp_path):
    from forensic_analyzer.analyzers.disk import DiskAnalyzer

    results = DiskAnalyzer(workdir=str(tmp_path / "work")).analyze(str(ext4_image))
    by_type = {r.type: r for r in results}
    assert {"disk", "linux_artifacts"} <= by_type.keys()
    units = by_type["linux_artifacts"].extra["systemd"]["units"]
    assert units[0]["unit"] == "/etc/systemd/system/systemd-evil.service" and units[0]["suspicious"]
    # Le triage écrit dans le dossier de travail, jamais à côté des preuves
    assert os.listdir(ext4_image.parent) == ["disk.img"]
    assert (tmp_path / "work").exists()


def test_extraction_refused_inside_evidence_dir(ext4_image):
    from forensic_analyzer.analyzers.disk import DiskAnalyzer

    result = DiskAnalyzer(workdir=str(ext4_image.parent)).analyze(str(ext4_image))
    assert isinstance(result, FindingModel)  # seule l'analyse disque, aucune extraction
    assert os.listdir(ext4_image.parent) == ["disk.img"]


def test_unit_path_cannot_escape_extraction_dir(ext4_image, tmp_path):
    """Un ExecStart en `/../..` est résolu par TSK dans l'image : il ne doit pas écrire hors du dossier de travail."""
    from forensic_analyzer.analyzers.disk import DiskAnalyzer, tsk_image

    work = tmp_path / "work"
    for fs in tsk_image.open_filesystems(str(ext4_image)):
        dest = work / f"{fs.family}_{fs.offset}"
        assert fs.extract("/../../../" + IMPLANT.lstrip("/"), str(dest)) is None
        assert fs.extract(IMPLANT, str(dest)) == str(dest) + IMPLANT
    assert not (tmp_path / IMPLANT.lstrip("/")).exists()
    assert tsk_image.local_path(str(work), "/etc/../../x") is None

    DiskAnalyzer(workdir=str(work)).analyze(str(ext4_image))
    assert not (tmp_path / IMPLANT.lstrip("/")).exists()


def test_carving_writes_outside_evidence_dir(tmp_path):
    from forensic_analyzer.analyzers.carving import CarvingAnalyzer

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    blob = evidence / "blob.bin"
    blob.write_bytes(b"\x00" * 64 + b"PK\x03\x04" + b"\x00" * 26 + b"PK\x05\x06" + b"\x00" * 18)

    result = CarvingAnalyzer(workdir=str(tmp_path / "work")).analyze(str(blob))
    assert os.listdir(evidence) == ["blob.bin"]
    carved = result.extra["embedded"][0]["extracted_path"]
    assert carved.startswith(str(tmp_path / "work") + os.sep) and os.path.isfile(carved)

    CarvingAnalyzer(workdir=str(evidence)).analyze(str(blob))
    assert os.listdir(evidence) == ["blob.bin"]


def test_bare_ntfs_boot_sector_is_not_a_partition_table(tmp_path):
    boot = bytearray(4096)
    boot[3:11] = b"NTFS    "
    boot[510:512] = b"\x55\xaa"
    img = tmp_path / "ntfs.img"
    img.write_bytes(bytes(boot))
    info = layout.describe(str(img))
    assert info["scheme"] == "" and info["bare_filesystem"] == "NTFS"


# 2. Corrélation multi-sources

def _finding(ftype, extra=None, **meta):
    return FindingModel(type=ftype, file=f"/case/{ftype}", metadata=meta, extra=extra or {})


def test_correlation_links_disk_memory_and_binary():
    findings = [
        _finding("elf_analysis", {"iocs": {"ips": ["203.0.113.50"], "paths": []}},
                 **{"Origine (image)": f"disk.raw:{IMPLANT}"}),
        _finding("memory", {"suspicious_processes": [{"pid": 315, "comm": "evil", "args": IMPLANT}],
                            "remote_sockets": [{"dst": "203.0.113.50:4444", "process": "evil", "pid": 315}]}),
        _finding("linux_artifacts", {"file_anomalies": {"caches": [{"path": IMPLANT}]}}),
    ]
    corr = correlate(findings)
    shared = {(i["kind"], i["value"]): set(i["sources"]) for i in corr.extra["shared"]}
    assert shared[("path", IMPLANT)] == {"elf_analysis", "memory", "linux_artifacts"}
    assert shared[("ipv4", "203.0.113.50")] == {"elf_analysis", "memory"}
    assert corr.extra["graph"]["edges"]


# 3. Chronologie consolidée

def _ev(ts, source, desc, etype="x"):
    return {"timestamp": ts, "source": source, "event_type": etype, "description": desc}


def test_consolidation_confidence_levels():
    facts = consolidate([
        _ev("2026-10-21T08:54:37.812+00:00", "journald", "Started systemd-sysupdate.service - System Update Helper."),
        _ev("2026-10-21T08:54:37.824+00:00", "audit.log", "SERVICE_START systemd-sysupdate"),
        _ev("2026-10-21T08:55:00+00:00", "bodyfile", "Modification de l'unite /etc/x.service", "unit_modified"),
        _ev("2026-10-21T09:00:00+00:00", "journald", "System is powering down."),
    ])
    assert [(f["confidence"], f["sources"]) for f in facts] == [
        ("élevée", ["audit.log", "journald"]), ("faible", ["bodyfile"]), ("moyenne", ["journald"])]


def test_consolidation_does_not_chain_beyond_window():
    events = [_ev(f"2026-10-21T08:00:0{i}+00:00", src, "session root ttyS0")
              for i, src in enumerate(("wtmp", "audit.log", "journald", "memory"))]
    facts = consolidate(events, window=2.0)
    assert len(facts) == 2  # 0 s → 2 s, puis un nouveau fait à 3 s


# 4. Désassemblage

def _x86_beacon():
    """main() : inet_pton(AF_INET, "203.0.113.50", ...) ; sockaddr {AF_INET, 4444} ; connect ; sleep(300)."""
    base, inet_pton, connect, sleep, string_at = 0x401000, 0x402000, 0x402100, 0x402200, 0x403000
    code = bytearray()

    def call(target):
        code.extend(b"\xe8" + struct.pack("<i", target - (base + len(code) + 5)))

    code.extend(b"\xbd" + struct.pack("<I", 0x5C110002))                          # mov ebp, sockaddr
    code.extend(b"\x48\x8d\x35" + struct.pack("<i", string_at - (base + len(code) + 7)))  # lea rsi, [rip+str]
    code.extend(b"\xbf\x02\x00\x00\x00")                                          # mov edi, 2
    call(inet_pton)
    call(connect)
    code.extend(b"\xbf" + struct.pack("<I", 300))                                 # mov edi, 300
    call(sleep)
    names = {inet_pton: "__inet_pton", connect: "__libc_connect", sleep: "sleep"}
    return base, bytes(code), names, string_at


def test_disassembly_recovers_beacon_parameters():
    pytest.importorskip("capstone")
    from capstone import x86_const

    from forensic_analyzer.utils import disasm

    base, code, names, string_at = _x86_beacon()
    reader = disasm._Reader(b"203.0.113.50\x00", [{"addr": string_at, "offset": 0, "size": 13}])

    def resolve(insn):
        op = insn.operands[0]
        return names.get(op.imm) if op.type == x86_const.X86_OP_IMM else None

    calls = disasm.analyze_code([(base, code)], reader, resolve)
    summary = disasm.summarize(calls)
    assert summary["endpoints"] == [{"host": "203.0.113.50", "port": 4444}]
    assert summary["sleep_seconds"] == [300.0]


# 5. Règles de détection et STIX

def test_rules_generation_compiles_and_matches(tmp_path):
    yara = pytest.importorskip("yara")
    elf = _finding("elf_analysis", {
        "iocs": {"ips": ["203.0.113.50"], "paths": ["/tmp/.X11-unix/.lock"]},
        "network": [{"host": "203.0.113.50", "port": 4444}],
        "mitre": [{"id": "T1571", "name": "Non-Standard Port", "tactic": "C2"}],
    }, **{"[ALERTE] Comportement": "Balise", "SHA-256": "a" * 64, "Origine (image)": f"disk.raw:{IMPLANT}"})
    unit = _finding("linux_artifacts", {"systemd": {"units": [{
        "suspicious": True, "unit": "/etc/systemd/system/systemd-evil.service", "binary": IMPLANT}]}})

    out = DefenseRulesGenerator().generate(ReportModel.from_findings([elf, unit]), str(tmp_path))

    rules = yara.compile(filepath=out["yara"])
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"203.0.113.50\x00/tmp/.X11-unix/.lock\x00")
    assert [m.rule for m in rules.match(str(sample))] == ["FA_ELF_evil"]
    assert "203.0.113.50 4444" in open(out["suricata"]).read()
    assert "sigma/linux_auditd_service_start.yml" in out

    bundle = json.load(open(out["stix"]))
    ids = {o["id"] for o in bundle["objects"]}
    assert all(o["source_ref"] in ids and o["target_ref"] in ids
               for o in bundle["objects"] if o["type"] == "relationship")
    assert any("dst_port = 4444" in o.get("pattern", "") for o in bundle["objects"])
