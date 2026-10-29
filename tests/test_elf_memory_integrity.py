"""Tests de l'analyse ELF, du triage mémoire Linux, du manifeste d'empreintes et de MITRE."""
from __future__ import annotations

import hashlib
import os
import sys

from forensic_analyzer.analyzers.elf.analyzer import ELFAnalyzer, _hidden_system_paths
from forensic_analyzer.analyzers.elf.parser import parse_elf
from forensic_analyzer.analyzers.memory.analyzer import analyze_linux_results
from forensic_analyzer.core import mitre
from forensic_analyzer.core.integrity import verify_manifest


def test_parse_real_elf():
    with open(os.path.realpath(sys.executable), "rb") as f:
        info = parse_elf(f.read())
    assert info["class"] == "ELF64"
    assert info["linking"] == "dynamique" and info["interpreter"]


def test_elf_analyzer_rejects_non_elf(tmp_path):
    f = tmp_path / "not_elf.elf"
    f.write_bytes(b"MZ" + b"\x00" * 100)
    assert ELFAnalyzer().analyze(str(f)) is None


def test_hidden_system_paths_heuristic():
    strings = [
        "/tmp/.X11-unix/.sysupd_lock",            # implant : fichier caché dans /tmp
        "/usr/lib/systemd/.cache/sysupdate",      # répertoire caché sous /usr
        "/tmp/.X11-unix/X0",                       # socket X11 standard
        "/tmp/.X%d-lock",                          # verrou X11 standard
        "/usr/lib/debug/.dwz/x86_64/foo.debug",    # chemin de débogage
        "/usr/bin/.sysless",                       # fichier caché légitime (less)
        "/home/user/.bashrc",                      # hors répertoires système
    ]
    assert _hidden_system_paths(strings) == ["/tmp/.X11-unix/.sysupd_lock", "/usr/lib/systemd/.cache/sysupdate"]


def test_linux_memory_correlations():
    ok = lambda rows: {"success": True, "data": rows}  # noqa: E731
    results = {
        "pslist": ok([{"PID": 1, "COMM": "systemd"}, {"PID": 315, "COMM": "sysupdate"}]),
        "psscan": ok([
            {"PID": 1, "COMM": "systemd", "EXIT_STATE": "TASK_RUNNING"},
            {"PID": 315, "COMM": "sysupdate", "EXIT_STATE": "TASK_RUNNING"},
            {"PID": 666, "COMM": "rootkitd", "EXIT_STATE": "TASK_RUNNING"},
            {"PID": 342, "COMM": "bash", "EXIT_STATE": "EXIT_DEAD"},
            {"PID": 0, "COMM": "", "EXIT_STATE": "TASK_RUNNING"},          # carving corrompu
            {"PID": 2145, "COMM": "\x19\x0b", "EXIT_STATE": "TASK_RUNNING"},
        ]),
        "psaux": ok([{"PID": 315, "PPID": 1, "COMM": "sysupdate", "ARGS": "/usr/lib/systemd/.cache/sysupdate"}]),
        "sockstat": ok([
            {"Family": "AF_INET", "Destination Addr": "0.0.0.0", "Destination Port": "0", "PID": 319},
            {"Family": "AF_INET", "Destination Addr": "203.0.113.50", "Destination Port": "4444", "PID": 315,
             "Process Name": "sysupdate", "Source Addr": "10.0.0.5", "Source Port": "51000", "State": "ESTABLISHED"},
        ]),
        "check_syscall": ok([{"Handler Symbol": "__x64_sys_read"}, {"Handler Symbol": None}]),
    }
    meta, extra, techniques = analyze_linux_results(results)

    assert [p["COMM"] for p in extra["hidden_processes"]] == ["rootkitd"]
    assert len(extra["exited_tasks"]) == 1
    assert extra["suspicious_processes"][0]["pid"] == 315
    assert extra["remote_sockets"][0]["dst"] == "203.0.113.50:4444"
    assert meta["Appels système"] == "1/2 handlers vers le noyau"
    assert {"T1014", "T1564.001", "T1571"} <= techniques


def test_manifest_verification(tmp_path):
    (tmp_path / "disk.raw").write_bytes(b"disk")
    (tmp_path / "mem.raw").write_bytes(b"memory")
    manifest = tmp_path / "evidence.sha256"
    manifest.write_text(
        f"{hashlib.sha256(b'disk').hexdigest()}  disk.raw\n"
        f"{hashlib.sha256(b'tampered').hexdigest()} *mem.raw\n"
        f"{hashlib.md5(b'x').hexdigest()}  absent.raw\n"
    )
    res = verify_manifest(str(manifest))
    assert [r["status"] for r in res["results"]] == ["OK", "DIFFÉRENT", "ABSENT"]
    assert res["results"][2]["algo"] == "md5"
    assert not res["all_ok"]


def test_mitre_summary_is_sorted_and_deduplicated():
    assert mitre.summary(["T1564.001", "T1543.002", "T1543.002", "T9999"]) == \
        "T1543.002 Systemd Service, T1564.001 Hidden Files and Directories"
