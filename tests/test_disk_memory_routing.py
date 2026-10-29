"""Aiguillage disque / mémoire des fichiers .raw, structure de disque et détection d'OS."""
from __future__ import annotations

import hashlib
import struct

from forensic_analyzer.analyzers.disk import DiskAnalyzer, layout
from forensic_analyzer.analyzers.integrity import IntegrityAnalyzer
from forensic_analyzer.analyzers.memory.analyzer import MemoryAnalyzer, detect_memory_os, find_symbols_dir
from forensic_analyzer.core.scanner import default_registry

EXT_START = 2048


def _disk_image(path):
    """Image MBR avec une partition Linux (0x83) contenant un superbloc ext4."""
    img = bytearray(EXT_START * 512 + 8192)
    img[450] = 0x83                                                # entrée 1 : type Linux
    struct.pack_into("<II", img, 454, EXT_START, 16)
    img[510:512] = b"\x55\xaa"
    sb = EXT_START * 512 + 1024
    struct.pack_into("<II", img, sb, 128, 1024)                   # inodes, blocs
    struct.pack_into("<IIH", img, sb + 44, 1792573198, 1792571933, 9)  # montage, écriture
    struct.pack_into("<HH", img, sb + 56, 0xEF53, 1)               # magic, état propre
    struct.pack_into("<I", img, sb + 96, 0x40)                     # extents → ext4
    img[sb + 136:sb + 137] = b"/"
    path.write_bytes(bytes(img))
    return str(path)


def _memory_dump(path, offset):
    data = bytearray(offset + 4096)
    banner = b"Linux version 6.1.0-54-amd64 (debian-kernel@lists.debian.org) (gcc-12) #1 SMP"
    data[offset:offset + len(banner)] = banner
    path.write_bytes(bytes(data))
    return str(path)


def test_layout_reads_mbr_and_ext4_superblock(tmp_path):
    info = layout.describe(_disk_image(tmp_path / "disk.raw"))
    [part] = info["partitions"]
    assert info["scheme"] == "MBR" and part["start"] == EXT_START
    assert part["filesystem"] == "ext4"
    assert part["superblock"]["last_written"] == "2026-10-21T08:38:53+00:00"
    assert part["superblock"]["last_mount_path"] == "/"


def test_raw_files_are_routed_by_content(tmp_path):
    disk = _disk_image(tmp_path / "disk.raw")
    mem = _memory_dump(tmp_path / "memory.raw", 100)
    registry = default_registry()
    assert [a.name for a in registry.get_all_for(disk)] == ["disk"]
    assert [a.name for a in registry.get_all_for(mem)] == ["memory"]
    assert DiskAnalyzer().can_handle(disk) and not MemoryAnalyzer().can_handle(disk)


def test_memory_os_detection_across_chunks(tmp_path):
    # La bannière chevauche la frontière entre deux blocs de lecture
    dump = _memory_dump(tmp_path / "mem.raw", 4096 - 20)
    os_type, banner = detect_memory_os(dump, chunk=4096)
    assert os_type == "linux" and banner.startswith("Linux version 6.1.0-54-amd64")
    (tmp_path / "blank.raw").write_bytes(b"\x00" * 8192)
    assert detect_memory_os(str(tmp_path / "blank.raw"))[0] == "windows"


def test_symbols_dir_next_to_dump(tmp_path):
    dump = _memory_dump(tmp_path / "mem.raw", 0)
    assert find_symbols_dir(dump) is None
    (tmp_path / "symbols").mkdir()
    assert find_symbols_dir(dump) == str(tmp_path / "symbols")


def test_manifest_is_verified_during_scan(tmp_path):
    (tmp_path / "disk.raw").write_bytes(b"disk")
    manifest = tmp_path / "forensic-artifacts.sha256"
    manifest.write_text(f"{hashlib.sha256(b'disk').hexdigest()}  disk.raw\n")
    assert [a.name for a in default_registry().get_all_for(str(manifest))] == ["integrity"]
    finding = IntegrityAnalyzer().analyze(str(manifest), phase="initiale")
    assert finding.metadata["Verdict"] == "Toutes les preuves sont intactes"
