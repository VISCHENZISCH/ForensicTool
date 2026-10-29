"""Structure d'une image disque brute : table de partitions et systèmes de fichiers.

Équivalent en Python pur de `mmls` (MBR / GPT) et d'un `fsstat` réduit pour ext2/3/4.
"""
from __future__ import annotations

import datetime
import struct
import uuid

SECTOR = 512

_GPT_TYPES = {
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709": "Linux root (x86-64)",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "933ac7e1-2eb4-4f13-b844-0e14e2aef915": "Linux /home",
    "bc13c2ff-59e6-4262-a352-b275fd6f7172": "Linux /boot (XBOOTLDR)",
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "21686148-6449-6e6f-744e-656564454649": "BIOS boot",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft basic data",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft reserved",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows recovery",
}
_MBR_TYPES = {0x07: "NTFS / exFAT", 0x0B: "FAT32", 0x0C: "FAT32 (LBA)", 0x83: "Linux",
              0x82: "Linux swap", 0x8E: "Linux LVM", 0xEE: "GPT protective", 0xEF: "EFI System",
              0x05: "Étendue", 0x0F: "Étendue (LBA)"}


def _read(f, offset: int, size: int) -> bytes:
    f.seek(offset)
    return f.read(size)


def _utc(ts: int) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat() if ts else ""


def detect_filesystem(f, offset: int) -> str:
    """Type de système de fichiers commençant à `offset` ('' si inconnu)."""
    boot = _read(f, offset, 4096)
    if len(boot) < 512:
        return ""
    if boot[3:11] == b"NTFS    ":
        return "NTFS"
    if boot[82:90].startswith(b"FAT32"):
        return "FAT32"
    if boot[54:62].startswith((b"FAT16", b"FAT12")):
        return boot[54:59].decode()
    if boot[:4] == b"XFSB":
        return "XFS"
    if boot[:6] == b"LUKS\xba\xbe":
        return "LUKS (chiffré)"
    if boot[4086:4096] in (b"SWAPSPACE2", b"SWAP-SPACE"):
        return "swap"
    if len(boot) >= 1082 and struct.unpack_from("<H", boot, 1080)[0] == 0xEF53:
        incompat = struct.unpack_from("<I", boot, 1024 + 96)[0]
        compat = struct.unpack_from("<I", boot, 1024 + 92)[0]
        if incompat & 0x40:      # extents
            return "ext4"
        return "ext3" if compat & 0x4 else "ext2"
    if _read(f, offset + 0x10040, 8) == b"_BHRfS_M":
        return "Btrfs"
    return ""


def ext_superblock(f, offset: int) -> dict:
    """Champs utiles du superbloc ext2/3/4 (équivalent partiel de fsstat)."""
    sb = _read(f, offset + 1024, 1024)
    if len(sb) < 264 or struct.unpack_from("<H", sb, 56)[0] != 0xEF53:
        return {}
    inodes, blocks_lo = struct.unpack_from("<II", sb, 0)
    log_block = struct.unpack_from("<I", sb, 24)[0]
    mtime, wtime, mnt_count = struct.unpack_from("<IIH", sb, 44)
    state = struct.unpack_from("<H", sb, 58)[0]
    lastcheck = struct.unpack_from("<I", sb, 64)[0]
    mkfs_time = struct.unpack_from("<I", sb, 264)[0] if len(sb) >= 268 else 0
    return {
        "volume_name": sb[120:136].split(b"\0")[0].decode("utf-8", "replace"),
        "uuid": str(uuid.UUID(bytes=sb[104:120])),
        "block_size": 1024 << log_block,
        "inodes": inodes,
        "blocks": blocks_lo,
        "created": _utc(mkfs_time),
        "last_mounted": _utc(mtime),
        "last_written": _utc(wtime),
        "last_checked": _utc(lastcheck),
        "mount_count": mnt_count,
        "last_mount_path": sb[136:200].split(b"\0")[0].decode("utf-8", "replace"),
        "state": "démonté proprement" if state & 1 else "non démonté proprement",
    }


def read_partitions(f) -> tuple[str, list[dict]]:
    """(schéma, partitions) depuis une table GPT ou MBR."""
    mbr = _read(f, 0, SECTOR)
    if len(mbr) < SECTOR or mbr[510:512] != b"\x55\xaa":
        return "", []
    # Un secteur de démarrage NTFS/FAT porte aussi 55AA : système de fichiers nu, pas de table
    if detect_filesystem(f, 0):
        return "", []

    header = _read(f, SECTOR, SECTOR)
    if header[:8] == b"EFI PART":
        entries_lba, count, size = struct.unpack_from("<QII", header, 72)
        table = _read(f, entries_lba * SECTOR, count * size)
        parts = []
        for i in range(count):
            e = table[i * size:(i + 1) * size]
            if len(e) < 128 or e[:16] == b"\0" * 16:
                continue
            type_guid = str(uuid.UUID(bytes_le=e[:16]))
            first, last = struct.unpack_from("<QQ", e, 32)
            parts.append({
                "index": i, "start": first, "end": last, "sectors": last - first + 1,
                "type": _GPT_TYPES.get(type_guid, type_guid),
                "name": e[56:128].decode("utf-16le", "replace").rstrip("\0"),
            })
        return "GPT", sorted(parts, key=lambda p: p["start"])

    parts = []
    for i in range(4):
        e = mbr[446 + i * 16:446 + (i + 1) * 16]
        ptype = e[4]
        start, sectors = struct.unpack_from("<II", e, 8)
        if ptype and sectors:
            parts.append({"index": i, "start": start, "end": start + sectors - 1, "sectors": sectors,
                          "type": _MBR_TYPES.get(ptype, hex(ptype)), "name": ""})
    return "MBR", parts


def describe(path: str) -> dict:
    """Schéma, partitions (avec système de fichiers et superbloc ext) ou système de fichiers nu."""
    with open(path, "rb") as f:
        scheme, parts = read_partitions(f)
        for p in parts:
            p["filesystem"] = detect_filesystem(f, p["start"] * SECTOR)
            if p["filesystem"].startswith("ext"):
                p["superblock"] = ext_superblock(f, p["start"] * SECTOR)
        bare = "" if parts else detect_filesystem(f, 0)
        superblock = ext_superblock(f, 0) if bare.startswith("ext") else {}
    return {"scheme": scheme, "partitions": parts, "bare_filesystem": bare, "superblock": superblock}


def is_disk_image(path: str) -> bool:
    """Vrai si l'image commence par une table de partitions ou un système de fichiers reconnu."""
    try:
        with open(path, "rb") as f:
            if read_partitions(f)[0]:
                return True
            return bool(detect_filesystem(f, 0))
    except OSError:
        return False
