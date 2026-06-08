"""Analyzer disque - MFT NTFS, ADS, ext4 inodes, slack space."""
from __future__ import annotations

import datetime
import os
import struct

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("disk")


def _windows_filetime_to_dt(filetime: int) -> str:
    """Convertit un Windows FILETIME (100ns depuis 1601) en datetime ISO."""
    if filetime <= 0:
        return "N/A"
    try:
        epoch_diff = 116444736000000000  # Difference 1601-1970 en 100ns
        timestamp = (filetime - epoch_diff) / 10_000_000
        return datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).isoformat()
    except (OSError, ValueError, OverflowError):
        return "N/A"


def parse_mft_record(data: bytes, offset: int = 0) -> dict | None:
    """Parse un enregistrement MFT NTFS (1024 octets)."""
    if len(data) < 1024:
        return None
    if data[0:4] != b'FILE':
        return None

    try:
        record = {
            "signature": data[0:4].decode('ascii', 'replace'),
            "sequence_number": struct.unpack_from('<H', data, 16)[0],
            "link_count": struct.unpack_from('<H', data, 18)[0],
            "first_attribute_offset": struct.unpack_from('<H', data, 20)[0],
            "flags": struct.unpack_from('<H', data, 22)[0],
            "used_size": struct.unpack_from('<I', data, 24)[0],
            "allocated_size": struct.unpack_from('<I', data, 28)[0],
            "base_record": struct.unpack_from('<Q', data, 32)[0],
            "record_offset": offset,
        }

        # Flags interpretation
        flags_val = record["flags"]
        record["in_use"] = bool(flags_val & 0x01)
        record["is_directory"] = bool(flags_val & 0x02)

        # Parser les attributs
        attr_offset = record["first_attribute_offset"]
        attributes = []
        while attr_offset < min(record["used_size"], 1024) - 4:
            attr_type = struct.unpack_from('<I', data, attr_offset)[0]
            if attr_type == 0xFFFFFFFF:
                break
            attr_len = struct.unpack_from('<I', data, attr_offset + 4)[0]
            if attr_len == 0 or attr_len > 1024:
                break

            attr_info = {
                "type": attr_type,
                "type_name": _MFT_ATTR_NAMES.get(attr_type, f"Unknown(0x{attr_type:X})"),
                "length": attr_len,
                "offset": attr_offset,
            }

            # $STANDARD_INFORMATION (0x10)
            if attr_type == 0x10 and attr_len >= 72:
                resident = data[attr_offset + 8]
                if resident == 0:  # Resident
                    content_offset = struct.unpack_from('<H', data, attr_offset + 20)[0]
                    si_start = attr_offset + content_offset
                    if si_start + 32 <= len(data):
                        created = struct.unpack_from('<Q', data, si_start)[0]
                        modified = struct.unpack_from('<Q', data, si_start + 8)[0]
                        mft_modified = struct.unpack_from('<Q', data, si_start + 16)[0]
                        accessed = struct.unpack_from('<Q', data, si_start + 24)[0]
                        record["timestamps"] = {
                            "created": _windows_filetime_to_dt(created),
                            "modified": _windows_filetime_to_dt(modified),
                            "mft_modified": _windows_filetime_to_dt(mft_modified),
                            "accessed": _windows_filetime_to_dt(accessed),
                        }

            # $FILE_NAME (0x30)
            if attr_type == 0x30:
                resident = data[attr_offset + 8]
                if resident == 0:
                    content_offset = struct.unpack_from('<H', data, attr_offset + 20)[0]
                    fn_start = attr_offset + content_offset
                    if fn_start + 66 <= len(data):
                        name_len = data[fn_start + 64]
                        name_ns = data[fn_start + 65]
                        name_start = fn_start + 66
                        if name_start + name_len * 2 <= len(data):
                            filename = data[name_start:name_start + name_len * 2].decode(
                                'utf-16-le', 'replace'
                            )
                            record["filename"] = filename
                            record["filename_namespace"] = {0: "POSIX", 1: "Win32",
                                                            2: "DOS", 3: "Win32+DOS"}.get(name_ns, str(name_ns))

            attributes.append(attr_info)
            attr_offset += attr_len

        record["attributes"] = attributes
        return record
    except (struct.error, IndexError) as exc:
        log.debug("Erreur parsing MFT record @ offset %d : %s", offset, exc)
        return None


_MFT_ATTR_NAMES = {
    0x10: "$STANDARD_INFORMATION",
    0x20: "$ATTRIBUTE_LIST",
    0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID",
    0x50: "$SECURITY_DESCRIPTOR",
    0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION",
    0x80: "$DATA",
    0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION",
    0xB0: "$BITMAP",
    0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION",
    0xE0: "$EA",
    0x100: "$LOGGED_UTILITY_STREAM",
}


def detect_ads(path: str) -> list[dict]:
    """Detecte les Alternate Data Streams NTFS."""
    ads_found = []
    try:
        # Sous Linux, on ne peut pas lire les ADS natifs NTFS
        # Mais on peut scanner un dump MFT pour les attributs $DATA multiples
        if os.path.isfile(path):
            with open(path, "rb") as f:
                data = f.read()

            # Scanner les records MFT
            offset = 0
            while offset < len(data) - 1024:
                if data[offset:offset+4] == b'FILE':
                    record = parse_mft_record(data[offset:offset+1024], offset)
                    if record:
                        data_attrs = [a for a in record.get("attributes", [])
                                     if a["type"] == 0x80]
                        if len(data_attrs) > 1:
                            ads_found.append({
                                "filename": record.get("filename", "?"),
                                "record_offset": offset,
                                "data_streams": len(data_attrs),
                                "detail": f"ADS detecte : {len(data_attrs)} flux $DATA",
                            })
                    offset += 1024
                else:
                    offset += 512
    except Exception as exc:
        log.warning("Erreur detection ADS : %s", exc)
    return ads_found


def parse_ext4_inode(data: bytes, offset: int = 0, inode_size: int = 256) -> dict | None:
    """Parse un inode ext4."""
    if len(data) < offset + 128:
        return None
    try:
        d = data[offset:]
        mode = struct.unpack_from('<H', d, 0)[0]
        uid = struct.unpack_from('<H', d, 2)[0]
        size_lo = struct.unpack_from('<I', d, 4)[0]
        atime = struct.unpack_from('<I', d, 8)[0]
        ctime = struct.unpack_from('<I', d, 12)[0]
        mtime = struct.unpack_from('<I', d, 16)[0]
        dtime = struct.unpack_from('<I', d, 20)[0]
        gid = struct.unpack_from('<H', d, 24)[0]
        links = struct.unpack_from('<H', d, 26)[0]
        blocks = struct.unpack_from('<I', d, 28)[0]
        struct.unpack_from('<I', d, 32)[0]

        # Determiner le type de fichier
        file_type = {
            0o100000: "fichier",
            0o040000: "dossier",
            0o120000: "lien symbolique",
            0o020000: "device char",
            0o060000: "device block",
            0o010000: "pipe",
            0o140000: "socket",
        }.get(mode & 0o170000, "inconnu")

        deleted = dtime > 0

        return {
            "offset": offset,
            "mode": oct(mode),
            "file_type": file_type,
            "uid": uid,
            "gid": gid,
            "size": size_lo,
            "links": links,
            "blocks": blocks,
            "atime": datetime.datetime.fromtimestamp(atime, tz=datetime.timezone.utc).isoformat() if atime else "N/A",
            "ctime": datetime.datetime.fromtimestamp(ctime, tz=datetime.timezone.utc).isoformat() if ctime else "N/A",
            "mtime": datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc).isoformat() if mtime else "N/A",
            "dtime": datetime.datetime.fromtimestamp(dtime, tz=datetime.timezone.utc).isoformat() if dtime else "N/A",
            "deleted": deleted,
        }
    except (struct.error, IndexError):
        return None


class DiskAnalyzer(BaseAnalyzer):
    """Analyse forensique de disque - MFT NTFS, ADS, ext4 inodes."""
    name = "disk"
    supported_extensions = ('.raw', '.dd', '.img', '.001', '.E01', '.mft')

    def analyze(self, path: str) -> FindingModel | None:
        try:
            file_size = os.path.getsize(path)
            max_read = min(file_size, 50 * 1024 * 1024)

            with open(path, "rb") as f:
                data = f.read(max_read)

            meta: dict = {
                "Fichier": os.path.basename(path),
                "Taille": f"{file_size:,} octets",
                "Taille analysee": f"{max_read:,} octets",
            }
            extra: dict = {}

            # Detection MFT
            mft_records = []
            offset = 0
            while offset <= len(data) - 1024:
                if data[offset:offset+4] == b'FILE':
                    record = parse_mft_record(data[offset:offset+1024], offset)
                    if record:
                        mft_records.append(record)
                    offset += 1024
                else:
                    offset += 512

            if mft_records:
                meta["Records MFT trouves"] = str(len(mft_records))
                deleted = [r for r in mft_records if not r.get("in_use")]
                meta["Fichiers supprimes (MFT)"] = str(len(deleted))
                extra["mft_records"] = mft_records[:200]
                extra["deleted_files"] = [
                    {"filename": r.get("filename", "?"),
                     "timestamps": r.get("timestamps", {})}
                    for r in deleted[:50]
                ]

                for i, rec in enumerate(mft_records[:10]):
                    fname = rec.get("filename", "?")
                    status = "SUPPRIME" if not rec.get("in_use") else "actif"
                    meta[f"MFT #{i+1}"] = f"{fname} [{status}]"

            # Detection ADS
            ads = detect_ads(path)
            if ads:
                meta["ADS detectes"] = str(len(ads))
                extra["ads"] = ads

            # Detection ext4
            ext4_inodes = []
            # Chercher le superblock ext4 a l'offset 1024
            if len(data) > 1080 and struct.unpack_from('<H', data, 1080)[0] == 0xEF53:
                meta["Systeme de fichiers"] = "ext4 detecte"
                # Scanner quelques inodes
                inode_table_offset = 2048  # Approximation
                for i in range(min(100, (len(data) - inode_table_offset) // 256)):
                    inode = parse_ext4_inode(data, inode_table_offset + i * 256)
                    if inode and inode.get("links", 0) > 0:
                        ext4_inodes.append(inode)

                deleted_inodes = [n for n in ext4_inodes if n.get("deleted")]
                meta["Inodes ext4 trouves"] = str(len(ext4_inodes))
                meta["Inodes supprimes (ext4)"] = str(len(deleted_inodes))
                extra["ext4_inodes"] = ext4_inodes[:100]

            # Detection NTFS
            if data[:4] == b'\xEB\x52\x90N' or data[:8] == b'\xEB\x52\x90NTFS':
                meta["Systeme de fichiers"] = "NTFS detecte"
            elif data[:2] == b'\xEB\x3C' or data[:2] == b'\xEB\x58':
                meta["Systeme de fichiers"] = "FAT detecte"

            return FindingModel(
                type="disk",
                file=os.path.abspath(path),
                metadata=meta,
                extra=extra,
            )
        except Exception as exc:
            log.error("Erreur disk '%s' : %s", os.path.basename(path), exc)
            return None
