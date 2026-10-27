"""Analyzer disque - partitions, systemes de fichiers, MFT NTFS, ADS, ext via The Sleuth Kit."""
from __future__ import annotations

import datetime
import mmap
import os
import shutil
import struct
import subprocess

from forensic_analyzer.analyzers.disk import layout, tsk_image
from forensic_analyzer.analyzers.linux import bodyfile as bf
from forensic_analyzer.core import mitre
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
        
        # Slack space (Espace vide a la fin de l'enregistrement MFT)
        record["mft_slack_space"] = max(0, record["allocated_size"] - record["used_size"])

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
    """Detecte les Alternate Data Streams NTFS via parsing de dump."""
    ads_found = []
    try:
        if os.path.isfile(path):
            with open(path, "rb") as f:
                try:
                    data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                except ValueError:
                    return ads_found # Fichier vide

            # Scanner les records MFT (Optimisé via C-level mmap.find)
            offset = 0
            while True:
                offset = data.find(b'FILE', offset)
                if offset == -1 or offset > len(data) - 1024:
                    break
                    
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
                
            if isinstance(data, mmap.mmap):
                data.close()
    except Exception as exc:
        log.warning("Erreur detection ADS : %s", exc)
    return ads_found


def _scan_windows_artifacts(path: str, data, meta: dict, extra: dict) -> None:
    """Heuristiques NTFS : records MFT, journaux, corbeille, LNK, Prefetch, VSS, ADS."""
    # LNK, Prefetch, VSS carving (signatures)
    lnk_count = data.find(b'\x4c\x00\x00\x00\x01\x14\x02\x00') != -1 # Simplification pour eviter scan complet lourd si mmap
    if lnk_count:
        meta["Raccourcis LNK"] = "Détectés"
        
    prefetch_count = data.find(b'SCCA') != -1 or data.find(b'MAM\x04') != -1
    if prefetch_count:
        meta["Fichiers Prefetch"] = "Détectés"
        
    vss_count = data.find(b'\x38\xe2\x76\x16\x96\x65\x5f\x41') != -1
    if vss_count:
        meta["Shadow Copies (VSS)"] = "DÉTECTÉ"

    # Detection MFT (O(N) optimisé en C)
    mft_records = []
    usnjrnl_found = False
    logfile_found = False
    recycle_bin_items = 0
    total_mft_slack = 0
    
    offset = 0
    while True:
        offset = data.find(b'FILE', offset)
        if offset == -1 or offset > len(data) - 1024:
            break
            
        record = parse_mft_record(data[offset:offset+1024], offset)
        if record:
            mft_records.append(record)
            total_mft_slack += record.get("mft_slack_space", 0)
            fname = record.get("filename", "")
            if "$UsnJrnl" in fname: usnjrnl_found = True
            if "$LogFile" in fname: logfile_found = True
            if fname.startswith("$I") and len(fname) == 8: recycle_bin_items += 1
            
        offset += 1024

    if mft_records:
        meta["Records MFT trouves"] = str(len(mft_records))
        meta["Slack Space (MFT)"] = f"{total_mft_slack:,} octets (potentiel data cachee)"
        
        if usnjrnl_found: meta["Journal $UsnJrnl"] = "PRÉSENT"
        if logfile_found: meta["Journal $LogFile"] = "PRÉSENT"
        if recycle_bin_items > 0: meta["Fichiers Corbeille ($I)"] = str(recycle_bin_items)
        
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



def _report_file_anomalies(entries: list, meta: dict, extra: dict, label: str) -> set[str]:
    """Fichiers systeme hors root et fichiers caches ; retourne les techniques ATT&CK associees."""
    techniques: set[str] = set()
    for title, found in (("Fichiers systeme hors root", bf.ownership_anomalies(entries)),
                         ("Fichiers caches (systeme / temporaires)", bf.hidden_entries(entries))):
        if found:
            meta[f"[ALERTE] {label} : {title}"] = ", ".join(f"{e.path} (uid {e.uid})" for e in found[:15])
            extra.setdefault("file_anomalies", {})[title] = [
                {"path": e.path, "uid": e.uid, "mode": e.mode, "created": bf.utc(e.crtime),
                 "modified": bf.utc(e.mtime)} for e in found]
            if title.startswith("Fichiers caches"):
                techniques.add("T1564.001")
    return techniques


def _scan_ext_partition(path: str, start_sector: int, meta: dict, extra: dict, label: str) -> set[str]:
    """Repli sans pytsk3 : bodyfile TSK en memoire via la commande fls."""
    fls = shutil.which("fls")
    command = f"fls -r -m / -o {start_sector} '{path}'"
    if not fls:
        meta[f"{label} : bodyfile"] = f"The Sleuth Kit absent ; a generer avec : {command}"
        return set()
    try:
        proc = subprocess.run([fls, "-r", "-m", "/", "-o", str(start_sector), path],
                              capture_output=True, text=True, errors="replace", timeout=600)
    except subprocess.TimeoutExpired:
        log.warning("fls trop long sur '%s'", path)
        return set()
    if proc.returncode != 0:
        log.warning("fls a echoue (offset %s) : %s", start_sector, proc.stderr.strip()[:200])
        return set()

    entries = bf.parse_bodyfile_lines(proc.stdout.splitlines())
    meta[f"{label} : entrees (fls)"] = f"{len(entries)} dont {sum(e.deleted for e in entries)} supprimees"
    meta[f"{label} : analyse complete"] = (
        f"installer pytsk3, ou : {command} > bodyfile.txt ; tsk_recover -a -o {start_sector} '{path}' ./root ; "
        "puis --linux ./root --bodyfile bodyfile.txt")
    return _report_file_anomalies(entries, meta, extra, label)


def _analyze_extracted(local_path: str, origin: str) -> list[FindingModel]:
    """Passe un fichier extrait de l'image dans les analyzers du scan (hors disque/memoire)."""
    from forensic_analyzer.core.scanner import default_registry

    results = []
    for analyzer in default_registry().get_all_for(local_path):
        if analyzer.name in ("disk", "memory"):
            continue
        try:
            res = analyzer.analyze(local_path)
        except Exception as exc:
            log.warning("Erreur %s sur '%s' : %s", analyzer.name, origin, exc)
            continue
        if res is not None:
            res.metadata["Origine (image)"] = origin
            results.append(res)
    return results


class DiskAnalyzer(BaseAnalyzer):
    """Analyse forensique de disque - partitions, systemes de fichiers, MFT NTFS, ext via TSK."""
    name = "disk"
    supported_extensions = ('.raw', '.dd', '.img', '.001', '.E01', '.mft')

    def __init__(self, workdir: str | None = None) -> None:
        # Dossier des artefacts extraits : jamais dans le dossier des preuves
        self.workdir = workdir or os.path.join("export", "extractions")

    def can_handle(self, path: str) -> bool:
        # .raw est ambigu (dump memoire ou image disque) : on exige une structure de disque
        if path.lower().endswith(".raw"):
            return layout.is_disk_image(path)
        return super().can_handle(path)

    def analyze(self, path: str) -> FindingModel | None:
        try:
            file_size = os.path.getsize(path)
            meta: dict = {
                "Fichier": os.path.basename(path),
                "Taille": f"{file_size:,} octets",
            }
            extra: dict = {}

            structure = {} if path.lower().endswith((".mft", ".e01")) else layout.describe(path)
            extra["layout"] = structure
            filesystems = []
            if structure.get("scheme"):
                meta["Table de partitions"] = structure["scheme"]
                for p in structure["partitions"]:
                    fs = p["filesystem"] or "inconnu"
                    filesystems.append(fs)
                    meta[f"Partition @{p['start']}"] = (f"{p['type']} - {fs} - "
                                                        f"{p['sectors'] * layout.SECTOR / 2**20:,.0f} Mio")
            elif structure.get("bare_filesystem"):
                filesystems.append(structure["bare_filesystem"])
                meta["Systeme de fichiers"] = structure["bare_filesystem"] + " (sans table de partitions)"

            ext_parts = [p for p in structure.get("partitions", []) if p["filesystem"].startswith("ext")]
            if structure.get("bare_filesystem", "").startswith("ext"):
                ext_parts.append({"start": 0, "superblock": structure["superblock"]})
            for p in ext_parts:
                label = f"ext @{p['start']}"
                sb = p.get("superblock", {})
                if sb:
                    meta[f"{label} : UUID"] = sb["uuid"]
                    meta[f"{label} : derniere ecriture du superbloc"] = sb["last_written"]
                    meta[f"{label} : dernier montage"] = f"{sb['last_mounted']} sur {sb['last_mount_path'] or '?'} ({sb['state']})"

            techniques: set[str] = set()
            nested: list[FindingModel] = []
            deep = tsk_image.HAS_PYTSK3 and not path.lower().endswith((".mft", ".e01"))
            if deep:
                nested = self._deep_analysis(path, meta, extra, techniques)
            else:
                for p in ext_parts:
                    techniques |= _scan_ext_partition(path, p["start"], meta, extra, f"ext @{p['start']}")
            if techniques:
                meta["MITRE ATT&CK"] = mitre.summary(techniques)

            # Heuristiques NTFS brutes : seulement sans lecture TSK du systeme de fichiers
            if not deep and ("NTFS" in filesystems or not filesystems):
                max_read = min(file_size, 200 * 1024 * 1024)  # Scan max 200MB de raw
                meta["Taille analysee (NTFS)"] = f"{max_read:,} octets"
                with open(path, "rb") as f:
                    try:
                        data = mmap.mmap(f.fileno(), max_read, access=mmap.ACCESS_READ)
                    except ValueError:
                        data = f.read(max_read)
                _scan_windows_artifacts(path, data, meta, extra)
                if isinstance(data, mmap.mmap):
                    data.close()

            finding = FindingModel(
                type="disk",
                file=os.path.abspath(path),
                metadata=meta,
                extra=extra,
            )
            return [finding, *nested] if nested else finding
        except Exception as exc:
            log.error("Erreur disk '%s' : %s", os.path.basename(path), exc)
            return None

    def _deep_analysis(self, path: str, meta: dict, extra: dict, techniques: set[str]) -> list[FindingModel]:
        """Lecture pytsk3 : metadonnees, triage des artefacts, puis analyses Linux / Windows / binaires."""
        from forensic_analyzer.analyzers.linux import LinuxArtifactsAnalyzer
        from forensic_analyzer.core.scanner import auto_scan, default_registry

        evidence_dir = os.path.dirname(os.path.abspath(path))
        workdir = os.path.abspath(os.path.join(self.workdir, os.path.basename(path)))
        if workdir == evidence_dir or workdir.startswith(evidence_dir + os.sep):
            log.warning("Dossier d'extraction dans le dossier des preuves : extraction annulee (%s)", workdir)
            return []

        nested: list[FindingModel] = []
        for fs in tsk_image.open_filesystems(path):
            if fs.family == "other":
                continue
            label = f"{fs.family} @{fs.offset}"
            entries = fs.walk()
            meta[f"{label} : entrees"] = f"{len(entries)} dont {sum(e.deleted for e in entries)} supprimees"
            techniques |= _report_file_anomalies(entries, meta, extra, label)

            # Fichiers suspects a extraire en plus du profil de triage
            suspects = {e.path for e in bf.ownership_anomalies(entries) + bf.hidden_entries(entries)}
            dest = os.path.join(workdir, f"{fs.family}_{fs.offset}")
            extracted = fs.triage(entries, dest, extra_paths=suspects)
            meta[f"{label} : artefacts extraits"] = f"{len(extracted)} fichiers dans {dest}"

            if fs.family == "linux":
                res = LinuxArtifactsAnalyzer().analyze(dest, entries=entries, file_hasher=fs.md5)
                if res:
                    res.metadata["Origine (image)"] = f"{os.path.basename(path)} {label}"
                    nested.append(res)
                    for unit in res.extra.get("systemd", {}).get("units", []):
                        if unit["suspicious"] and unit["binary"]:
                            suspects.add(unit["binary"])
                            fs.extract(unit["binary"], dest)
                for suspect in sorted(suspects):
                    local = tsk_image.local_path(dest, suspect)
                    if local and os.path.isfile(local):
                        nested.extend(_analyze_extracted(local, f"{os.path.basename(path)}:{suspect}"))
            else:
                report = auto_scan(dest, default_registry())
                for res in report.findings:
                    rel = os.path.relpath(res.file, dest) if res.file.startswith(dest) else res.file
                    res.metadata["Origine (image)"] = f"{os.path.basename(path)}:/{rel}"
                nested.extend(report.findings)
        return nested
