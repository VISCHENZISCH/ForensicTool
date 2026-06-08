"""Analyzer IOC - extraction d'indicateurs de compromission (IPs, URLs, hashes, emails)."""
from __future__ import annotations

import hashlib
import os
import re

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("ioc")

# Patterns IOC
_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)
_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    r'|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
)
_URL = re.compile(
    r'https?://[^\s<>"\')\]}{,]+',
    re.IGNORECASE,
)
_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}'
    r'(?:com|net|org|io|info|biz|co|me|xyz|top|tk|ml|ga|cf|gq|'
    r'ru|cn|de|uk|fr|br|in|au|jp|onion|bit|exit)\b',
    re.IGNORECASE,
)
_EMAIL = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)
_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_BITCOIN = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
_CVE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)

# IPs privees a exclure
_PRIVATE_RANGES = (
    '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
    '172.30.', '172.31.', '192.168.', '127.', '0.0.0.0',
    '255.255.255.255', '169.254.',
)


def extract_iocs(data: str | bytes, include_private_ips: bool = False) -> dict:
    """Extrait tous les IOCs d'un texte ou de donnees binaires."""
    if isinstance(data, bytes):
        text = data.decode('utf-8', 'replace')
    else:
        text = data

    result: dict = {
        "ipv4": [],
        "ipv6": [],
        "urls": [],
        "domains": [],
        "emails": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
        "bitcoin": [],
        "cve": [],
    }

    # IPv4
    for match in _IPV4.finditer(text):
        ip = match.group()
        if not include_private_ips and ip.startswith(_PRIVATE_RANGES):
            continue
        if ip not in result["ipv4"]:
            result["ipv4"].append(ip)

    # IPv6
    for match in _IPV6.finditer(text):
        ip = match.group()
        if ip not in result["ipv6"]:
            result["ipv6"].append(ip)

    # URLs
    for match in _URL.finditer(text):
        url = match.group().rstrip('.,;:)')
        if url not in result["urls"]:
            result["urls"].append(url)

    # Domains
    for match in _DOMAIN.finditer(text):
        domain = match.group().lower()
        if domain not in result["domains"]:
            result["domains"].append(domain)

    # Emails
    for match in _EMAIL.finditer(text):
        email = match.group().lower()
        if email not in result["emails"]:
            result["emails"].append(email)

    # Hashes (filtre les faux positifs via longueur)
    for match in _SHA256.finditer(text):
        h = match.group().lower()
        if h not in result["sha256"]:
            result["sha256"].append(h)

    # SHA1 (exclure ceux deja matche comme SHA256)
    sha256_set = set(result["sha256"])
    for match in _SHA1.finditer(text):
        h = match.group().lower()
        if h not in result["sha1"] and not any(h in s for s in sha256_set):
            result["sha1"].append(h)

    # MD5 (exclure ceux deja matche comme SHA1/SHA256)
    sha1_set = set(result["sha1"])
    for match in _MD5.finditer(text):
        h = match.group().lower()
        if (h not in result["md5"]
            and not any(h in s for s in sha256_set)
            and not any(h in s for s in sha1_set)):
            result["md5"].append(h)

    # Bitcoin
    for match in _BITCOIN.finditer(text):
        addr = match.group()
        if addr not in result["bitcoin"]:
            result["bitcoin"].append(addr)

    # CVE
    for match in _CVE.finditer(text):
        cve = match.group().upper()
        if cve not in result["cve"]:
            result["cve"].append(cve)

    return result


def compute_file_hashes(path: str) -> dict:
    """Calcule les hashes MD5, SHA1, SHA256 d'un fichier."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


class IOCAnalyzer(BaseAnalyzer):
    """Extraction d'indicateurs de compromission (IOC) depuis des fichiers."""
    name = "ioc"
    supported_extensions = ()

    def can_handle(self, path: str) -> bool:
        return False  # Active uniquement via CLI --ioc

    def analyze(self, path: str) -> FindingModel | None:
        try:
            file_size = os.path.getsize(path)
            max_read = min(file_size, 50 * 1024 * 1024)

            with open(path, "rb") as f:
                data = f.read(max_read)

            # Hashes du fichier
            file_hashes = compute_file_hashes(path)

            # Extraction IOC
            iocs = extract_iocs(data)

            # Comptage
            total_iocs = sum(len(v) for v in iocs.values())

            meta: dict = {
                "Fichier": os.path.basename(path),
                "Taille": f"{file_size:,} octets",
                "MD5": file_hashes["md5"],
                "SHA1": file_hashes["sha1"],
                "SHA256": file_hashes["sha256"],
                "Total IOCs extraits": str(total_iocs),
            }

            for ioc_type, items in iocs.items():
                if items:
                    meta[f"IOC {ioc_type}"] = str(len(items))

            # Apercu des IOCs
            for ioc_type, items in iocs.items():
                for i, item in enumerate(items[:5]):
                    meta[f"{ioc_type} #{i+1}"] = str(item)[:100]

            return FindingModel(
                type="ioc",
                file=os.path.abspath(path),
                metadata=meta,
                extra={
                    "file_hashes": file_hashes,
                    "iocs": iocs,
                    "total_iocs": total_iocs,
                },
            )
        except Exception as exc:
            log.error("Erreur IOC '%s' : %s", os.path.basename(path), exc)
            return None
