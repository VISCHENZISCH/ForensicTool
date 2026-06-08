"""Analyzer PCAP - reconstruction de flux, extraction credentials, detection C2, DNS exfiltration."""
from __future__ import annotations

import base64
import os
import re
from collections import Counter, defaultdict

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("pcap")

try:
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, rdpcap
    HAS_SCAPY = True
except ImportError:
    try:
        from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, rdpcap
        HAS_SCAPY = True
    except ImportError:
        HAS_SCAPY = False

# Patterns pour extraction de credentials
_FTP_USER = re.compile(rb'USER\s+(\S+)', re.IGNORECASE)
_FTP_PASS = re.compile(rb'PASS\s+(\S+)', re.IGNORECASE)
_HTTP_AUTH = re.compile(rb'Authorization:\s*Basic\s+(\S+)', re.IGNORECASE)
_HTTP_HOST = re.compile(rb'Host:\s*(\S+)', re.IGNORECASE)
_TELNET_LOGIN = re.compile(rb'login:\s*(\S+)', re.IGNORECASE)


def _rebuild_tcp_streams(packets) -> dict[str, bytes]:
    """Reconstruit les flux TCP a partir des paquets."""
    streams: dict[str, list[tuple[int, bytes]]] = defaultdict(list)

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            continue
        ip = pkt[IP] if pkt.haslayer(IP) else None
        if not ip:
            continue

        tcp = pkt[TCP]
        src = f"{ip.src}:{tcp.sport}"
        dst = f"{ip.dst}:{tcp.dport}"
        stream_key = tuple(sorted([src, dst]))
        stream_id = f"{stream_key[0]} <-> {stream_key[1]}"
        seq = tcp.seq if hasattr(tcp, 'seq') else 0
        streams[stream_id].append((seq, bytes(pkt[Raw].load)))

    # Reassembler par sequence
    result = {}
    for stream_id, segments in streams.items():
        segments.sort(key=lambda x: x[0])
        result[stream_id] = b"".join(data for _, data in segments)

    return result


def _extract_credentials(streams: dict[str, bytes]) -> list[dict]:
    """Extrait les credentials depuis les flux reconstruits."""
    creds = []

    for stream_id, data in streams.items():
        # FTP
        users = _FTP_USER.findall(data)
        passwords = _FTP_PASS.findall(data)
        if users:
            for i, user in enumerate(users):
                cred = {
                    "protocol": "FTP",
                    "stream": stream_id,
                    "username": user.decode('utf-8', 'replace'),
                }
                if i < len(passwords):
                    cred["password"] = passwords[i].decode('utf-8', 'replace')
                creds.append(cred)

        # HTTP Basic Auth
        auths = _HTTP_AUTH.findall(data)
        hosts = _HTTP_HOST.findall(data)
        host = hosts[0].decode('utf-8', 'replace') if hosts else "unknown"
        for auth in auths:
            try:
                decoded = base64.b64decode(auth).decode('utf-8', 'replace')
                parts = decoded.split(':', 1)
                creds.append({
                    "protocol": "HTTP Basic",
                    "stream": stream_id,
                    "host": host,
                    "username": parts[0],
                    "password": parts[1] if len(parts) > 1 else "",
                })
            except Exception:
                pass

        # Telnet
        logins = _TELNET_LOGIN.findall(data)
        for login in logins:
            creds.append({
                "protocol": "Telnet",
                "stream": stream_id,
                "username": login.decode('utf-8', 'replace'),
            })

    return creds


def _detect_dns_exfiltration(packets) -> dict:
    """Detecte les tentatives d'exfiltration DNS."""
    dns_queries: list[dict] = []
    query_lengths: list[int] = []
    subdomain_depths: list[int] = []
    unique_domains: set = set()
    txt_queries = 0

    for pkt in packets:
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            continue

        qr = pkt[DNSQR]
        qname = qr.qname.decode('utf-8', 'replace').rstrip('.')
        qtype = qr.qtype

        parts = qname.split('.')
        subdomain_depths.append(len(parts))
        query_lengths.append(len(qname))
        unique_domains.add('.'.join(parts[-2:]) if len(parts) >= 2 else qname)

        if qtype == 16:  # TXT
            txt_queries += 1

        dns_queries.append({
            "query": qname,
            "type": {1: "A", 5: "CNAME", 12: "PTR", 15: "MX",
                     16: "TXT", 28: "AAAA"}.get(qtype, str(qtype)),
        })

    if not dns_queries:
        return {"detected": False, "detail": "Pas de requetes DNS"}

    avg_length = sum(query_lengths) / len(query_lengths)
    avg_depth = sum(subdomain_depths) / len(subdomain_depths)
    long_queries = sum(1 for l in query_lengths if l > 50)
    entropy_queries = sum(1 for q in dns_queries if _has_high_entropy(q["query"]))

    # Heuristiques d'exfiltration
    score = 0
    indicators = []
    if avg_length > 40:
        score += 2
        indicators.append(f"Longueur moyenne elevee ({avg_length:.0f} chars)")
    if long_queries > len(dns_queries) * 0.1:
        score += 2
        indicators.append(f"{long_queries} requetes longues (>50 chars)")
    if avg_depth > 4:
        score += 1
        indicators.append(f"Profondeur moyenne elevee ({avg_depth:.1f} niveaux)")
    if txt_queries > 5:
        score += 2
        indicators.append(f"{txt_queries} requetes TXT")
    if entropy_queries > len(dns_queries) * 0.2:
        score += 3
        indicators.append(f"{entropy_queries} requetes a haute entropie")

    return {
        "detected": score >= 3,
        "score": score,
        "total_queries": len(dns_queries),
        "unique_domains": len(unique_domains),
        "avg_query_length": round(avg_length, 1),
        "avg_subdomain_depth": round(avg_depth, 1),
        "txt_queries": txt_queries,
        "long_queries": long_queries,
        "high_entropy_queries": entropy_queries,
        "indicators": indicators,
        "top_queries": dns_queries[:50],
    }


def _detect_c2_beacons(packets) -> dict:
    """Detecte les patterns de beacon C2 (intervalles reguliers, taille constante)."""
    connections: dict[str, list[float]] = defaultdict(list)

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        if tcp.flags & 0x02:  # SYN
            key = f"{ip.src} -> {ip.dst}:{tcp.dport}"
            connections[key].append(float(pkt.time))

    beacons = []
    for conn, times in connections.items():
        if len(times) < 5:
            continue
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval == 0:
            continue
        variance = sum((i - avg_interval)**2 for i in intervals) / len(intervals)
        stddev = variance ** 0.5
        jitter_pct = (stddev / avg_interval * 100) if avg_interval > 0 else 100

        if jitter_pct < 20 and avg_interval > 1:
            beacons.append({
                "connection": conn,
                "count": len(times),
                "avg_interval_sec": round(avg_interval, 2),
                "jitter_pct": round(jitter_pct, 2),
                "detail": f"Beacon suspect : intervalle ~{avg_interval:.0f}s, jitter {jitter_pct:.0f}%",
            })

    return {
        "detected": len(beacons) > 0,
        "beacons": beacons,
        "total_connections_analyzed": len(connections),
    }


def _extract_files_from_streams(streams: dict[str, bytes]) -> list[dict]:
    """Extrait les fichiers detectes dans les flux reseau."""
    from forensic_analyzer.analyzers.carving_analyzer import scan_magic_bytes
    extracted = []

    for stream_id, data in streams.items():
        hits = scan_magic_bytes(data)
        for hit in hits[:10]:
            extracted.append({
                "stream": stream_id,
                "type": hit["extension"],
                "description": hit["description"],
                "offset_in_stream": hit["offset"],
            })

    return extracted


def _has_high_entropy(s: str) -> bool:
    """Verifie si une chaine a une entropie elevee (> 3.5 bits/char)."""
    import math
    if len(s) < 10:
        return False
    freq = Counter(s)
    n = len(s)
    entropy = -sum((c/n) * math.log2(c/n) for c in freq.values())
    return entropy > 3.5


class PCAPAnalyzer(BaseAnalyzer):
    """Analyse de fichiers PCAP - reconstruction, credentials, C2, DNS exfil."""
    name = "pcap"
    supported_extensions = ('.pcap', '.pcapng', '.cap')

    def analyze(self, path: str) -> FindingModel | None:
        if not HAS_SCAPY:
            log.error("scapy requis pour l'analyse PCAP - pip install scapy")
            return None
        try:
            packets = rdpcap(path)
            total = len(packets)

            # Stats de base
            protocols = Counter()
            src_ips = Counter()
            dst_ips = Counter()
            for pkt in packets:
                if pkt.haslayer(IP):
                    src_ips[pkt[IP].src] += 1
                    dst_ips[pkt[IP].dst] += 1
                if pkt.haslayer(TCP):
                    protocols["TCP"] += 1
                if pkt.haslayer(UDP):
                    protocols["UDP"] += 1
                if pkt.haslayer(DNS):
                    protocols["DNS"] += 1

            # Reconstruction des flux TCP
            streams = _rebuild_tcp_streams(packets)

            # Extraction des credentials
            credentials = _extract_credentials(streams)

            # Detection C2
            c2_result = _detect_c2_beacons(packets)

            # DNS exfiltration
            dns_exfil = _detect_dns_exfiltration(packets)

            # Extraction de fichiers depuis les streams
            extracted_files = _extract_files_from_streams(streams)

            # Metadata plate
            meta: dict = {
                "Total paquets": str(total),
                "Flux TCP reconstruits": str(len(streams)),
                "Protocoles": ", ".join(f"{k}:{v}" for k, v in protocols.most_common()),
                "IPs source (top 5)": ", ".join(f"{ip}({c})" for ip, c in src_ips.most_common(5)),
                "IPs dest (top 5)": ", ".join(f"{ip}({c})" for ip, c in dst_ips.most_common(5)),
                "Credentials trouvees": str(len(credentials)),
                "C2 Beacons detectes": str(len(c2_result["beacons"])),
                "DNS Exfiltration": "OUI" if dns_exfil["detected"] else "NON",
                "DNS Total requetes": str(dns_exfil.get("total_queries", 0)),
                "Fichiers dans flux": str(len(extracted_files)),
            }

            for i, cred in enumerate(credentials[:5]):
                meta[f"Cred #{i+1}"] = (
                    f"[{cred['protocol']}] {cred.get('username', '?')}"
                    f":{cred.get('password', '?')}"
                )

            for i, beacon in enumerate(c2_result["beacons"][:3]):
                meta[f"Beacon #{i+1}"] = beacon["detail"]

            return FindingModel(
                type="pcap",
                file=os.path.abspath(path),
                metadata=meta,
                extra={
                    "streams_count": len(streams),
                    "credentials": credentials,
                    "c2_beacons": c2_result,
                    "dns_exfiltration": dns_exfil,
                    "extracted_files": extracted_files,
                    "protocol_stats": dict(protocols),
                    "top_src_ips": dict(src_ips.most_common(10)),
                    "top_dst_ips": dict(dst_ips.most_common(10)),
                },
            )
        except Exception as exc:
            log.error("Erreur PCAP '%s' : %s", os.path.basename(path), exc)
            return None
