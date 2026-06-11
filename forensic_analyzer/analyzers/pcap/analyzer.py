from __future__ import annotations
import os
from collections import Counter
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

from .credentials import extract_credentials
from .streams import rebuild_tcp_streams, extract_files_from_streams, extract_http_user_agents, extract_pe_from_streams, extract_http_exfiltration, extract_payload_delivery
from .dns_exfil import detect_dns_exfiltration
from .beacons import detect_c2_beacons
from .identities import extract_host_identities
from .dns_mapping import extract_dns_mappings
from .ja3_fingerprint import get_ja3_fingerprints
from .timeline import build_attack_timeline
from .tls_decrypt import extract_decrypted_http

log = get_logger("pcap")

try:
    from scapy.all import DNS, IP, TCP, UDP, rdpcap
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

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
            protocols = Counter()
            src_ips = Counter()
            dst_ips = Counter()
            for pkt in packets:
                if pkt.haslayer(IP):
                    src_ips[pkt[IP].src] += 1
                    dst_ips[pkt[IP].dst] += 1
                if pkt.haslayer(TCP): protocols["TCP"] += 1
                if pkt.haslayer(UDP): protocols["UDP"] += 1
                if pkt.haslayer(DNS): protocols["DNS"] += 1

            streams = rebuild_tcp_streams(packets)
            credentials = extract_credentials(streams)
            host_identities = extract_host_identities(packets, streams, path)
            c2_result = detect_c2_beacons(packets)
            dns_exfil = detect_dns_exfiltration(packets)
            extracted_files = extract_files_from_streams(streams)
            dns_res = extract_dns_mappings(packets)
            dns_mappings = dns_res.get("mappings", {})
            suspect_domains = dns_res.get("suspects", [])
            
            user_agents = extract_http_user_agents(streams)
            pe_files = extract_pe_from_streams(streams)
            payload_deliveries = extract_payload_delivery(streams)
            http_exfil = extract_http_exfiltration(streams)
            
            # --- DÉTECTION SCANS (NMAP / SYN FLOOD) ---
            syn_scans = 0
            xmas_scans = 0
            null_scans = 0
            for pkt in packets:
                if pkt.haslayer(TCP):
                    flags = pkt[TCP].flags
                    if flags == 'S': syn_scans += 1
                    elif flags == 'FPU': xmas_scans += 1
                    elif flags == '': null_scans += 1

            scan_alerts = []
            # Heuristique basique : si beaucoup de SYN par rapport au trafic ou volume énorme
            if syn_scans > 1000 and (syn_scans / max(1, total)) > 0.2:
                scan_alerts.append(f"SYN Flood / Port Scan Agressif ({syn_scans} paquets)")
            if xmas_scans > 0:
                scan_alerts.append(f"XMAS Scan (Nmap) détecté ({xmas_scans} paquets)")
            if null_scans > 0:
                scan_alerts.append(f"NULL Scan (Nmap) détecté ({null_scans} paquets)")
                
            # TLS & JA3
            tls_data = get_ja3_fingerprints(packets)
            ja3_fingerprints = tls_data.get("ja3", {})
            tls_snis = tls_data.get("sni", [])
            
            tls_decrypted = []
            sslkeylogfile = os.environ.get("SSLKEYLOGFILE")
            if sslkeylogfile and os.path.exists(sslkeylogfile):
                tls_decrypted = extract_decrypted_http(path, sslkeylogfile)
                
            attack_timeline = build_attack_timeline(packets, suspect_domains, c2_result)
            
            malware_hits = []
            if pe_files:
                import tempfile
                from forensic_analyzer.analyzers.malware.analyzer import MalwareAnalyzer
                mw_analyzer = MalwareAnalyzer()
                for idx, pe_data in enumerate(pe_files[:5]):  # limit to top 5 PEs to avoid taking forever
                    try:
                        fd, tmp_path = tempfile.mkstemp(suffix=".exe")
                        with os.fdopen(fd, 'wb') as f:
                            f.write(pe_data)
                        mw_res = mw_analyzer.analyze(tmp_path)
                        if mw_res:
                            malware_hits.append(mw_res)
                        os.remove(tmp_path)
                    except Exception as e:
                        log.debug(f"Auto-malware error: {e}")

            # Formatage des top IPs avec résolution DNS
            def format_ips(ip_counter):
                result = []
                for ip, count in ip_counter.most_common(5):
                    domain_str = ""
                    if ip in dns_mappings and dns_mappings[ip]:
                        # On prend le premier domaine resolu
                        domain_str = f" [{dns_mappings[ip][0]}]"
                    result.append(f"{ip}{domain_str}({count})")
                return ", ".join(result)

            meta: dict = {
                "Total paquets": str(total),
                "Flux TCP reconstruits": str(len(streams)),
                "Protocoles": ", ".join(f"{k}:{v}" for k, v in protocols.most_common()),
                "IPs source (top 5)": format_ips(src_ips),
                "IPs dest (top 5)": format_ips(dst_ips),
                "Hôtes / Identités": str(len(host_identities)),
                "Credentials trouvees": str(len(credentials)),
                "C2 Beacons detectes": str(len(c2_result["beacons"])),
                "DNS Exfiltration": "OUI" if dns_exfil["detected"] else "NON",
                "DNS Total requetes": str(dns_exfil.get("total_queries", 0)),
                "Fichiers dans flux": str(len(extracted_files)),
            }

            for i, cred in enumerate(credentials[:5]):
                meta[f"Cred #{i+1}"] = f"[{cred['protocol']}] {cred.get('username', '?')}:{cred.get('password', '?')}"
            for i, beacon in enumerate(c2_result["beacons"][:3]):
                meta[f"Beacon #{i+1}"] = beacon["detail"]

            if suspect_domains:
                meta["Alerte Phishing/Typosquatting"] = f"{len(suspect_domains)} domaine(s) suspect(s) !"

            # Add User-Agents
            if user_agents:
                suspect_uas = [ua for ua in user_agents if "Windows NT" not in ua["user_agent"] and "Macintosh" not in ua["user_agent"]]
                meta["User-Agents suspects"] = str(len(suspect_uas))
                
            # Add Auto-Malware Pipeline hits
            if malware_hits:
                meta["Malwares extraits"] = f"{len(malware_hits)} analysés"
                
            if payload_deliveries:
                for idx, pd in enumerate(payload_deliveries[:3]):
                    sz_mb = round(pd['size_bytes'] / 1024 / 1024, 2)
                    meta[f"Payload Delivery #{idx+1}"] = f"IP: {pd['source_ip']} ({pd['type']}, {sz_mb} Mo)"
                
            if scan_alerts:
                meta["Alerte Scans / Reconnaissance"] = " | ".join(scan_alerts)
                
            if ja3_fingerprints:
                meta["Empreintes JA3 (TLS)"] = str(len(set(ja3_fingerprints.values())))
                
            if tls_snis:
                meta["TLS SNI (Serveurs ciblés)"] = " | ".join(list(set(tls_snis))[:5])
                
            if http_exfil:
                meta["Données exfiltrées (HTTP)"] = str(len(http_exfil))
                
            if tls_decrypted:
                meta["Déchiffrement TLS"] = f"SUCCÈS ({len(tls_decrypted)} requêtes HTTP extraites)"

            return FindingModel(
                type="pcap",
                file=os.path.abspath(path),
                metadata=meta,
                extra={
                    "streams_count": len(streams),
                    "host_identities": host_identities,
                    "credentials": credentials,
                    "c2_beacons": c2_result,
                    "dns_exfiltration": dns_exfil,
                    "extracted_files": extracted_files,
                    "protocol_stats": dict(protocols),
                    "top_src_ips": dict(src_ips.most_common(10)),
                    "top_dst_ips": dict(dst_ips.most_common(10)),
                    "typosquatting": suspect_domains,
                    "user_agents": user_agents,
                    "auto_malware": [hit.metadata for hit in malware_hits],
                    "ja3_fingerprints": ja3_fingerprints,
                    "timeline": attack_timeline,
                    "http_exfiltration": http_exfil,
                    "tls_decrypted": tls_decrypted
                },
            )
        except Exception as exc:
            log.error("Erreur PCAP '%s' : %s", os.path.basename(path), exc)
            return None
