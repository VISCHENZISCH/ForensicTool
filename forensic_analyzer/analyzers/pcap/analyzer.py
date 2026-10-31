from __future__ import annotations
import datetime
import os
from collections import Counter
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel, severity_if_alerts
from forensic_analyzer.utils.logger import get_logger

from .credentials import extract_credentials

# rdpcap charge toute la capture en objets scapy (~10x sa taille en mémoire)
MAX_PCAP_BYTES = int(os.environ.get("FORENSIC_PCAP_MAX_MB", "512")) * 2**20
from .http import analyze_http_attack, extract_http_transactions
from .streams import (
    rebuild_tcp_streams,
    extract_files_from_streams,
    extract_http_user_agents,
    extract_pe_from_streams,
    extract_http_exfiltration,
    extract_http_auth_attempts,
    extract_payload_delivery,
)
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
    heavy = True   # rdpcap charge toute la capture en mémoire : une à la fois
    supported_extensions = ('.pcap', '.pcapng', '.cap')

    def analyze(self, path: str) -> FindingModel | None:
        if not HAS_SCAPY:
            log.error("scapy requis pour l'analyse PCAP - pip install scapy")
            return None
        size = os.path.getsize(path)
        if size > MAX_PCAP_BYTES:
            return FindingModel(
                type="pcap", file=os.path.abspath(path),
                metadata={"[ATTENTION] Non analysé": f"capture de {size / 2**20:.0f} Mo au-delà du plafond de "
                                                     f"{MAX_PCAP_BYTES // 2**20} Mo (FORENSIC_PCAP_MAX_MB) : utiliser "
                                                     "tshark ou Zeek, ou découper avec editcap -c"},
                incomplete=[f"capture trop volumineuse ({size / 2**20:.0f} Mo) pour un chargement en mémoire"])
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
            auth_attempts = extract_http_auth_attempts(streams)
            http_attack = analyze_http_attack(extract_http_transactions(packets))
            attackers = set(http_attack["attackers"])

            # Les mots de passe d'un brute-force ne sont pas des identifiants : seul celui qui
            # a fonctionné l'est (réponse 302 + session), placé en tête
            brute_clients = {b["client"] for b in http_attack["brute_force"]}
            winners = [{"protocol": "HTTP Form (POST) - VALIDE", "host": s["server"], "client": s["client"],
                        "username": s["username"], "password": s["password"], "time": s["time"]}
                       for s in http_attack["successful_logins"]]
            credentials = winners + [c for c in credentials if not (
                c.get("protocol", "").startswith("HTTP Form") and c.get("stream", "").split(" <-> ")[-1].split(":")[0] in brute_clients)]

            # Balises : une requête isolée vers un port de C2 compte (pas seulement les séries périodiques)
            known = {b["connection"] for b in c2_result["beacons"]}
            for b in http_attack["beacons"]:
                conn = f"{b['source']} -> {b['destination']}:{b['port']}"
                if b["outbound"] and conn not in known:
                    c2_result["beacons"].append({"connection": conn, "count": 1, "avg_interval_sec": 0, "jitter_pct": 0,
                                                 "detail": f"Requête sortante vers C2 : {conn} {b['uri']}"})
                    known.add(conn)
            c2_result["detected"] = bool(c2_result["beacons"])

            # --- DÉTECTION SCANS & LATERAL MOVEMENT ---
            syn_scans = 0
            xmas_scans = 0
            null_scans = 0
            syn_velocity: dict[tuple[str, str], list[tuple[float, int]]] = {}
            smb_lateral: list[str] = []

            for pkt in packets:
                if pkt.haslayer(TCP) and pkt.haslayer(IP):
                    ip = pkt[IP]
                    tcp = pkt[TCP]
                    flags = str(tcp.flags)
                    t = float(pkt.time) if hasattr(pkt, 'time') else 0.0

                    if 'S' in flags and 'A' not in flags:
                        syn_scans += 1
                        pair = (ip.src, ip.dst)
                        if pair not in syn_velocity:
                            syn_velocity[pair] = []
                        syn_velocity[pair].append((t, tcp.dport))

                    if flags == 'FPU': xmas_scans += 1
                    elif flags == '': null_scans += 1

                    # Mouvement latéral SMB (ports 445, 139) entre sous-réseaux (/24 différents)
                    if tcp.dport in (445, 139) and ('S' in flags and 'A' not in flags):
                        src_net = ip.src.rsplit('.', 1)[0]
                        dst_net = ip.dst.rsplit('.', 1)[0]
                        if src_net != dst_net and ip.src not in attackers:
                            smb_desc = f"{ip.src} -> {ip.dst}:{tcp.dport}"
                            if smb_desc not in smb_lateral:
                                smb_lateral.append(smb_desc)

            scan_alerts = []
            # Détection de scan par vélocité (>= 5 ports distincts sur la même cible)
            for (src, dst), events in syn_velocity.items():
                distinct_ports = {p for _, p in events}
                if len(distinct_ports) >= 5:
                    times = [t for t, _ in events]
                    duration = max(times) - min(times) if times else 0
                    if duration <= 15 or len(distinct_ports) >= 10:
                        scan_alerts.append(f"Scan SYN détecté : {src} -> {dst} ({len(distinct_ports)} ports en {duration:.1f}s)")

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
            attack_timeline = sorted(attack_timeline + _http_attack_events(http_attack),
                                     key=lambda e: e["time"])
            
            malware_hits = []
            if pe_files:
                import tempfile
                from forensic_analyzer.analyzers.malware.analyzer import MalwareAnalyzer
                mw_analyzer = MalwareAnalyzer()
                for idx, pe_data in enumerate(pe_files[:5]):  # limit to top 5 PEs to avoid taking forever
                    fd, tmp_path = tempfile.mkstemp(suffix=".exe")
                    try:
                        with os.fdopen(fd, 'wb') as f:
                            f.write(pe_data)
                        mw_res = mw_analyzer.analyze(tmp_path)
                        if mw_res:
                            malware_hits.append(mw_res)
                    except Exception as e:
                        log.debug(f"Auto-malware error: {e}")
                    finally:
                        os.remove(tmp_path)

            # Formatage des top IPs avec résolution DNS
            def format_ips(ip_counter):
                result = []
                for ip, count in ip_counter.most_common(5):
                    domain_str = ""
                    if ip in dns_mappings and dns_mappings[ip]:
                        # On prend le premier domaine résolu
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
                "Credentials trouvées": str(len(credentials)),
                "C2 Beacons détectés": str(len(c2_result["beacons"])),
                "DNS Exfiltration": "OUI" if dns_exfil["detected"] else "NON",
                "DNS Total requêtes": str(dns_exfil.get("total_queries", 0)),
                "Signatures de fichiers dans les flux": str(len(extracted_files)),
            }

            for i, cred in enumerate(credentials[:5]):
                meta[f"Cred #{i+1}"] = f"[{cred['protocol']}] {cred.get('username', '?')}:{cred.get('password', '?')}"
            for i, beacon in enumerate(c2_result["beacons"][:3]):
                meta[f"Beacon #{i+1}"] = beacon["detail"]

            if suspect_domains:
                meta["Alerte Phishing/Typosquatting"] = f"{len(suspect_domains)} domaine(s) suspect(s) !"

            for bf in http_attack["brute_force"]:
                outcome = f"RÉUSSI : {bf['winning_credential']}" if bf["succeeded"] else "sans succès"
                meta[f"[ALERTE] Brute-force HTTP {bf['client']}"] = (
                    f"{bf['attempts']} tentatives vers {bf['server']} en {bf['last'] - bf['first']:.0f} s, {outcome}")
            for up in http_attack["uploads"]:
                label = "[ALERTE] Téléversement de script" if up["php"] else "Téléversement"
                meta[f"{label} {up['filename']}"] = f"{up['client']} -> {up['server']}{up['uri']}"
            if http_attack["webshell_commands"]:
                cmds = http_attack["webshell_commands"]
                meta["[ALERTE] Commandes via webshell"] = (f"{len(cmds)} ({cmds[0]['shell']}) : "
                                                          + " ; ".join(c["command"] for c in cmds))
            for ex in http_attack["exfiltration"]:
                size = f"{ex['bytes'] / 1024 / 1024:.1f} Mo" if ex["bytes"] else "réponse non capturée"
                meta[f"[ALERTE] Exfiltration HTTP {ex['uri'].rsplit('/', 1)[-1]}"] = (
                    f"téléchargé par {ex['client']} depuis {ex['server']} ({size})")
            if smb_lateral:
                meta["[ALERTE] Mouvement latéral SMB"] = " | ".join(smb_lateral)

            if http_attack["user_agents"]:
                ranked = http_attack["user_agents"]
                meta["User-Agents (par rôle)"] = " | ".join(f"{u['user_agent']} ({u['verdict']})" for u in ranked[:5])
                meta["User-Agents suspects"] = str(sum(u["verdict"] == "attaquant" for u in ranked))
                
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
                    "auth_attempts": auth_attempts,
                    "smb_lateral": smb_lateral,
                    "http_attack": http_attack,
                    "tls_decrypted": tls_decrypted
                },
                severity=severity_if_alerts(meta, "élevé"),
            )
        except Exception as exc:
            log.error("Erreur PCAP '%s' : %s", os.path.basename(path), exc)
            return None


def _iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()


def _http_attack_events(http_attack: dict) -> list[dict]:
    """Étapes de l'attaque, datées, pour la chronologie (un événement par fait, pas par paquet)."""
    events = []
    for bf in http_attack["brute_force"]:
        events.append({"time": _iso(bf["first"]), "type": "BRUTE-FORCE",
                       "desc": f"Début du brute-force HTTP depuis {bf['client']} ({bf['attempts']} tentatives)"})
    for s in http_attack["successful_logins"]:
        events.append({"time": _iso(s["time"]), "type": "CONNEXION RÉUSSIE",
                       "desc": f"Connexion réussie {s['username']} depuis {s['client']} ({s['uri']})"})
    for up in http_attack["uploads"]:
        events.append({"time": _iso(up["time"]), "type": "TÉLÉVERSEMENT",
                       "desc": f"Téléversement de {up['filename']} par {up['client']}"})
    for c in http_attack["webshell_commands"]:
        events.append({"time": _iso(c["time"]), "type": "WEBSHELL",
                       "desc": f"Commande via {c['shell']} : {c['command']} ({c['client']})"})
    for ex in http_attack["exfiltration"]:
        events.append({"time": _iso(ex["time"]), "type": "EXFILTRATION",
                       "desc": f"Téléchargement de {ex['uri']} par {ex['client']}"})
    for b in http_attack["beacons"]:
        if b["outbound"]:
            events.append({"time": _iso(b["time"]), "type": "C2 BEACON",
                           "desc": f"Requête sortante {b['source']} -> {b['destination']}:{b['port']} {b['uri']}"})
    return events
