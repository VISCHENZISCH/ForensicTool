import datetime

from forensic_analyzer.utils.logger import get_logger

log = get_logger("pcap")

try:
    from scapy.all import DNS, TCP, UDP, IP
except ImportError:
    pass

def build_attack_timeline(packets, suspect_domains, c2_beacons) -> list[dict]:
    timeline = []
    seen_streams = set()
    seen_http_reqs = set()

    suspect_dns = {s['domaine'] for s in suspect_domains} if suspect_domains else set()
    # Couple IP/port de la balise : une réponse du serveur vers un port client de cette IP n'est pas du C2
    c2_endpoints = set()
    for beacon in c2_beacons.get('beacons', []):
        dst = beacon.get('connection', '').split(' -> ')[-1]
        if ':' in dst:
            ip, port = dst.rsplit(':', 1)
            if port.isdigit():
                c2_endpoints.add((ip, int(port)))

    for pkt in packets:
        try:
            ts = datetime.datetime.fromtimestamp(float(pkt.time), datetime.timezone.utc).isoformat()

            # 1. Requêtes DNS
            if pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt[UDP].dport == 53:
                dns = pkt[DNS]
                if dns.qdcount > 0:
                    qname = dns.qd[0].qname.decode('utf-8', 'ignore').rstrip('.')
                    if qname in suspect_dns:
                        timeline.append({"time": ts, "type": "RECON (DNS)", "desc": f"Requête DNS vers domaine suspect : {qname}"})
                    elif not any(qname.endswith(b) for b in ("in-addr.arpa", "ip6.arpa", "local")):
                        if len(timeline) < 15 and not any(qname in e.get("desc", "") for e in timeline):
                            timeline.append({"time": ts, "type": "DNS QUERY", "desc": f"Résolution DNS : {qname}"})

            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                ip = pkt[IP]
                tcp = pkt[TCP]
                flags = str(tcp.flags)
                dst = ip.dst
                stream_id = f"{ip.src} -> {ip.dst}:{tcp.dport}"

                if (dst, tcp.dport) in c2_endpoints and not any(
                        e["desc"].endswith(f"{dst}:{tcp.dport}") for e in timeline if e["type"] == "C2 CONNECT"):
                    timeline.append({"time": ts, "type": "C2 CONNECT", "desc": f"Début de la communication C2 vers {dst}:{tcp.dport}"})
                    seen_streams.add(stream_id)

                elif 'S' in flags and 'A' not in flags and stream_id not in seen_streams:
                    seen_streams.add(stream_id)
                    if tcp.dport in (4444, 5555, 1337, 31337, 8888, 6667, 445, 139):
                        timeline.append({"time": ts, "type": "TCP CONNECT (SUSPECT)", "desc": f"Connexion TCP vers port critique {tcp.dport} ({ip.src} -> {ip.dst}:{tcp.dport})"})
                    elif len(seen_streams) <= 40:
                        timeline.append({"time": ts, "type": "TCP CONNECT", "desc": f"Nouvelle connexion TCP {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"})

                if pkt.haslayer("Raw"):
                    payload = bytes(pkt["Raw"].load)
                    if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ")):
                        try:
                            lines = payload.split(b"\r\n")
                            req = lines[0].decode('utf-8', 'ignore')
                            if req not in seen_http_reqs:
                                seen_http_reqs.add(req)
                                if ".exe " in req or ".dll " in req or ".zip " in req:
                                    timeline.append({"time": ts, "type": "PAYLOAD DOWNLOAD", "desc": f"Téléchargement suspect : {req}"})
                                elif any(k in req.lower() for k in ("login", "auth", "x.php", "shell", "eval", "cmd", "admin")):
                                    timeline.append({"time": ts, "type": "HTTP REQUEST (CRITIQUE)", "desc": f"Requête web sensible : {req} ({ip.src} -> {ip.dst})"})
                                elif len(seen_http_reqs) <= 30:
                                    timeline.append({"time": ts, "type": "HTTP REQUEST", "desc": f"{req} ({ip.src} -> {ip.dst})"})
                        except Exception:
                            pass
        except Exception as exc:
            log.debug("Paquet ignoré dans la chronologie : %s", exc)

    # Trier et limiter la chronologie
    timeline.sort(key=lambda x: x["time"])
    return timeline[:100]
