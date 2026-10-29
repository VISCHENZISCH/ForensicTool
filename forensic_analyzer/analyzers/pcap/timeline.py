import datetime

from forensic_analyzer.utils.logger import get_logger

log = get_logger("pcap")

try:
    from scapy.all import DNS, TCP, UDP, IP
except ImportError:
    pass

def build_attack_timeline(packets, suspect_domains, c2_beacons) -> list[dict]:
    timeline = []
    
    suspect_dns = {s['domaine'] for s in suspect_domains}
    c2_ips = set()
    for beacon in c2_beacons.get('beacons', []):
        # "10.0.0.5 -> 185.220.101.42:443"
        dst = beacon.get('connection', '').split(' -> ')[-1]
        if dst:
            c2_ips.add(dst.rsplit(':', 1)[0])
    
    for pkt in packets:
        try:
            ts = datetime.datetime.fromtimestamp(float(pkt.time), datetime.timezone.utc).isoformat()
            
            # 1. DNS Suspect
            if pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt[UDP].dport == 53:
                dns = pkt[DNS]
                if dns.qdcount > 0:
                    qname = dns.qd[0].qname.decode('utf-8', 'ignore').rstrip('.')
                    if qname in suspect_dns:
                        timeline.append({"time": ts, "type": "RECON (DNS)", "desc": f"Requête vers le domaine suspect: {qname}"})
                        
            # 2. HTTP Downloads / Beacons Start
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                dst = pkt[IP].dst
                if dst in c2_ips:
                    # We only log the first packet per C2 to avoid spam
                    if not any(e["desc"].endswith(dst) for e in timeline if e["type"] == "C2 CONNECT"):
                        timeline.append({"time": ts, "type": "C2 CONNECT", "desc": f"Début de la communication C2 vers {dst}"})
                        
                # Raw HTTP GET (Download / Recon)
                if pkt.haslayer("Raw"):
                    payload = bytes(pkt["Raw"].load)
                    if payload.startswith(b"GET ") or payload.startswith(b"POST "):
                        try:
                            lines = payload.split(b"\r\n")
                            req = lines[0].decode('utf-8', 'ignore')
                            if ".exe " in req or ".dll " in req or ".zip " in req:
                                timeline.append({"time": ts, "type": "PAYLOAD DOWNLOAD", "desc": f"Téléchargement suspect: {req}"})
                            if "ip-api" in payload.decode('utf-8', 'ignore') or "NCSI" in payload.decode('utf-8', 'ignore'):
                                if not any("GeoIP" in e["desc"] for e in timeline):
                                    timeline.append({"time": ts, "type": "RECON (GEOIP)", "desc": "Requête de géolocalisation ou vérification de connectivité"})
                        except Exception:
                            pass
        except Exception as exc:
            log.debug("Paquet ignore dans la chronologie : %s", exc)

    # Sort and deduplicate timeline
    timeline.sort(key=lambda x: x["time"])
    
    # Keep only the first 20 events to avoid flooding
    return timeline[:20]
