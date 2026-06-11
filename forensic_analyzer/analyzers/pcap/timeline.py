import datetime
import math

try:
    from scapy.all import DNS, TCP, UDP, IP
except ImportError:
    pass

def build_attack_timeline(packets, suspect_domains, c2_beacons) -> list[dict]:
    timeline = []
    
    # Fast access sets
    suspect_dns = {s['domaine'] for s in suspect_domains}
    c2_ips = set()
    for beacon in c2_beacons.get('beacons', []):
        ip = beacon['detail'].split('(')[0].split(' -> ')[-1].strip()
        c2_ips.add(ip)
    
    # Extraction packets
    for pkt in packets:
        try:
            ts = datetime.datetime.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S')
            
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
                dport = pkt[TCP].dport
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
                        except:
                            pass
        except Exception as exc:
            pass  # TODO: log.debug(exc)
            pass
            
    # Sort and deduplicate timeline
    timeline.sort(key=lambda x: x["time"])
    
    # Keep only the first 20 events to avoid flooding
    return timeline[:20]
