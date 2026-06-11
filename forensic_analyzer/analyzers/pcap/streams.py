from collections import defaultdict
try:
    from scapy.all import IP, TCP, Raw
except ImportError:
    pass

def rebuild_tcp_streams(packets) -> dict[str, bytes]:
    streams: dict[str, list[tuple[int, bytes]]] = defaultdict(list)
    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw): continue
        ip = pkt[IP] if pkt.haslayer(IP) else None
        if not ip: continue
        tcp = pkt[TCP]
        src, dst = f"{ip.src}:{tcp.sport}", f"{ip.dst}:{tcp.dport}"
        stream_key = tuple(sorted([src, dst]))
        stream_id = f"{stream_key[0]} <-> {stream_key[1]}"
        seq = tcp.seq if hasattr(tcp, 'seq') else 0
        streams[stream_id].append((seq, bytes(pkt[Raw].load)))
    result = {}
    for stream_id, segments in streams.items():
        segments.sort(key=lambda x: x[0])
        result[stream_id] = b"".join(data for _, data in segments)
    return result

def extract_files_from_streams(streams: dict[str, bytes]) -> list[dict]:
    from forensic_analyzer.analyzers.carving import scan_magic_bytes
    extracted = []
    for stream_id, data in streams.items():
        hits = scan_magic_bytes(data)
        for hit in hits[:10]:
            extracted.append({"stream": stream_id, "type": hit["extension"], "description": hit["description"], "offset_in_stream": hit["offset"]})
    return extracted

def extract_http_user_agents(streams: dict[str, bytes]) -> list[dict]:
    import re
    uas = []
    seen = set()
    for stream_id, data in streams.items():
        if b"User-Agent:" in data:
            for match in re.finditer(b"User-Agent: (.*?)\r\n", data):
                ua_b = match.group(1)
                try:
                    ua = ua_b.decode('utf-8', 'ignore').strip()
                    if ua not in seen:
                        seen.add(ua)
                        uas.append({"stream": stream_id, "user_agent": ua})
                except:
                    pass
    return uas

def extract_pe_from_streams(streams: dict[str, bytes]) -> list[bytes]:
    pe_files = []
    for stream_id, data in streams.items():
        # Recherche basique de MZ et PE\0\0
        idx = 0
        while True:
            pos = data.find(b'MZ', idx)
            if pos == -1:
                break
            pe_pos = data.find(b'PE\0\0', pos, pos + 1024)
            if pe_pos != -1:
                # On extrait tout jusqu'a la fin du stream ou un marqueur evident (simplifie)
                # En vrai carving, on lirait les headers PE, mais ici on dump le reste du stream
                pe_data = data[pos:]
                if len(pe_data) > 1024:
                    pe_files.append(pe_data)
                break # 1 PE max par stream par simplicite
            idx = pos + 2
    return pe_files

def extract_payload_delivery(streams: dict[str, bytes]) -> list[dict]:
    """Analyse heuristique pour detecter les telechargements de fichiers executables (Payload Delivery)."""
    deliveries = []
    for stream_id, data in streams.items():
        if b"HTTP/1." in data and b"\r\n\r\n" in data:
            parts = data.split(b"\r\n\r\n", 1)
            if len(parts) == 2:
                headers = parts[0].lower()
                body = parts[1]
                is_pe = body.startswith(b"MZ")
                is_download = b"application/x-msdownload" in headers or b"application/octet-stream" in headers
                if (is_pe or is_download) and len(body) > 10000:
                    ips = stream_id.replace(" <-> ", ":").split(":")
                    if len(ips) == 4:
                        ip1, port1, ip2, port2 = ips
                        src_ip = ip1 if port1 in ("80", "8080", "443", "4444") else ip2
                        deliveries.append({
                            "stream": stream_id,
                            "source_ip": src_ip,
                            "size_bytes": len(body),
                            "type": "PE Executable" if is_pe else "Fichier Binaire"
                        })
    return deliveries


def extract_http_exfiltration(streams: dict[str, bytes]) -> list[dict]:
    """Parse le trafic HTTP POST/GET pour extraire les donnees exfiltrees (mots de passe, parametres C2)."""
    import urllib.parse
    exfil_data = []
    
    for stream_id, data in streams.items():
        try:
            # Recherche de requetes POST
            if b"POST " in data:
                parts = data.split(b"\r\n\r\n")
                if len(parts) > 1:
                    headers = parts[0]
                    body = parts[1].split(b"HTTP/1.")[0] # Prendre juste le body de la requete
                    if len(body) > 0 and len(body) < 1000:
                        body_str = body.decode('utf-8', 'ignore').strip()
                        # Si le corps ressemble a des donnees de formulaire (x-www-form-urlencoded)
                        if b"application/x-www-form-urlencoded" in headers:
                            parsed = urllib.parse.parse_qs(body_str)
                            exfil_data.append({"stream": stream_id, "method": "POST", "payload": parsed})
                        elif b"application/json" in headers or body_str.startswith("{"):
                            exfil_data.append({"stream": stream_id, "method": "POST JSON", "payload": body_str[:200]})
                        else:
                            exfil_data.append({"stream": stream_id, "method": "POST RAW", "payload": body_str[:200]})
                            
            # Recherche de parametres suspects dans les GET (Base64, longs hex)
            if b"GET " in data:
                first_line = data.split(b"\r\n")[0]
                url = first_line.split(b" ")[1] if len(first_line.split(b" ")) > 1 else b""
                if b"?" in url:
                    params = url.split(b"?")[1]
                    if len(params) > 50: # URL parameters unusually long
                        exfil_data.append({"stream": stream_id, "method": "GET PARAM", "payload": urllib.parse.unquote(params.decode('utf-8', 'ignore'))})
        except:
            pass
            
    return exfil_data
