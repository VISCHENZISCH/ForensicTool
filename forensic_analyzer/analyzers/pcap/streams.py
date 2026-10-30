from collections import defaultdict

try:
    from scapy.all import IP, TCP, Raw
except ImportError:
    pass

from forensic_analyzer.utils.logger import get_logger

log = get_logger("pcap")

def rebuild_tcp_streams(packets) -> dict[str, bytes]:
    sessions: dict[tuple[str, str], int] = defaultdict(int)
    streams: dict[str, list[tuple[int, bytes]]] = defaultdict(list)
    active_session: dict[tuple[str, str], int] = {}

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue
        ip = pkt[IP] if pkt.haslayer(IP) else None
        if not ip:
            continue
        tcp = pkt[TCP]
        src, dst = f"{ip.src}:{tcp.sport}", f"{ip.dst}:{tcp.dport}"
        pair_key = tuple(sorted([src, dst]))

        flags = tcp.flags if hasattr(tcp, 'flags') else 0
        if isinstance(flags, int):
            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)
        else:
            s_flags = str(flags)
            is_syn = 'S' in s_flags
            is_ack = 'A' in s_flags

        if is_syn and not is_ack:
            sessions[pair_key] += 1
            active_session[pair_key] = sessions[pair_key]
        elif pair_key not in active_session:
            sessions[pair_key] = 1
            active_session[pair_key] = 1

        if not pkt.haslayer(Raw):
            continue

        sess_idx = active_session[pair_key]
        stream_id = f"{pair_key[0]} <-> {pair_key[1]}" if sess_idx == 1 else f"{pair_key[0]} <-> {pair_key[1]}#{sess_idx}"
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
                except Exception:
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
                # On extrait tout jusqu'à la fin du stream ou un marqueur évident (simplifié)
                # En vrai carving, on lirait les headers PE, mais ici on dump le reste du stream
                pe_data = data[pos:]
                if len(pe_data) > 1024:
                    pe_files.append(pe_data)
                break # 1 PE max par stream par simplicité
            idx = pos + 2
    return pe_files

def extract_payload_delivery(streams: dict[str, bytes]) -> list[dict]:
    """Analyse heuristique pour détecter les téléchargements de fichiers exécutables (Payload Delivery)."""
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
                        ip1, port1, ip2, _port2 = ips
                        src_ip = ip1 if port1 in ("80", "8080", "443", "4444") else ip2
                        deliveries.append({
                            "stream": stream_id,
                            "source_ip": src_ip,
                            "size_bytes": len(body),
                            "type": "PE Executable" if is_pe else "Fichier Binaire"
                        })
    return deliveries


def extract_http_auth_attempts(streams: dict[str, bytes]) -> list[dict]:
    """Extrait les tentatives de connexion HTTP (wp-login.php, formulaires de login)."""
    import urllib.parse
    auth_attempts = []
    for stream_id, data in streams.items():
        if b"POST " not in data:
            continue
        try:
            first_line = data.split(b"\r\n")[0]
            url = first_line.split(b" ")[1].decode('utf-8', 'ignore') if len(first_line.split(b" ")) > 1 else ""
            if any(k in url.lower() for k in ("wp-login.php", "login", "auth", "signin", "xmlrpc.php")):
                parts = data.split(b"\r\n\r\n", 1)
                body = parts[1].split(b"HTTP/1.")[0] if len(parts) > 1 else b""
                body_str = body.decode('utf-8', 'ignore').strip()
                payload = urllib.parse.parse_qs(body_str) if b"application/x-www-form-urlencoded" in parts[0] else body_str[:200]
                auth_attempts.append({
                    "stream": stream_id,
                    "url": url,
                    "payload": payload,
                })
        except Exception:
            continue
    return auth_attempts


def extract_http_exfiltration(streams: dict[str, bytes]) -> list[dict]:
    """Parse le trafic HTTP POST/GET pour extraire les données exfiltrées (hors formulaires d'authentification)."""
    import urllib.parse
    exfil_data = []

    for stream_id, data in streams.items():
        try:
            if b"POST " in data:
                first_line = data.split(b"\r\n")[0]
                url = first_line.split(b" ")[1].decode('utf-8', 'ignore') if len(first_line.split(b" ")) > 1 else ""
                if any(k in url.lower() for k in ("wp-login.php", "login", "auth", "signin", "xmlrpc.php")):
                    continue

                parts = data.split(b"\r\n\r\n", 1)
                if len(parts) > 1:
                    headers = parts[0]
                    body = parts[1].split(b"HTTP/1.")[0]
                    if 0 < len(body) < 10000:
                        body_str = body.decode('utf-8', 'ignore').strip()
                        if b"application/x-www-form-urlencoded" in headers:
                            parsed = urllib.parse.parse_qs(body_str)
                            exfil_data.append({"stream": stream_id, "method": "POST", "url": url, "payload": parsed})
                        elif b"application/json" in headers or body_str.startswith("{"):
                            exfil_data.append({"stream": stream_id, "method": "POST JSON", "url": url, "payload": body_str[:200]})
                        else:
                            exfil_data.append({"stream": stream_id, "method": "POST RAW", "url": url, "payload": body_str[:200]})

            if b"GET " in data:
                first_line = data.split(b"\r\n")[0]
                url_b = first_line.split(b" ")[1] if len(first_line.split(b" ")) > 1 else b""
                if b"?" in url_b:
                    params = url_b.split(b"?")[1]
                    if len(params) > 50:
                        exfil_data.append({"stream": stream_id, "method": "GET PARAM", "payload": urllib.parse.unquote(params.decode('utf-8', 'ignore'))})
        except Exception as exc:
            log.debug("Flux %s ignore (exfiltration HTTP) : %s", stream_id, exc)

    return exfil_data
