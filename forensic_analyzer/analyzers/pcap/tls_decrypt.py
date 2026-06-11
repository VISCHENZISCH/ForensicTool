import subprocess
import json
import os
from forensic_analyzer.utils.logger import get_logger

log = get_logger("pcap.tls")

def extract_decrypted_http(pcap_path: str, keylog_path: str) -> list[dict]:
    """Utilise tshark pour dechiffrer le trafic TLS avec un fichier SSLKEYLOGFILE et extraire le HTTP sous-jacent."""
    if not os.path.exists(keylog_path):
        log.warning(f"Fichier de cles TLS introuvable: {keylog_path}")
        return []
        
    decrypted_data = []
    try:
        # On extrait les hotes, URIs, et donnees POST dechiffrees
        cmd = [
            "tshark", "-r", pcap_path,
            "-o", f"tls.keylog_file:{keylog_path}",
            "-Y", "http.request or http.response",
            "-T", "json",
            "-e", "ip.src", "-e", "ip.dst", 
            "-e", "http.request.method", "-e", "http.host", "-e", "http.request.uri",
            "-e", "http.file_data"
        ]
        
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout)
            for packet in data:
                layers = packet.get("_source", {}).get("layers", {})
                
                src = layers.get("ip.src", [""])[0]
                dst = layers.get("ip.dst", [""])[0]
                method = layers.get("http.request.method", [""])[0]
                host = layers.get("http.host", [""])[0]
                uri = layers.get("http.request.uri", [""])[0]
                file_data = layers.get("http.file_data", [""])[0]
                
                if method or file_data:
                    decrypted_data.append({
                        "src": src,
                        "dst": dst,
                        "method": method,
                        "host": host,
                        "uri": uri,
                        "data": file_data[:500] if file_data else ""
                    })
    except Exception as e:
        log.error(f"Erreur lors du dechiffrement TLS: {e}")
        
    return decrypted_data
