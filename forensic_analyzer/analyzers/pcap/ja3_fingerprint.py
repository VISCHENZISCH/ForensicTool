try:
    from scapy.all import TLSClientHello
except ImportError:
    pass

import hashlib

def get_ja3_fingerprints(packets) -> dict:
    """Extrait les empreintes JA3 (TLS Client Hello) et SNI depuis le PCAP."""
    ja3_hashes = {}
    sni_list = []
    
    try:
        if not hasattr(packets, 'filename') or not packets.filename:
            return {"ja3": {}, "sni": []}
            
        import subprocess
        import json
        
        # On demande JA3 et SNI
        cmd = [
            "tshark", "-r", packets.filename, "-Y", "tls.handshake.type == 1", 
            "-T", "json", 
            "-e", "ip.src", "-e", "tcp.srcport", 
            "-e", "ip.dst", "-e", "tcp.dstport", 
            "-e", "tls.handshake.ja3", 
            "-e", "tls.handshake.extensions_server_name"
        ]
        
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout)
            for packet in data:
                layers = packet.get("_source", {}).get("layers", {})
                
                # JA3
                ja3_val = layers.get("tls.handshake.ja3", [])
                src = layers.get("ip.src", [""])[0]
                dst = layers.get("ip.dst", [""])[0]
                
                if ja3_val and src and dst:
                    conn_id = f"{src} -> {dst}"
                    ja3_hashes[conn_id] = ja3_val[0]
                    
                # SNI
                sni_val = layers.get("tls.handshake.extensions_server_name", [])
                if sni_val:
                    sni_list.append(sni_val[0])
                    
    except Exception as e:
        pass
        
    return {
        "ja3": ja3_hashes,
        "sni": list(set(sni_list))
    }
