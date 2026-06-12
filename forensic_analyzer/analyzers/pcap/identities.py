import struct
import subprocess
import json
from collections import defaultdict
from forensic_analyzer.utils.logger import get_logger

log = get_logger("pcap.identities")

try:
    from scapy.all import IP, UDP, Ether
except ImportError:
    pass

def extract_host_identities(packets, streams: dict[str, bytes], path: str) -> dict:
    mac_info = defaultdict(lambda: {"ips": set(), "hostnames": set(), "users": set()})
    ip_to_mac = {}
    for pkt in packets:
        if not pkt.haslayer(Ether): continue
        mac = pkt[Ether].src
        if pkt.haslayer(IP):
            ip_src = pkt[IP].src
            if ip_src not in ("0.0.0.0", "255.255.255.255"):
                mac_info[mac]["ips"].add(ip_src)
                ip_to_mac[ip_src] = mac
        if pkt.haslayer(UDP) and pkt[UDP].sport == 68 and pkt[UDP].dport == 67:
            try:
                raw_payload = bytes(pkt[UDP].payload)
                idx = raw_payload.find(b'\x0c')
                if idx != -1 and idx + 1 < len(raw_payload):
                    length = raw_payload[idx+1]
                    if idx + 2 + length <= len(raw_payload):
                        hostname = raw_payload[idx+2 : idx+2+length].decode('utf-8', 'ignore')
                        if hostname and len(hostname) > 1: mac_info[mac]["hostnames"].add(hostname)
            except Exception:
                pass  # TODO: log.debug(exc)

    ntlm_sig = b"NTLMSSP\x00\x03\x00\x00\x00"
    for stream_id, data in streams.items():
        src_ip = stream_id.split(":")[0]
        mac = ip_to_mac.get(src_ip)
        if not mac: continue
        idx = 0
        while True:
            idx = data.find(ntlm_sig, idx)
            if idx == -1: break
            try:
                usr_len, _, usr_off = struct.unpack_from("<HHI", data, idx + 36)
                ws_len, _, ws_off = struct.unpack_from("<HHI", data, idx + 44)
                if usr_len > 0 and idx + usr_off + usr_len <= len(data):
                    user = data[idx + usr_off : idx + usr_off + usr_len].decode('utf-16le', 'ignore')
                    if user and not user.endswith('$'): mac_info[mac]["users"].add(user)
                if ws_len > 0 and idx + ws_off + ws_len <= len(data):
                    ws = data[idx + ws_off : idx + ws_off + ws_len].decode('utf-16le', 'ignore')
                    if ws and len(ws) > 1: mac_info[mac]["hostnames"].add(ws)
            except Exception:
                pass  # TODO: log.debug(exc)
            idx += 8

    final_results = {}
    for mac, info in mac_info.items():
        if info["hostnames"] or info["users"]:
            for ip in info["ips"]:
                if ip not in final_results: final_results[ip] = {"mac": set(), "hostnames": set(), "users": set()}
                final_results[ip]["mac"].add(mac)
                final_results[ip]["hostnames"].update(info["hostnames"])
                final_results[ip]["users"].update(info["users"])

    try:
        filter_str = "(kerberos.CNameString and (udp.dstport==88 or tcp.dstport==88)) or (smb2.acct and (tcp.dstport==445 or tcp.dstport==139)) or ldap.name"
        cmd = ["tshark", "-r", path, "-Y", filter_str, "-T", "json", "-e", "ip.src", "-e", "kerberos.CNameString", "-e", "smb2.acct", "-e", "ldap.name"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout)
            for packet in data:
                layers = packet.get("_source", {}).get("layers", {})
                src_ip = layers.get("ip.src", [""])[0]
                if not src_ip: continue
                cnames = layers.get("kerberos.CNameString", [])
                for cname in cnames:
                    if cname and not cname.endswith("$") and cname != "krbtgt":
                        if src_ip not in final_results: final_results[src_ip] = {"mac": set(), "hostnames": set(), "users": set()}
                        final_results[src_ip]["users"].add(cname)
                acct = layers.get("smb2.acct", [""])[0]
                if acct and not acct.endswith("$"):
                    if src_ip not in final_results: final_results[src_ip] = {"mac": set(), "hostnames": set(), "users": set()}
                    final_results[src_ip]["users"].add(acct)
                
                # Extraction LDAP
                ldap_names = layers.get("ldap.name", [])
                for lname in ldap_names:
                    if lname and "=" in lname:
                        # Ex: CN=jsimpson,CN=Users,DC=...
                        parts = lname.split(",")
                        for part in parts:
                            if part.startswith("CN=") and not part.endswith("$") and part != "CN=Users" and part != "CN=Computers":
                                username = part[3:]
                                if src_ip not in final_results: final_results[src_ip] = {"mac": set(), "hostnames": set(), "users": set()}
                                final_results[src_ip]["users"].add(username)
        else:
            log.warning(f"Tshark extraction retourné un code d'erreur: {res.stderr}")
    except Exception as e:
        log.warning(f"Erreur Tshark Kerberos/SMB2: {e}")

    for ip in final_results:
        final_results[ip] = {"mac": list(final_results[ip]["mac"]), "hostnames": list(final_results[ip]["hostnames"]), "users": list(final_results[ip]["users"])}
    return final_results
