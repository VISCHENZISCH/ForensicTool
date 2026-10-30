from collections import defaultdict
try:
    from scapy.all import IP, TCP
except ImportError:
    pass

_SUSPICIOUS_C2_PORTS = {4444, 5555, 1337, 31337, 8888, 6667, 9999, 1234, 4445, 7777}


def detect_c2_beacons(packets) -> dict:
    connections: dict[str, list[float]] = defaultdict(list)
    port_map: dict[str, int] = {}
    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP): continue
        ip, tcp = pkt[IP], pkt[TCP]
        if tcp.flags & 0x02:
            key = f"{ip.src} -> {ip.dst}:{tcp.dport}"
            connections[key].append(float(pkt.time))
            port_map[key] = tcp.dport
    beacons = []
    for conn, times in connections.items():
        dport = port_map.get(conn, 0)
        if dport in _SUSPICIOUS_C2_PORTS:
            beacons.append({
                "connection": conn,
                "count": len(times),
                "avg_interval_sec": 0,
                "jitter_pct": 0,
                "detail": f"Connexion suspecte (port C2/reverse shell Metasploit {dport}) : {conn} ({len(times)} SYN)"
            })
            continue

        if len(times) < 5: continue
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval == 0: continue
        variance = sum((i - avg_interval)**2 for i in intervals) / len(intervals)
        stddev = variance ** 0.5
        jitter_pct = (stddev / avg_interval * 100) if avg_interval > 0 else 100
        if jitter_pct < 20 and avg_interval > 1:
            beacons.append({
                "connection": conn,
                "count": len(times),
                "avg_interval_sec": round(avg_interval, 2),
                "jitter_pct": round(jitter_pct, 2),
                "detail": f"Beacon suspect : intervalle ~{avg_interval:.0f}s, jitter {jitter_pct:.0f}%"
            })
    return {"detected": len(beacons) > 0, "beacons": beacons, "total_connections_analyzed": len(connections)}
