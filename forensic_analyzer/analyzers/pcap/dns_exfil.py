import math
from collections import Counter
try:
    from scapy.all import DNS, DNSQR
except ImportError:
    pass

def has_high_entropy(s: str) -> bool:
    if len(s) < 10: return False
    freq = Counter(s)
    n = len(s)
    entropy = -sum((c/n) * math.log2(c/n) for c in freq.values())
    return entropy > 3.5

def detect_dns_exfiltration(packets) -> dict:
    dns_queries, query_lengths, subdomain_depths = [], [], []
    unique_domains = set()
    txt_queries = 0
    for pkt in packets:
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR): continue
        qr = pkt[DNSQR]
        qname = qr.qname.decode('utf-8', 'replace').rstrip('.')
        qtype = qr.qtype
        parts = qname.split('.')
        subdomain_depths.append(len(parts))
        query_lengths.append(len(qname))
        unique_domains.add('.'.join(parts[-2:]) if len(parts) >= 2 else qname)
        if qtype == 16: txt_queries += 1
        dns_queries.append({"query": qname, "type": {1: "A", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}.get(qtype, str(qtype))})
    if not dns_queries: return {"detected": False, "detail": "Pas de requetes DNS"}
    avg_length = sum(query_lengths) / len(query_lengths)
    avg_depth = sum(subdomain_depths) / len(subdomain_depths)
    long_queries = sum(1 for l in query_lengths if l > 50)
    entropy_queries = sum(1 for q in dns_queries if has_high_entropy(q["query"]))
    score = 0
    indicators = []
    if avg_length > 40: score += 2; indicators.append(f"Longueur moyenne elevee ({avg_length:.0f} chars)")
    if long_queries > len(dns_queries) * 0.1: score += 2; indicators.append(f"{long_queries} requetes longues (>50 chars)")
    if avg_depth > 4: score += 1; indicators.append(f"Profondeur moyenne elevee ({avg_depth:.1f} niveaux)")
    if txt_queries > 5: score += 2; indicators.append(f"{txt_queries} requetes TXT")
    if entropy_queries > len(dns_queries) * 0.2: score += 3; indicators.append(f"{entropy_queries} requetes a haute entropie")
    return {"detected": score >= 3, "score": score, "total_queries": len(dns_queries), "unique_domains": len(unique_domains), "avg_query_length": round(avg_length, 1), "avg_subdomain_depth": round(avg_depth, 1), "txt_queries": txt_queries, "long_queries": long_queries, "high_entropy_queries": entropy_queries, "indicators": indicators, "top_queries": dns_queries[:50]}
