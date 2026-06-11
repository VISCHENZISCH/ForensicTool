import math
from collections import defaultdict
from difflib import SequenceMatcher

def calculate_shannon_entropy(s: str) -> float:
    if not s: return 0.0
    entropy = 0.0
    for x in set(s):
        p_x = float(s.count(x)) / len(s)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def is_dga(domain: str) -> bool:
    # Remove TLD
    parts = domain.split('.')
    if len(parts) > 1:
        base = parts[-2]
    else:
        base = domain
    
    if len(base) < 8:
        return False
        
    ent = calculate_shannon_entropy(base)
    if ent > 3.8:  # High entropy (randomness)
        return True
        
    consonants = "bcdfghjklmnpqrstvwxyz"
    vowels = "aeiou"
    c_count = sum(1 for c in base.lower() if c in consonants)
    v_count = sum(1 for c in base.lower() if c in vowels)
    
    if v_count > 0:
        if c_count / v_count > 4.5:
            return True
    elif c_count > 5:
        return True
        
    return False

def extract_dns_mappings(packets) -> dict[str, list[str]]:
    """
    Construit une carte passive DNS (Passive DNS) depuis le trafic.
    Retourne un dictionnaire mappant les adresses IP à leurs noms de domaine.
    """
    ip_to_domains = defaultdict(set)
    try:
        from scapy.all import DNS, DNSRR
    except ImportError:
        return {}

    for pkt in packets:
        if not pkt.haslayer(DNS) or pkt[DNS].ancount == 0:
            continue
        
        dns = pkt[DNS]
        for i in range(dns.ancount):
            try:
                rr = dns.an[i]
                # Type 1 = A (IPv4), Type 28 = AAAA (IPv6)
                if rr.type in (1, 28) and hasattr(rr, 'rdata') and hasattr(rr, 'rrname'):
                    # Selon la version de scapy, rdata peut etre bytes ou str
                    ip = rr.rdata
                    if isinstance(ip, bytes):
                        ip = ip.decode('utf-8', 'ignore')
                        
                    domain = rr.rrname
                    if isinstance(domain, bytes):
                        domain = domain.decode('utf-8', 'ignore')
                    domain = domain.rstrip('.')
                    
                    if domain and ip:
                        ip_to_domains[ip].add(domain)
            except Exception as exc:
                pass  # TODO: log.debug(exc)
                pass

    import difflib

    suspect_domains = []
    targets = ["google", "authenticator", "microsoft", "windows", "paypal", "update"]

    for ip, domains in ip_to_domains.items():
        for domain in domains:
            dom_lower = domain.lower()
            for t in targets:
                for part in dom_lower.split('.'):
                    if part != t and len(t)-1 <= len(part) <= len(t)+2:
                        ratio = difflib.SequenceMatcher(None, part, t).ratio()
                        if ratio >= 0.85:
                            suspect_domains.append({"domaine": domain, "cible": t.capitalize(), "raison": f"Typosquatting ({ratio:.0%} ressemblance)"})
                    elif t in part and len(part) < len(t) + 5 and part != t:
                        suspect_domains.append({"domaine": domain, "cible": t.capitalize(), "raison": "Mot-clé sensible inséré"})
                        
            if is_dga(domain):
                suspect_domains.append({"domaine": domain, "cible": "DGA", "raison": "Algorithme de génération de domaine (Entropie élevée)"})

    # Deduplication
    unique_suspects = []
    seen = set()
    for s in suspect_domains:
        key = f"{s['domaine']}-{s['cible']}"
        if key not in seen:
            seen.add(key)
            unique_suspects.append(s)

    return {
        "mappings": {ip: list(doms) for ip, doms in ip_to_domains.items()},
        "suspects": unique_suspects
    }
