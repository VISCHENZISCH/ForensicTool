"""Transactions HTTP reconstruites paquet par paquet, puis lecture de l'attaque qu'elles décrivent.

La reconstruction par flux TCP fusionne les connexions qui réutilisent un port source et
ne sait pas apparier une réponse à sa requête. Ici, chaque requête est rattachée à la
réponse suivante sur le même quadruplet IP/port, dans l'ordre du temps.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from collections import defaultdict

try:
    from scapy.all import IP, TCP, Raw
except ImportError:
    pass

_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")
_LOGIN_URI = re.compile(r"(?i)wp-login\.php|xmlrpc\.php|/login|/signin|/auth")
_USER_KEYS = ("log", "user", "username", "login", "email")
_PASS_KEYS = ("pwd", "password", "passwd", "pass")
_SENSITIVE_DOWNLOAD = re.compile(r"(?i)\.(sql|sql\.gz|gz|tgz|tar|zip|7z|rar|bak|dump|db|sqlite|csv|xlsx?)(\?|$)")
_CMD_PARAMS = ("c", "cmd", "command", "exec", "e")
_C2_PORTS = {4444, 5555, 1337, 31337, 6667, 8888, 9999, 1234, 4445, 7777}
_AUTOMATION_UA = re.compile(r"(?i)^(axios|curl|wget|python-requests|python-urllib|go-http-client|libwww-perl|java/|okhttp|powershell|nmap|sqlmap|nikto|hydra|wpscan)")


def _headers(block: bytes) -> dict[str, str]:
    out = {}
    for line in block.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            out[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return out


def extract_http_transactions(packets) -> list[dict]:
    """Requêtes HTTP en clair, chacune avec sa réponse (statut, taille annoncée) si elle est capturée."""
    pending: dict[tuple, dict] = {}
    transactions: list[dict] = []
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw)):
            continue
        ip, tcp, data = pkt[IP], pkt[TCP], bytes(pkt[Raw].load)
        if data.startswith(_METHODS):
            head, _, body = data.partition(b"\r\n\r\n")
            parts = head.split(b"\r\n", 1)[0].split(b" ")
            hdr = _headers(head)
            tx = {
                "time": float(pkt.time), "client": ip.src, "client_port": tcp.sport,
                "server": ip.dst, "server_port": tcp.dport,
                "method": parts[0].decode("latin-1"),
                "uri": parts[1].decode("latin-1", "replace") if len(parts) > 1 else "",
                "host": hdr.get("host", ""), "user_agent": hdr.get("user-agent", ""),
                "body": body[:4096], "status": None, "response_length": None, "location": "",
            }
            transactions.append(tx)
            pending[(ip.src, tcp.sport, ip.dst, tcp.dport)] = tx
        elif data.startswith(b"HTTP/1."):
            tx = pending.pop((ip.dst, tcp.dport, ip.src, tcp.sport), None)
            if tx is None:
                continue
            head = data.partition(b"\r\n\r\n")[0]
            status = head.split(b"\r\n", 1)[0].split(b" ")
            hdr = _headers(head)
            tx["status"] = int(status[1]) if len(status) > 1 and status[1].isdigit() else None
            length = hdr.get("content-length", "")
            tx["response_length"] = int(length) if length.isdigit() else len(data) - len(head) - 4
            tx["location"] = hdr.get("location", "")
            tx["sets_session"] = "logged_in" in hdr.get("set-cookie", "") or "session" in hdr.get("set-cookie", "").lower()
    return transactions


def _form(body: bytes) -> dict[str, str]:
    try:
        parsed = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
    except ValueError:
        return {}
    return {k: v[0] for k, v in parsed.items() if v}


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def analyze_http_attack(transactions: list[dict]) -> dict:
    """
    Lecture offensive des transactions : brute-force (et identifiants qui ont fonctionné),
    téléversements, commandes de webshell, téléchargements sensibles (exfiltration),
    balises sortantes et rôle de chaque client.
    """
    login_tries: dict[str, list[dict]] = defaultdict(list)
    successes, uploads, webshell_cmds, exfiltration, beacons = [], [], [], [], []

    for tx in transactions:
        uri, path = tx["uri"], tx["uri"].split("?", 1)[0]
        query = urllib.parse.parse_qs(tx["uri"].split("?", 1)[1]) if "?" in tx["uri"] else {}

        if tx["method"] == "POST" and _LOGIN_URI.search(path):
            form = _form(tx["body"])
            user = next((form[k] for k in _USER_KEYS if k in form), None)
            pwd = next((form[k] for k in _PASS_KEYS if k in form), None)
            login_tries[tx["client"]].append(tx)
            # WordPress : 302 vers /wp-admin + cookie de session = mot de passe accepté
            if tx["status"] in (301, 302, 303) and (tx.get("sets_session") or "admin" in tx["location"]):
                successes.append({"time": tx["time"], "client": tx["client"], "server": tx["server"],
                                  "uri": path, "username": user, "password": pwd})

        if tx["method"] in ("POST", "PUT") and b"filename=" in tx["body"]:
            name = re.search(rb'filename="([^"]+)"', tx["body"])
            uploads.append({"time": tx["time"], "client": tx["client"], "server": tx["server"], "uri": path,
                            "filename": name.group(1).decode("utf-8", "replace") if name else "?",
                            "php": bool(re.search(rb"<\?php|system\(|exec\(|passthru\(|shell_exec\(", tx["body"]))})

        cmd_key = next((k for k in _CMD_PARAMS if k in query), None)
        if cmd_key and path.lower().endswith((".php", ".jsp", ".asp", ".aspx")):
            webshell_cmds.append({"time": tx["time"], "client": tx["client"], "server": tx["server"],
                                  "shell": path, "command": query[cmd_key][0]})

        if tx["method"] == "GET" and _SENSITIVE_DOWNLOAD.search(path) and tx["status"] in (200, 206, None):
            exfiltration.append({"time": tx["time"], "client": tx["client"], "server": tx["server"],
                                 "uri": path, "status": tx["status"], "bytes": tx["response_length"]})

        # Requête sortante d'un serveur vers une IP publique sur un port de C2 connu
        if tx["server_port"] in _C2_PORTS or re.search(r"(?i)/(beacon|checkin|gate|heartbeat)\b", path):
            beacons.append({"time": tx["time"], "source": tx["client"], "destination": tx["server"],
                            "port": tx["server_port"], "uri": uri[:120],
                            "outbound": _is_public(tx["server"]) and not _is_public(tx["client"])
                                        or tx["server_port"] in _C2_PORTS})

    brute_force = []
    for client, tries in login_tries.items():
        if len(tries) < 20:
            continue
        won = [s for s in successes if s["client"] == client]
        brute_force.append({"client": client, "server": tries[0]["server"], "attempts": len(tries),
                            "first": tries[0]["time"], "last": tries[-1]["time"],
                            "succeeded": bool(won),
                            "winning_credential": f"{won[0]['username']} / {won[0]['password']}" if won else ""})

    # Rôle des clients : un client lié à une action offensive est un attaquant, son UA aussi
    attackers = {b["client"] for b in brute_force} | {u["client"] for u in uploads if u["php"]} | \
                {w["client"] for w in webshell_cmds} | {e["client"] for e in exfiltration}
    user_agents: dict[str, dict] = {}
    for tx in transactions:
        ua = tx["user_agent"]
        if not ua:
            continue
        entry = user_agents.setdefault(ua, {"user_agent": ua, "clients": set(), "requests": 0})
        entry["clients"].add(tx["client"])
        entry["requests"] += 1
    ua_list = []
    for entry in user_agents.values():
        if entry["clients"] & attackers:
            verdict = "attaquant"
        elif _AUTOMATION_UA.match(entry["user_agent"]):
            verdict = "outil automatisé"
        else:
            verdict = "navigateur"
        ua_list.append({"user_agent": entry["user_agent"], "verdict": verdict,
                        "clients": sorted(entry["clients"])[:5], "requests": entry["requests"]})
    order = {"attaquant": 0, "outil automatisé": 1, "navigateur": 2}
    ua_list.sort(key=lambda u: (order[u["verdict"]], -u["requests"]))

    return {"brute_force": brute_force, "successful_logins": successes, "uploads": uploads,
            "webshell_commands": webshell_cmds, "exfiltration": exfiltration, "beacons": beacons,
            "attackers": sorted(attackers), "user_agents": ua_list}
