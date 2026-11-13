"""Correspondance MITRE ATT&CK des détections."""

from __future__ import annotations

TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1014": ("Rootkit", "Évasion"),
    "T1036.004": ("Masquerade Task or Service", "Évasion"),
    "T1036.005": ("Match Legitimate Name or Location", "Évasion"),
    "T1037.004": ("RC Scripts", "Persistance"),
    "T1053.003": ("Cron", "Persistance"),
    "T1055": ("Process Injection", "Évasion / Élévation"),
    "T1059.003": ("Windows Command Shell", "Exécution"),
    "T1059.004": ("Unix Shell", "Exécution"),
    "T1070.003": ("Clear Command History", "Évasion"),
    "T1078.003": ("Local Accounts", "Accès / Élévation"),
    "T1095": ("Non-Application Layer Protocol", "Commande et contrôle"),
    "T1098.004": ("SSH Authorized Keys", "Persistance"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1562.004": ("Disable or Modify System Firewall", "Évasion"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1543.002": ("Systemd Service", "Persistance / Élévation"),
    "T1546.004": ("Unix Shell Configuration Modification", "Persistance"),
    "T1548.003": ("Sudo and Sudo Caching", "Élévation"),
    "T1564.001": ("Hidden Files and Directories", "Évasion"),
    "T1571": ("Non-Standard Port", "Commande et contrôle"),
    "T1574.006": ("Dynamic Linker Hijacking", "Persistance / Évasion"),
}

# Linux, journaux web, réseau et ransomware (agent LINUX-WEB-NET)
TECHNIQUES.update(
    {
        "T1003.008": ("/etc/passwd and /etc/shadow", "Accès aux identifiants"),
        "T1046": ("Network Service Discovery", "Découverte"),
        "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
        "T1053.002": ("At", "Persistance"),
        "T1053.006": ("Systemd Timers", "Persistance"),
        "T1059.006": ("Python", "Exécution"),
        "T1070.002": ("Clear Linux or Mac System Logs", "Évasion"),
        "T1071.001": ("Web Protocols", "Commande et contrôle"),
        "T1071.004": ("DNS", "Commande et contrôle"),
        "T1098": ("Account Manipulation", "Persistance"),
        "T1105": ("Ingress Tool Transfer", "Commande et contrôle"),
        "T1110.001": ("Password Guessing", "Accès aux identifiants"),
        "T1136.001": ("Local Account", "Persistance"),
        "T1140": ("Deobfuscate/Decode Files or Information", "Évasion"),
        "T1190": ("Exploit Public-Facing Application", "Accès initial"),
        "T1490": ("Inhibit System Recovery", "Impact"),
        "T1505.003": ("Web Shell", "Persistance"),
        "T1546.017": ("Udev Rules", "Persistance"),
        "T1547.006": ("Kernel Modules and Extensions", "Persistance / Élévation"),
        "T1547.013": ("XDG Autostart Entries", "Persistance"),
        "T1548.001": ("Setuid and Setgid", "Élévation"),
        "T1556.003": ("Pluggable Authentication Modules", "Accès aux identifiants / Persistance"),
        "T1562.012": ("Disable or Modify Linux Audit System", "Évasion"),
        "T1572": ("Protocol Tunneling", "Commande et contrôle"),
        "T1595.002": ("Vulnerability Scanning", "Reconnaissance"),
        "T1595.003": ("Wordlist Scanning", "Reconnaissance"),
    }
)


def describe(technique_ids) -> list[dict]:
    """Liste triée et dédoublonnée {id, name, tactic} pour les identifiants donnés."""
    return [
        {"id": t, "name": TECHNIQUES[t][0], "tactic": TECHNIQUES[t][1]} for t in sorted(set(technique_ids)) if t in TECHNIQUES
    ]


def summary(technique_ids) -> str:
    """Résumé lisible pour les métadonnées : « T1543.002 Systemd Service, ... »."""
    return ", ".join(f"{t['id']} {t['name']}" for t in describe(technique_ids))
