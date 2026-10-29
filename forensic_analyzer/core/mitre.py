"""Correspondance MITRE ATT&CK des détections."""
from __future__ import annotations

TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1014":     ("Rootkit", "Évasion"),
    "T1036.004": ("Masquerade Task or Service", "Évasion"),
    "T1036.005": ("Match Legitimate Name or Location", "Évasion"),
    "T1037.004": ("RC Scripts", "Persistance"),
    "T1053.003": ("Cron", "Persistance"),
    "T1055":     ("Process Injection", "Évasion / Élévation"),
    "T1059.003": ("Windows Command Shell", "Exécution"),
    "T1059.004": ("Unix Shell", "Exécution"),
    "T1070.003": ("Clear Command History", "Évasion"),
    "T1078.003": ("Local Accounts", "Accès / Élévation"),
    "T1095":     ("Non-Application Layer Protocol", "Commande et contrôle"),
    "T1098.004": ("SSH Authorized Keys", "Persistance"),
    "T1543.002": ("Systemd Service", "Persistance / Élévation"),
    "T1546.004": ("Unix Shell Configuration Modification", "Persistance"),
    "T1548.003": ("Sudo and Sudo Caching", "Élévation"),
    "T1564.001": ("Hidden Files and Directories", "Évasion"),
    "T1571":     ("Non-Standard Port", "Commande et contrôle"),
    "T1574.006": ("Dynamic Linker Hijacking", "Persistance / Évasion"),
}


def describe(technique_ids) -> list[dict]:
    """Liste triée et dédoublonnée {id, name, tactic} pour les identifiants donnés."""
    return [{"id": t, "name": TECHNIQUES[t][0], "tactic": TECHNIQUES[t][1]}
            for t in sorted(set(technique_ids)) if t in TECHNIQUES]


def summary(technique_ids) -> str:
    """Résumé lisible pour les métadonnées : « T1543.002 Systemd Service, ... »."""
    return ", ".join(f"{t['id']} {t['name']}" for t in describe(technique_ids))
