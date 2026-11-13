"""Classement des lignes de commande shell par comportement offensif (historiques, audit, cron).

Chaque catégorie porte ses techniques ATT&CK et dit si elle suffit à lever une alerte : un
shell inversé ou l'effacement de l'historique n'a pas d'usage d'administration courant, un
téléchargement ou un `useradd` en a, et reste un point à vérifier.
Motifs inspirés des règles SigmaHQ linux/process_creation et linux/auditd.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_COMMAND_CHARS = 300  # une ligne d'historique hostile peut être arbitrairement longue
MAX_EVENTS = 200  # événements de chronologie gardés par source


@dataclass(frozen=True)
class Category:
    key: str
    label: str
    mitre: tuple[str, ...]
    alert: bool
    pattern: re.Pattern[str]


def _rx(*parts: str) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in parts), re.IGNORECASE)


CATEGORIES: tuple[Category, ...] = (
    Category(
        "reverse_shell",
        "Shell inversé",
        ("T1059.004",),
        True,
        _rx(
            r"/dev/(?:tcp|udp)/[\w.-]+/\d+",
            r"\bn(?:c|cat|etcat)\b[^|;]*\s-[a-z]*[ec]\s",
            r"mkfifo\b.*\|\s*(?:/bin/)?(?:ba|z|da)?sh\b",
            r"\bsocat\b.*\bexec:",
            r"\bperl\b.*-e.*socket",
            r"\bphp\b.*-r.*fsockopen",
            r"\bruby\b.*-rsocket",
            r"\bpython[23.]*\b.*-c.*socket.*(?:connect|dup2|pty)",
        ),
    ),
    Category(
        "download_exec",
        "Téléchargement puis exécution",
        ("T1105", "T1059.004"),
        True,
        _rx(
            r"\b(?:curl|wget|fetch)\b[^|;&]*\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z|da|k)?sh\b",
            r"\b(?:curl|wget)\b[^|;&]*https?://\S+.*(?:&&|;)\s*(?:chmod\s+\+?[0-7]*x|\./|(?:ba)?sh\s)",
            r"\b(?:ba)?sh\s+<\(\s*(?:curl|wget)\b",
        ),
    ),
    Category(
        "decode_exec",
        "Décodage puis exécution",
        ("T1140", "T1059.004"),
        True,
        _rx(r"base64\s+(?:-d|--decode)\b.*\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z|da)?sh\b", r"\|\s*xxd\s+-r.*\|\s*(?:ba)?sh"),
    ),
    Category(
        "history_tamper",
        "Effacement de l'historique",
        ("T1070.003",),
        True,
        _rx(
            r"\bhistory\s+-[cw]\b",
            r"\bunset\s+HISTFILE\b",
            r"\bHIST(?:FILE)?SIZE=0\b",
            r"\bHISTFILE=/dev/null",
            r"\bset\s+\+o\s+history\b",
            r"\b(?:rm|shred|truncate)\b.*\.(?:bash|zsh|sh|ash)_history",
            r"\bln\s+-s\w*\s+/dev/null\s+\S*_history",
            r"(?:^|[;&|]\s*)(?:cat\s+/dev/null\s*)?>\s*~?/?\S*\.(?:bash|zsh)_history",
        ),
    ),
    Category(
        "log_clearing",
        "Effacement de journaux système",
        ("T1070.002",),
        True,
        _rx(
            r"\b(?:rm|shred|unlink)\b[^;|&]*/var/log/",
            r"\btruncate\b[^;|&]*(?:/var/log/|wtmp|btmp|lastlog)",
            r"(?:^|[;&|]\s*)(?:echo\s*(?:\"\"|'')?\s*|cat\s+/dev/null\s*|:\s*)?>\s*/var/log/",
            r"\bjournalctl\b.*--vacuum",
            r"\butmpdump\b|\blogtamper\b|\bwtmpclean\b",
        ),
    ),
    Category(
        "audit_tamper",
        "Neutralisation de l'audit",
        ("T1562.012",),
        True,
        _rx(r"\bauditctl\s+-(?:D|e\s*0)\b", r"\b(?:systemctl|service)\s+(?:stop|disable|mask)\s+auditd|\bauditd\s+stop\b"),
    ),
    Category(
        "defense_evasion",
        "Désactivation des protections",
        ("T1562.004",),
        True,
        _rx(
            r"\biptables\s+-[FX]\b",
            r"\bufw\s+disable\b",
            r"\bsetenforce\s+0\b",
            r"\b(?:systemctl|service)\s+(?:stop|disable)\s+(?:firewalld|apparmor|ufw|falcon-sensor|wazuh-agent|osqueryd)",
        ),
    ),
    Category(
        "credential_access",
        "Accès aux secrets de comptes",
        ("T1003.008",),
        True,
        _rx(
            r"\b(?:cat|less|more|head|tail|cp|scp|base64|strings|grep)\b[^;|&]*/etc/(?:g?shadow|security/opasswd)\b",
            r"\bunshadow\b",
            r"\bmimipenguin\b|\blazagne\b",
        ),
    ),
    Category(
        "account_manipulation",
        "Création ou élévation de compte",
        ("T1136.001", "T1098"),
        True,
        _rx(
            r"\busermod\b.*-a?G\s*\S*\b(?:sudo|wheel|root|adm|docker|lxd)\b",
            r">>\s*/etc/(?:passwd|shadow|sudoers|group)\b",
            r"\buseradd\b.*-o\b.*-u\s*0\b|\buseradd\b.*-u\s*0\b.*-o\b",
            r"NOPASSWD\s*:\s*ALL",
        ),
    ),
    Category(
        "account_creation",
        "Création de compte",
        ("T1136.001",),
        False,
        _rx(r"\b(?:useradd|adduser)\b", r"\bpasswd\s+\w+"),
    ),
    Category(
        "suid",
        "Positionnement d'un bit SUID/SGID",
        ("T1548.001",),
        True,
        _rx(r"\bchmod\s+(?:-\w+\s+)*(?:[ugo]*\+s\b|[2467][0-7]{3}\b)"),
    ),
    Category(
        "persistence",
        "Mise en place de persistance",
        ("T1098.004", "T1574.006", "T1546.004"),
        True,
        _rx(
            r">>?\s*\S*\.ssh/authorized_keys",
            r"/etc/ld\.so\.preload",
            r">>\s*\S*/(?:\.bashrc|\.profile|\.bash_profile|\.zshrc|bash\.bashrc|profile)\b",
        ),
    ),
    Category(
        "scheduled_persistence",
        "Tâche planifiée ou service",
        ("T1053.003", "T1543.002"),
        False,
        _rx(r"\bcrontab\s+(?:-\w\s+)*-?[re]\b|>>?\s*/etc/cron", r"\bsystemctl\s+(?:--user\s+)?enable\b", r"\bat\s+now\b"),
    ),
    Category(
        "kernel_module",
        "Chargement de module noyau",
        ("T1547.006",),
        False,
        _rx(r"\binsmod\b|\bmodprobe\s+(?!-r)\S"),
    ),
    Category(
        "inhibit_recovery",
        "Destruction des sauvegardes / points de restauration",
        ("T1490",),
        True,
        _rx(
            r"\bvssadmin(?:\.exe)?\b.*\bdelete\s+shadows",
            r"\bvssadmin(?:\.exe)?\b.*\bresize\s+shadowstorage\b",
            r"\bwmic(?:\.exe)?\b.*\bshadowcopy\b.*\bdelete",
            r"\bwbadmin(?:\.exe)?\b.*\bdelete\s+(?:catalog|systemstatebackup|backup)",
            r"\bbcdedit(?:\.exe)?\b.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)",
            r"Get-WmiObject\s+Win32_Shadowcopy.*Delete|Remove-CimInstance.*Win32_ShadowCopy",
            r"\bvim-cmd\s+vmsvc/snapshot\.remove",
            r"\b(?:lvremove|zfs\s+destroy|btrfs\s+subvolume\s+delete)\b",
            r"\brm\s+-\w*r\w*\s+\S*(?:backup|\.snapshots|/bak)\b",
        ),
    ),
    Category(
        "exfiltration",
        "Exfiltration de données",
        ("T1048",),
        False,
        _rx(
            r"\brclone\s+(?:copy|sync|move)\b",
            r"\bcurl\b.*(?:-T\s|--upload-file|-F\s+\S*=@|--data-binary\s+@)",
            r"\bn(?:c|cat)\b\s+\S+\s+\d+\s*<",
        ),
    ),
    Category(
        "miner",
        "Minage de cryptomonnaie",
        ("T1496",),
        True,
        _rx(r"\bxmrig\b|stratum\+(?:tcp|ssl)://|\bminerd\b|\bcpuminer\b"),
    ),
    Category(
        "offensive_tool",
        "Outil offensif ou de reconnaissance",
        ("T1046",),
        False,
        _rx(
            r"\b(?:nmap|masscan|zmap|rustscan|hydra|medusa|john|hashcat|linpeas|linenum|pspy|chisel|ligolo|"
            r"gsocket|sliver|msfconsole|msfvenom|responder|crackmapexec|netexec|impacket)\b",
            r"\bfind\s+/\s+.*-perm\s+-?[u/]?=?(?:4000|s)\b",
        ),
    ),
    Category(
        "download",
        "Téléchargement d'outil",
        ("T1105",),
        False,
        _rx(r"\b(?:wget|curl|tftp|fetch)\b[^|]*\b(?:https?|ftp)://", r"\bscp\s+\S+@\S+:\S+\s+\S"),
    ),
)

_BY_KEY = {c.key: c for c in CATEGORIES}
# Une catégorie précise rend la plus générale redondante pour la même commande
_SUPERSEDES = {"download_exec": ("download",), "account_manipulation": ("account_creation",)}


def classify(command: str) -> list[Category]:
    """Catégories reconnues dans une commande (lecture bornée)."""
    text = command[:MAX_COMMAND_CHARS * 4]
    hits = [c for c in CATEGORIES if c.pattern.search(text)]
    dropped = {k for c in hits for k in _SUPERSEDES.get(c.key, ())}
    return [c for c in hits if c.key not in dropped]


def category(key: str) -> Category:
    return _BY_KEY[key]


def analyze_commands(commands: list[tuple[str, str]], source: str, file: str = "") -> dict:
    """
    Classe une suite de (horodatage ISO ou "", commande).

    Retourne {"hits": [...], "by_category": {clé: nombre}, "mitre": [...], "alerts": {libellé: [exemples]},
    "events": [...]} ; les événements ne portent que des commandes horodatées.
    """
    hits: list[dict] = []
    by_category: dict[str, int] = {}
    alerts: dict[str, list[str]] = {}
    techniques: set[str] = set()
    events: list[dict] = []
    for ts, command in commands:
        cats = classify(command)
        if not cats:
            continue
        short = command[:MAX_COMMAND_CHARS]
        hits.append({"timestamp": ts, "command": short, "categories": [c.key for c in cats]})
        for c in cats:
            by_category[c.key] = by_category.get(c.key, 0) + 1
            techniques.update(c.mitre)
            if c.alert:
                alerts.setdefault(c.label, []).append(short)
        if ts and len(events) < MAX_EVENTS:
            events.append(
                {
                    "timestamp": ts,
                    "source": source,
                    "event_type": cats[0].key,
                    "description": f"{cats[0].label} : {short[:150]}",
                    "file": file,
                    "details": ", ".join(t for c in cats for t in c.mitre),
                }
            )
    return {
        "hits": hits[:500],
        "by_category": by_category,
        "mitre": sorted(techniques),
        "alerts": alerts,
        "events": events,
    }
