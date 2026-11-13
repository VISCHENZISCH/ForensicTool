"""Règles de chasse EVTX : motifs de lignes de commande, de registre, de DNS et de filiation de processus.

Inspirées des règles SigmaHQ (windows/process_creation, registry_set, dns_query, process_access),
des règles Hayabusa et du rapport JPCERT « Detecting Lateral Movement through Tracking Event Logs ».
Chaque règle : (motif, libellé, techniques MITRE, gravité). Les motifs sont bornés ({0,n})
pour rester linéaires sur des lignes de commande hostiles et très longues.
"""

from __future__ import annotations

import re

CRIT, HIGH, MED, LOW = "critique", "haute", "moyenne", "faible"
SEVERITY_RANK = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3}

Rule = tuple[re.Pattern[str], str, tuple[str, ...], str]


def _r(pattern: str, label: str, techniques: tuple[str, ...], severity: str) -> Rule:
    return re.compile(pattern, re.I), label, techniques, severity


# Lignes de commande (4688, Sysmon 1) et blocs de script PowerShell (4104)
COMMAND_RULES: list[Rule] = [
    _r(
        r"mimikatz|sekurlsa|lsadump::|procdump[^\n]{0,60}lsass|comsvcs[^\n]{0,60}minidump|"
        r"rundll32[^\n]{0,60}comsvcs|out-minidump",
        "Vol d'identifiants (LSASS)",
        ("T1003.001",),
        CRIT,
    ),
    _r(r"reg(\.exe)?\s+(save|export)\s+\"?hklm\\(sam|security|system)\b", "Copie des ruches SAM/SECURITY", ("T1003.002",), CRIT),
    _r(
        r"ntdsutil[^\n]{0,80}(ifm|ac\s+i\s+ntds)|\\ntds\.dit|vssadmin[^\n]{0,30}create\s+shadow",
        "Extraction de NTDS.dit",
        ("T1003.003",),
        CRIT,
    ),
    _r(
        r"vssadmin[^\n]{0,30}delete\s+shadows|wmic[^\n]{0,30}shadowcopy\s+delete|bcdedit[^\n]{0,40}recoveryenabled\s+no|"
        r"wbadmin[^\n]{0,20}delete\s+(catalog|systemstatebackup)|get-wmiobject[^\n]{0,30}win32_shadowcopy[^\n]{0,40}delete",
        "Suppression des copies de sauvegarde",
        ("T1490",),
        CRIT,
    ),
    _r(
        r"wevtutil[^\n]{0,10}\s(cl|clear-log)\s|clear-eventlog|remove-eventlog|limit-eventlog[^\n]{0,40}-maximumsize",
        "Effacement de journal",
        ("T1070.001",),
        CRIT,
    ),
    _r(
        r"amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext|amsi\.dll",
        "Contournement d'AMSI",
        ("T1562.001",),
        CRIT,
    ),
    _r(
        r"invoke-mimikatz|invoke-kerberoast|rubeus|sharphound|invoke-bloodhound|powerview|get-domainuser|"
        r"invoke-sharefinder|invoke-smbexec|invoke-wmiexec|invoke-thehash|powersploit|invoke-shellcode|"
        r"invoke-reflectivepeinjection|invoke-dcsync|get-gpppassword|invoke-portscan",
        "Outil offensif PowerShell",
        ("T1059.001",),
        CRIT,
    ),
    _r(
        r"(copy|move|xcopy)[^\n]{0,80}(cmd|powershell)\.exe[^\n]{0,80}(sethc|utilman|osk|magnify|narrator|displayswitch)\.exe",
        "Remplacement d'un outil d'accessibilité (porte dérobée d'ouverture de session)",
        ("T1546.008",),
        CRIT,
    ),
    _r(
        r"image\s+file\s+execution\s+options[^\n]{0,120}debugger",
        "Débogueur IFEO (détournement d'exécutable)",
        ("T1546.012",),
        CRIT,
    ),
    _r(
        r"set-mppreference[^\n]{0,80}(-disable\w+\s+(\$true|1)|-exclusion(path|process|extension))|"
        r"add-mppreference[^\n]{0,40}-exclusion|disableantispyware|sc(\.exe)?\s+(stop|delete|config)\s+windefend",
        "Neutralisation de Microsoft Defender",
        ("T1562.001",),
        HIGH,
    ),
    _r(
        r"auditpol[^\n]{0,40}(/clear|/remove|/disable|success:disable)",
        "Modification de la stratégie d'audit",
        ("T1562.002",),
        HIGH,
    ),
    _r(
        r"powershell[^\n]{0,80}\s-(e|en|enc|enco|encod|encode|encodedcommand)\s",
        "PowerShell encodé",
        ("T1027", "T1059.001"),
        HIGH,
    ),
    _r(
        r"(iex|invoke-expression)[\s(]|downloadstring|downloadfile|downloaddata|net\.webclient|"
        r"invoke-webrequest|\biwr\s|start-bitstransfer|invoke-restmethod",
        "PowerShell : téléchargement / exécution en mémoire",
        ("T1059.001", "T1105"),
        HIGH,
    ),
    _r(r"certutil[^\n]{0,60}(-urlcache|-decode|-verifyctl)", "certutil : téléchargement ou décodage", ("T1105", "T1140"), HIGH),
    _r(r"bitsadmin[^\n]{0,60}/(transfer|addfile|create)", "bitsadmin : téléchargement", ("T1197",), HIGH),
    _r(r"mshta[^\n]{0,40}(https?:|javascript:|vbscript:)", "mshta : script distant", ("T1218.005",), HIGH),
    _r(
        r"rundll32[^\n]{0,80}(javascript:|url\.dll[^\n]{0,40}(openurl|fileprotocolhandler)|shell32[^\n]{0,20}shellexec_rundll)",
        "rundll32 : exécution détournée",
        ("T1218.011",),
        HIGH,
    ),
    _r(r"regsvr32[^\n]{0,60}(/i:https?:|scrobj\.dll)", "regsvr32 : scriptlet distant (Squiblydoo)", ("T1218.010",), HIGH),
    _r(r"wmic[^\n]{0,80}(/node:|process\s+call\s+create)", "WMIC : exécution de processus (distante ?)", ("T1047",), HIGH),
    _r(r"\bnet1?(\.exe)?\s+user\s+\S+\s+\S+[^\n]{0,40}/add", "Création de compte (net user /add)", ("T1136.001",), HIGH),
    _r(
        r"\bnet1?(\.exe)?\s+(local)?group\s+\"?(administrat|admins du domaine|domain admins|enterprise admins|"
        r"remote desktop|utilisateurs du bureau)[^\n]{0,60}/add",
        "Ajout à un groupe privilégié (net group /add)",
        ("T1098",),
        HIGH,
    ),
    _r(
        r"reg(\.exe)?\s+add\s+[^\n]{0,80}\\currentversion\\(run|runonce)\b",
        "Clé Run ajoutée en ligne de commande",
        ("T1547.001",),
        HIGH,
    ),
    _r(
        r"psexec|paexec|\\\\[^\\\s]{1,64}\\(admin|c)\$",
        "Exécution distante par partage administratif (PsExec)",
        ("T1021.002", "T1569.002"),
        HIGH,
    ),
    _r(
        r"-w(indowstyle)?\s+h(idden)?\b|-ep?\s+bypass|-executionpolicy\s+bypass",
        "PowerShell caché / sans stratégie",
        ("T1059.001",),
        MED,
    ),
    _r(r"frombase64string", "Décodage Base64 en mémoire", ("T1140",), MED),
    _r(r"schtasks(\.exe)?\s+/create", "Création de tâche planifiée (schtasks)", ("T1053.005",), MED),
    _r(
        r"\bsc(\.exe)?\s+(\\\\\S+\s+)?(create|config)\s+[^\n]{0,80}binpath",
        "Création / modification de service (sc)",
        ("T1543.003",),
        MED,
    ),
    _r(r"fdenytsconnections[^\n]{0,40}\b0\b", "Activation du Bureau à distance", ("T1021.001",), MED),
    _r(r"nltest[^\n]{0,20}/(domain_trusts|dclist|all_trusts)|adfind", "Découverte des approbations de domaine", ("T1482",), LOW),
    _r(
        r"net1?(\.exe)?\s+group\s+\"?(domain admins|admins du domaine)\"?\s+/dom|dsquery|get-aduser[^\n]{0,30}-filter",
        "Découverte des comptes du domaine",
        ("T1087.002",),
        LOW,
    ),
]

# Filiation suspecte (Sysmon 1, 4688 Win10+) : (parent, enfant, libellé, techniques, gravité)
_OFFICE = r"\\(winword|excel|powerpnt|outlook|msaccess|mspub|onenote|visio)\.exe$"
_SHELLS = r"\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild|installutil)\.exe$"
PARENT_RULES: list[tuple[re.Pattern[str], re.Pattern[str], str, tuple[str, ...], str]] = [
    (
        re.compile(_OFFICE, re.I),
        re.compile(_SHELLS, re.I),
        "Document Office lançant un interpréteur (macro malveillante)",
        ("T1566.001", "T1204.002"),
        CRIT,
    ),
    (
        re.compile(r"\\(w3wp|httpd|nginx|tomcat\d*|php-cgi|sqlservr)\.exe$", re.I),
        re.compile(r"\\(cmd|powershell|pwsh|whoami|net1?|certutil)\.exe$", re.I),
        "Serveur web / SQL lançant un shell (webshell)",
        ("T1505.003",),
        CRIT,
    ),
    (
        re.compile(r"\\wmiprvse\.exe$", re.I),
        re.compile(r"\\(cmd|powershell|pwsh|mshta|rundll32)\.exe$", re.I),
        "WMI lançant un shell (exécution distante WMI)",
        ("T1047",),
        HIGH,
    ),
    (
        re.compile(r"\\wsmprovhost\.exe$", re.I),
        re.compile(r"\\(cmd|powershell|pwsh)\.exe$", re.I),
        "Session WinRM / PowerShell Remoting",
        ("T1021.006",),
        MED,
    ),
]

# Indices d'obfuscation dans un bloc de script (4104) : seuils au-delà d'un script d'administration
OBFUSCATION_MARKERS = (
    re.compile(r"\[char\]\s*\d{2,3}", re.I),
    re.compile(r"`[a-z]", re.I),
    re.compile(r"-bxor\s", re.I),
    re.compile(r"-join\s*\(?\s*['\"]", re.I),
    re.compile(r"\[string\]::join|\.replace\(\s*['\"].{1,3}['\"]\s*,\s*['\"]['\"]\s*\)", re.I),
)
OBFUSCATION_THRESHOLD = 20  # occurrences cumulées des marqueurs

# Registre (Sysmon 12/13/14) : (motif sur TargetObject, libellé, techniques, gravité)
REGISTRY_RULES: list[Rule] = [
    _r(r"\\image file execution options\\[^\\]{1,260}\\debugger$", "Débogueur IFEO", ("T1546.012",), CRIT),
    _r(r"\\silentprocessexit\\[^\\]{1,260}\\monitorprocess$", "Surveillance de fin de processus (IFEO)", ("T1546.012",), HIGH),
    _r(r"\\windows nt\\currentversion\\winlogon\\(userinit|shell)$", "Winlogon Userinit/Shell modifié", ("T1547.004",), HIGH),
    _r(r"\\windows nt\\currentversion\\windows\\appinit_dlls$", "AppInit_DLLs modifié", ("T1546.010",), HIGH),
    _r(
        r"\\currentversion\\(run|runonce|runservices|runservicesonce|policies\\explorer\\run)\\",
        "Clé de démarrage modifiée",
        ("T1547.001",),
        HIGH,
    ),
    _r(
        r"\\control\\lsa\\(security packages|authentication packages|notification packages)$",
        "Paquet LSA ajouté",
        ("T1547.005",),
        HIGH,
    ),
    _r(
        r"\\control\\securityproviders\\wdigest\\uselogoncredential$",
        "WDigest réactivé (mots de passe en clair)",
        ("T1112",),
        HIGH,
    ),
    _r(r"\\microsoft\\netsh\\", "DLL d'assistance netsh", ("T1546.007",), HIGH),
    _r(
        r"\\windows defender\\(exclusions\\|.{0,60}(disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring)$)",
        "Microsoft Defender affaibli",
        ("T1562.001",),
        HIGH,
    ),
    _r(
        r"^hk(u|cu)\\[^\n]{0,120}\\classes\\clsid\\[^\\]{1,60}\\(inprocserver32|localserver32)\\",
        "Détournement COM (HKCU)",
        ("T1546.015",),
        MED,
    ),
    _r(r"\\terminal server\\fdenytsconnections$", "Bureau à distance activé", ("T1021.001",), MED),
]

# Requêtes DNS (Sysmon 22) vers des services prisés des attaquants
DNS_RULES: list[Rule] = [
    _r(
        r"(^|\.)(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|serveo\.net|localhost\.run|loca\.lt)$",
        "Tunnel public",
        ("T1572",),
        HIGH,
    ),
    _r(
        r"(^|\.)(pastebin\.com|paste\.ee|transfer\.sh|temp\.sh|file\.io|anonfiles\.com|gofile\.io|mega\.nz|ghostbin\.\w+)$",
        "Service de partage / exfiltration",
        ("T1567",),
        MED,
    ),
    _r(
        r"(^|\.)(duckdns\.org|no-ip\.(com|org|biz)|ddns\.net|hopto\.org|dynu\.net|freedns\.afraid\.org)$",
        "DNS dynamique",
        ("T1568",),
        MED,
    ),
]

# Services et binaires caractéristiques d'outils d'exécution distante (Impacket, PsExec, Metasploit)
REMOTE_EXEC_SERVICE = re.compile(
    r"psexesvc|paexec|remcom|csexec|\\\\127\.0\.0\.1\\admin\$|%comspec%\s*/q\s*/c\s*echo|\\admin\$\\[^\\]{1,40}\.exe",
    re.I,
)
SUSPICIOUS_PATH = re.compile(
    r"(cmd(\.exe)?\s*/c|powershell|%comspec%|\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\|"
    r"\\perflogs\\|\\windows\\tasks\\|\\\$recycle\.bin\\|mshta|rundll32|regsvr32|\.bat\b|\.ps1\b|\.vbs\b|\.hta\b)",
    re.I,
)
EXECUTABLE_EXT = re.compile(r"\.(exe|dll|scr|ps1|bat|cmd|vbs|js|hta|jar|msi)$", re.I)
STARTUP_FOLDER = re.compile(r"\\start menu\\programs\\startup\\", re.I)
LSASS_DUMP_FILE = re.compile(r"lsass[^\\]{0,40}\.(dmp|zip)$|\\(lsass|debug)\.dmp$", re.I)

# Sysmon 10 : droits d'accès à LSASS typiques des outils de vol d'identifiants (MITRE CAR-2019-04-004)
LSASS_ACCESS_MASKS = {"0x1010", "0x1410", "0x1418", "0x1438", "0x143a", "0x1fffff", "0x1f3fff", "0x1f1fff", "0x40"}
LSASS_BENIGN_SOURCES = re.compile(
    r"\\(wininit|csrss|lsm|msmpeng|mssense|sensecncproxy|wmiprvse|taskmgr|vmtoolsd|svchost)\.exe$|"
    r"\\program files( \(x86\))?\\(windows defender|microsoft security client)\\",
    re.I,
)
DUMP_CALLTRACE = re.compile(r"dbghelp\.dll|dbgcore\.dll", re.I)

# Kerberos : RC4 (0x17) et chiffrements faibles hérités
WEAK_KERBEROS_ETYPES = {"0x17", "0x18"}
# DCSync (4662) : droits de réplication DS-Replication-Get-Changes(-All / -In-Filtered-Set)
REPLICATION_GUIDS = (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c",
)
CONTROL_ACCESS_MASK = "0x100"

# Groupes privilégiés : SID bien connus (local) et RID de domaine
PRIVILEGED_LOCAL_SIDS = {"S-1-5-32-544", "S-1-5-32-555", "S-1-5-32-551", "S-1-5-32-548", "S-1-5-32-549"}
PRIVILEGED_DOMAIN_RIDS = ("-512", "-518", "-519", "-520")  # Domain/Schema/Enterprise Admins, GPO creators

# Comptes intégrés désactivés par défaut : leur réactivation est un indicateur classique
DEFAULT_DISABLED_RIDS = ("-501", "-503")  # Invité, DefaultAccount
