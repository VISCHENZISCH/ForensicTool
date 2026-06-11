"""
ui.py - Systeme de design terminal pur ANSI pour Forensic Analyzer.
Style hacker : double-lignes rouges, titres vert hacker et valeurs rouge hacker.
"""
from __future__ import annotations

import os
import shutil
import textwrap

# Codes couleur ANSI

# Constantes de couleurs ANSI 256 de WebMapper
CRIMSON   = "\033[38;5;196m"
EMERALD   = "\033[38;5;46m"
GOLD      = "\033[38;5;220m"
SKY_BLUE  = "\033[38;5;39m"
PURPLE    = "\033[38;5;141m"
MAGENTA   = "\033[38;5;201m"
DARK_GREY = "\033[38;5;243m"
# Le blanc a été intégralement supprimé pour le thème Matrix

class C:
    """Palette de couleurs sémantiques propres."""
    # Couleurs Sémantiques Spécifiques
    C_IP       = "\033[38;5;39m"   # Bleu ciel pour IPs
    C_MAC      = "\033[38;5;141m"  # Violet clair pour MACs
    C_HOST     = "\033[38;5;220m"  # Or/Jaune pour Hostnames
    C_USER     = "\033[38;5;208m"  # Orange pour Utilisateurs
    C_DNS      = "\033[38;5;75m"   # Bleu indigo pour DNS/URLs
    C_PARAM    = "\033[38;5;45m"   # Cyan/Vert pour Paramètres/Clés
    C_RESULT   = "\033[38;5;253m"  # Blanc/Gris clair pour Résultats
    C_DANGER   = "\033[38;5;196m"  # Rouge vif pour Alertes/Malwares
    C_STRUCT   = "\033[38;5;239m"  # Gris sombre pour Structure
    
    # Matrix Colors (Pour la bannière historique)
    MG1 = "\033[38;5;22m"  # Très sombre
    MG2 = "\033[38;5;28m"  # Sombre
    MG3 = "\033[38;5;34m"  # Hacker Green
    MG4 = "\033[38;5;40m"  # Vert clair
    MG5 = "\033[38;5;46m"  # Émeraude vif
    MG6 = "\033[38;5;118m" # Vert-Jaune intense

    # Couleurs de base existantes (pour compatibilité)
    R   = C_STRUCT
    G   = "\033[38;5;46m"
    Y   = "\033[38;5;226m"
    B   = "\033[38;5;33m"
    VB  = "\033[38;5;45m"
    M   = "\033[38;5;201m"
    P   = "\033[38;5;141m"
    W   = "\033[38;5;253m"
    D   = "\033[38;5;244m"
    HR  = C_DANGER
    HY  = Y

    BD  = "\033[1m"
    RS  = "\033[0m"


def c(color: str, text: str = "", bold: bool = False) -> str:
    """Applique une couleur ANSI à un texte."""
    return f"{C.BD if bold else ''}{color}{text}{C.RS if text else ''}"


# Marge vide car deleguee au wrapper sys.stdout global
MARGIN = ""


def _width() -> int:
    """Largeur du terminal, capped a 80."""
    try:
        return min(shutil.get_terminal_size().columns, 80)
    except Exception as exc:
        pass  # TODO: log.debug(exc)
        return 80


def clear_screen() -> None:
    """Efface completement le terminal."""
    os.system('cls' if os.name == 'nt' else 'clear')


# Banniere ASCII Art

BANNER = f"""
{c(C.MG1, "0 1 ▓█████   ▒█████ 1 ██▀███  ▓█████ 0███▄    █   ██████  ██▓ ▄████▄ 1", bold=True)}
{c(C.MG2, " 1  ▓█   ▀ 0▒██▒  ██▒▓██ ▒ ██▒▓█   ▀ 1██ ▀█   █ ▒██    ▒ ▓██▒▒██▀ ▀█ 0", bold=True)}
{c(C.MG3, " 01 ▒███  1 ▒██░  ██▒▓██ ░▄█ ▒▒███  0▓██  ▀█ ██▒░ ▓██▄ 1 ▒██▒▒▓█    ▄ ", bold=True)}
{c(C.MG4, " 1  ▒▓█     ▒██   ██░▒██▀▀█▄ 1▒▓█  ▄ ▓██▒ 0▐▌██▒ 1▒   ██▒░██░▒▓▓▄ ▄██0", bold=True)}
{c(C.MG5, "0 1 ░▒█ █▒ 1░ ████▓▒░░██▓ ▒██▒░▒████▒▒██░ 0 ▓██░▒██████▒▒░██░▒ ▓███▀ 1", bold=True)}
{c(C.MG6, " 10 ░░ ▒░ ░ ░ ▒░▒░▒░ 0 ▒▓ ░▒▓░░░ ▒░ ░░ ▒░ 1 ▒ ▒ ▒ ▒▓▒ ▒ ░░▓ 0░ ░▒ ▒ 0 ", bold=True)}
{c(C.MG5, "0    ░ ░  ░   ░ ▒ ▒░   ░▒ ░ ▒░ ░ ░  ░░ ░░ 0 ░ ▒░░ ░▒  ░ ░ ▒ ░  ░  ▒  1", bold=True)}
{c(C.MG4, " 1 0   ░  1 ░ ░ ░ ▒ 0  ░░   ░ 1  ░  0   ░ 1 ░ ░ ░  ░  ░ 1 ▒ ░░  0 1 ", bold=True)}
{c(C.MG3, "  0 1  ░  ░   0 ░ ░  1  ░   0    ░  ░    1    ░    1  ░   ░  ░ 0  1   ", bold=True)}
{c(C.MG1, "  0x4A 0x7F FF AF EB C3 0x00 0F EAX RAX rbp rip rcx rsp EIP rdi rsi r8", bold=True)}
{c(C.MG2, "  jmp push pop ret xor test cmp mov lea call syscall nop hlt out in 00", bold=True)}
"""

def banner() -> None:
    """Efface l'ecran et affiche le bandeau principal."""
    clear_screen()
    for line in BANNER.split("\n"):
        print(f"{MARGIN}{line}")

    print(f"{MARGIN}                      {c(C.HY, '© 2026 Félix TOVIGNAN')}")
    print(f"{MARGIN}         {c(C.G, 'https://github.com/VISCHENZISCH/ForensicTool.git')}")
    print()

    print(f"{MARGIN}  {c(C.W, 'usage Linux :', bold=True)} {c(C.D, './run.sh --help')}")
    print(f"{MARGIN}  {c(C.W, 'usage Win   :', bold=True)} {c(C.D, '.\\\\run.ps1 --help')}")
    print(f"{MARGIN}  {c(C.W, 'exemple     :', bold=True)} {c(C.D, '$')} {c(C.G, './run.sh')} {c(C.Y, '--scan ./evidence')} {c(C.VB, '--export-html rapport.html')}")
  



# Menu principal

def menu() -> None:
    """Affiche le menu interactif complet avec double-lignes rouges."""
    w = _width()
    # Separateur en rouge
    #sep = f"{C.R}{'-' * (w - 8)}{C.RS}"

    #print(f"\n{MARGIN}{sep}")
    print()

    # Colonnes : gauche et droite
    left = [
        (f"{C.VB}{C.BD}Analyse Fichiers{C.RS}", None),
        (f" {C.G}[01]{C.RS} {C.W}PDF - Metadonnees{C.RS}", None),
        (f" {C.G}[02]{C.RS} {C.W}Image / EXIF{C.RS}", None),
        (f" {C.G}[03]{C.RS} {C.W}Coordonnees GPS{C.RS}", None),
        (f" {C.G}[04]{C.RS} {C.W}Extraction Strings{C.RS}", None),
        (f" {C.G}[05]{C.RS} {C.W}Historique Firefox{C.RS}", None),
        (f" {C.G}[06]{C.RS} {C.W}Cookies Firefox{C.RS}", None),
        (f" {C.G}[07]{C.RS} {C.W}Artefacts Chromium{C.RS}", None),
        ("", None),
        (f"{C.VB}{C.BD}Analyse Avancée{C.RS}", None),
        (f" {C.G}[08]{C.RS} {C.W}Steganographie{C.RS}", None),
        (f" {C.G}[09]{C.RS} {C.W}File Carving{C.RS}", None),
        (f" {C.G}[10]{C.RS} {C.W}Analyse PCAP{C.RS}", None),
        (f" {C.G}[11]{C.RS} {C.W}Triage Malware (PE){C.RS}", None),
    ]

    right = [
        (f"{C.VB}{C.BD}Analyse Système{C.RS}", None),
        (f" {C.G}[12]{C.RS} {C.W}Windows Event Logs{C.RS}", None),
        (f" {C.G}[13]{C.RS} {C.W}Registre Windows{C.RS}", None),
        (f" {C.G}[14]{C.RS} {C.W}Artefacts Linux{C.RS}", None),
        (f" {C.G}[15]{C.RS} {C.W}Analyse Memoire{C.RS}", None),
        (f" {C.G}[16]{C.RS} {C.W}Forensique Disque{C.RS}", None),
        (f" {C.G}[17]{C.RS} {C.W}Exécution Windows{C.RS}", None),
        ("", None),
        (f"{C.VB}{C.BD}Threat Hunting{C.RS}", None),
        (f" {C.G}[18]{C.RS} {C.W}Scan YARA{C.RS}", None),
        (f" {C.G}[19]{C.RS} {C.W}Extraction IOC{C.RS}", None),
        (f" {C.G}[20]{C.RS} {C.W}Timeline DFIR{C.RS}", None),
        ("", None),
        ("", None),
    ]

    col_w = (w - 12) // 2
    for l_line, r_line in zip(left, right):
        l_text = l_line[0]
        r_text = r_line[0]
        l_visible = _strip_ansi(l_text)
        pad = col_w - len(l_visible)
        if pad < 0:
            pad = 2
        print(f"{MARGIN}   {l_text}{' ' * pad}{r_text}")

    print()
    print(f"{MARGIN}   {C.VB}{C.BD}Outils{C.RS}")
    print(f"{MARGIN}    {C.Y}[88]{C.RS} {C.W}Scan Automatique{C.RS}")
    print(f"{MARGIN}    {C.Y}[99]{C.RS} {C.W}Exporter Rapport{C.RS}")
    print(f"{MARGIN}    {C.R}[00]{C.RS} {C.W}Quitter{C.RS}")
    print()


def export_menu() -> None:
    """Affiche le sous-menu d'export avec double-lignes rouges."""
    print()
    print(f"{MARGIN}   {C.VB}{C.BD}Export{C.RS}")
    print(f"{MARGIN}    {C.G}[J]{C.RS}  {C.W}Export JSON{C.RS}")
    print(f"{MARGIN}    {C.G}[H]{C.RS}  {C.W}Export HTML (interactif){C.RS}")
    print(f"{MARGIN}    {C.G}[C]{C.RS}  {C.W}Export CSV Timeline{C.RS}")
    print(f"{MARGIN}    {C.G}[P]{C.RS}  {C.W}Export PDF{C.RS}")
    print(f"{MARGIN}    {C.D}[R]{C.RS}  {C.W}Retour{C.RS}")
    print()


# Prompt

def prompt(label: str = "forensic-analyzer") -> str:
    """Affiche le prompt style hacker ┌─[forensic-analyzer]─[label] └──╼ $"""
    try:
        line1 = (
            f"{MARGIN}"
            f"{C.R}┌─[{C.RS}"
            f"{C.HR}{C.BD}forensic-analyzer{C.RS}"
            f"{C.R}]─[{C.RS}"
            f"{C.HR}{label}{C.RS}"
            f"{C.R}]{C.RS}"
        )
        line2 = f"{MARGIN}{C.R}└──╼{C.RS} {C.W}${C.RS} {C.MG4}"
        print(line1)
        res = input(line2).strip()
        print(C.RS, end="") # Reset couleur après la saisie
        return res
    except (EOFError, KeyboardInterrupt):
        return ""


def prompt_file(label: str) -> str | None:
    """Demande un chemin de fichier avec validation."""
    while True:
        print(f"\n{MARGIN}{C.VB}[?]{C.RS} {C.W}{label}{C.RS}")
        path = prompt("path")
        if not path:
            return None
        path = os.path.expanduser(path)
        if os.path.exists(path):
            return os.path.abspath(path)
        error(f"Chemin introuvable : {path}")
        info("Reessayez ou laissez vide pour annuler.")


def prompt_input(label: str, required: bool = True) -> str | None:
    """Demande une saisie simple."""
    while True:
        print(f"\n{MARGIN}{C.VB}[?]{C.RS} {C.W}{label}{C.RS}")
        val = prompt("input")
        if val:
            return val
        if not required:
            return None
        error("Champ requis.")


# Messages

def info(msg: str) -> None:
    print(f"{MARGIN}{C.VB}[*]{C.RS} {C.W}{msg}{C.RS}")


def success(msg: str) -> None:
    print(f"{MARGIN}{C.G}[+]{C.RS} {C.G}{msg}{C.RS}")


def warning(msg: str) -> None:
    print(f"{MARGIN}{C.HY}[!]{C.RS} {C.HY}{msg}{C.RS}")


def error(msg: str) -> None:
    print(f"{MARGIN}{C.HR}[-]{C.RS} {C.HR}{msg}{C.RS}")


def status(msg: str) -> None:
    print(f"{MARGIN}{C.D}[~]{C.RS} {C.D}{msg}{C.RS}")


# Affichage des resultats

MODULE_TAGS = {
    "pdf": "PDF", "pdf_analysis": "PDF", "image": "IMG", "gps": "GPS", "strings": "STR",
    "firefox_history": "FHX", "firefox_cookies": "FCK",
    "stego": "SGO", "carving": "CRV", "pcap": "NET", "memory": "MEM",
    "disk": "DSK", "evtx": "EVT", "registry": "REG",
    "linux_artifacts": "LNX", "yara": "YRA", "ioc": "IOC", "timeline": "TML",
    "pe_analysis": "MAL", "malware_analysis": "MAL", "chromium_artifacts": "WEB", 
    "prefetch": "PF", "lnk_shortcut": "LNK"
}

MODULE_NAMES = {
    "pdf": "Analyse PDF", "pdf_analysis": "Analyse PDF", "image": "Analyse Image / EXIF",
    "gps": "Coordonnees GPS", "strings": "Extraction Strings",
    "firefox_history": "Historique Firefox", "firefox_cookies": "Cookies Firefox",
    "stego": "Steganographie", "carving": "File Carving",
    "pcap": "Analyse Reseau PCAP", "memory": "Analyse Memoire",
    "disk": "Forensique Disque", "evtx": "Windows Event Logs",
    "registry": "Registre Windows", "linux_artifacts": "Artefacts Linux",
    "yara": "Scan YARA", "ioc": "Extraction IOC", "timeline": "Timeline DFIR",
    "pe_analysis": "Triage Malware (PE)", "malware_analysis": "Triage Malware (PE)", "chromium_artifacts": "Artefacts Chromium",
    "prefetch": "Execution (Prefetch)", "lnk_shortcut": "Raccourci Windows (LNK)"
}

MODULE_COLORS = {
    "pdf": C.R, "pdf_analysis": C.R, "image": C.Y, "gps": C.B, "strings": C.D,
    "firefox_history": C.M, "firefox_cookies": C.P,
    "stego": "\033[38;5;198m", "carving": "\033[38;5;208m", 
    "pcap": C.VB, "memory": "\033[38;5;111m",
    "disk": "\033[38;5;240m", "evtx": "\033[38;5;45m", "registry": "\033[38;5;99m",
    "linux_artifacts": "\033[38;5;214m", "yara": C.HR, "ioc": C.HR, "timeline": C.G,
    "pe_analysis": "\033[38;5;160m", "malware_analysis": "\033[38;5;160m", "chromium_artifacts": "\033[38;5;33m", 
    "prefetch": "\033[38;5;184m", "lnk_shortcut": "\033[38;5;136m"
}

def separator(label: str = "", dynamic_width: int = 0, custom_color: str = C.G) -> None:
    """Separateur double-ligne style hacker avec taille fixe de 85."""
    target_width = 85
    if label:
        text = f" {custom_color}{label}{C.RS} "
        label_len = len(_strip_ansi(text))
        rem = target_width - label_len
        left = rem // 2
        right = rem - left
        print(f"{MARGIN}{C.R}{'═' * left}{C.RS}{text}{C.R}{'═' * right}{C.RS}")
    else:
        print(f"{MARGIN}{C.R}{'═' * target_width}{C.RS}")


def finding_header(finding_type: str, filename: str, dynamic_width: int = 0) -> None:
    """Affiche l'entete d'un finding."""
    tag = MODULE_TAGS.get(finding_type, "???")
    name = MODULE_NAMES.get(finding_type, finding_type)
    color = MODULE_COLORS.get(finding_type, C.G)
    print()
    separator(f"{tag} | {name}", custom_color=color)
    print(f"{MARGIN}   {color}Fichier                      {C.HY}:{C.RS} {C.W}{filename}{C.RS}")
    print()


def kv(key: str, value, indent: int = 3) -> None:
    """Affiche une paire cle-valeur en appliquant un retour a la ligne si besoin."""
    pad = " " * indent
    val_str = str(value)

    offset = indent + 1 + 28 + 3
    wrap_width = 85 - offset
    if wrap_width < 10:
        wrap_width = 50

    lines = textwrap.wrap(val_str, width=wrap_width)
    if not lines:
        lines = [""]

    import re
    def colorize(t):
        t = re.sub(r'\[([^\]]+)\]', f'[{C.C_DNS}\\1{C.C_RESULT}]', t)
        t = re.sub(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', f'{C.C_IP}\\1{C.C_RESULT}', t)
        t = re.sub(r'\((\d+)\)', f'{C.C_STRUCT}({C.C_USER}\\1{C.C_STRUCT}){C.C_RESULT}', t)
        return t

    key_display = f"{C.C_PARAM}{key:<28}{C.RS}"
    c_line0 = colorize(lines[0])
    print(f"{MARGIN}{pad} {key_display} {C.C_STRUCT}:{C.RS} {C.C_RESULT}{c_line0}{C.RS}")
    
    for line in lines[1:]:
        c_line = colorize(line)
        print(f"{MARGIN}{' ' * offset}{C.C_RESULT}{c_line}{C.RS}")


def render_finding(finding) -> None:
    """Rendu complet d'un finding dans le terminal."""
    fname = os.path.basename(finding.file)
    finding_header(finding.type, fname)

    # Metadonnees
    for k, v in finding.metadata.items():
        kv(k, v)

    # Extras selon le type
    extra = finding.extra or {}

    if finding.type == "strings" and "strings" in extra:
        strings = extra["strings"]
        print()
        separator("Chaines extraites")
        for i, s in enumerate(strings, 1):
            print(f"{MARGIN}    {C.D}{i:>4}.{C.RS} {C.W}{s}{C.RS}")

    elif finding.type == "firefox_history" and "entries" in extra:
        entries = extra["entries"]
        if entries:
            print()
            separator("Historique")
            for e in entries:
                date = e.get("date", "?")
                url = e.get("url", "")
                print(f"{MARGIN}    {C.D}{date:<22}{C.RS} {C.C_DNS}{url}{C.RS}")

    elif finding.type == "yara" and "matches" in extra:
        matches = extra["matches"]
        if matches:
            print()
            separator("Correspondances YARA")
            for rule in matches:
                print(f"{MARGIN}    {C.HR}[!]{C.RS} {C.W}{rule}{C.RS}")

    elif finding.type == "pe_analysis":
        if "sections_pe" in extra and extra["sections_pe"]:
            print()
            separator("Sections PE")
            for sec in extra["sections_pe"]:
                name = sec.get("Nom", "")
                ent = sec.get("Entropie", "")
                size = sec.get("Taille Virtuelle", 0)
                color = C.HR if "CRITIQUE" in ent else C.G
                print(f"{MARGIN}    {color}{name:<10}{C.RS} {C.HY}Entropie:{C.RS} {C.W}{ent:<15}{C.RS} {C.HY}Taille:{C.RS} {C.W}{size}{C.RS}")
        if "dll_imports" in extra and extra["dll_imports"]:
            print()
            separator("Imports DLL")
            for dll in extra["dll_imports"]:
                print(f"{MARGIN}    {C.G}DLL{C.HY}:{C.RS} {C.W}{dll}{C.RS}")

    elif finding.type == "chromium_artifacts":
        if "chromium_downloads" in extra and extra["chromium_downloads"]:
            print()
            separator("Téléchargements")
            for d in extra["chromium_downloads"]:
                color = C.HR if d.get('danger_type') else C.G
                fname = str(d.get('fichier', ''))[:50]
                print(f"{MARGIN}    {color}{fname:<50}{C.RS} {C.HY}Taille:{C.RS} {C.W}{d.get('taille_octets', 0)}{C.RS}")
        if "chromium_urls" in extra and extra["chromium_urls"]:
            print()
            separator("Historique URLs")
            for u in extra["chromium_urls"]:
                url = str(u.get('url', ''))[:65]
                print(f"{MARGIN}    {C.VB}{u.get('visites', 0):>4}x{C.RS} {C.C_DNS}{url}{C.RS}")

    elif finding.type == "firefox_cookies" and "entries" in extra:
        entries = extra["entries"]
        if entries:
            print()
            separator("Cookies")
            for e in entries:
                name = e.get("name", "")
                host = e.get("host", "")
                val = e.get("value", "")[:40]
                print(f"{MARGIN}    {C.C_PARAM}{name}{C.RS} {C.C_STRUCT}@{C.RS} {C.C_HOST}{host:<30}{C.RS} {C.C_RESULT}{val}{C.RS}")

    elif finding.type == "pcap":
        creds = extra.get("credentials", [])
        if creds:
            print()
            separator("Credentials detectes")
            for c_item in creds:
                proto = c_item.get("protocol", "?")
                data = c_item.get("data", c_item.get("user", str(c_item)))
                print(f"{MARGIN}    {C.G}{proto:<14}{C.RS} {C.W}{data}{C.RS}")
                
        hosts = extra.get("host_identities", {})
        if hosts:
            print()
            separator("Hotes / Identites")
            # If hosts is a dict (IP -> details)
            if isinstance(hosts, dict):
                for ip, h in list(hosts.items()):
                    macs = ", ".join(h.get("mac", []))
                    names = ", ".join(h.get("hostnames", []))
                    users = ", ".join(h.get("users", []))
                    print(f"{MARGIN}    {C.C_IP}{ip:<15}{C.RS} {C.C_MAC}{macs:<18}{C.RS} {C.C_HOST}{names:<20}{C.RS} {C.C_USER}{users}{C.RS}")
            else:
                for h in hosts:
                    ip = h.get("ip", "?")
                    mac = h.get("mac", "?")
                    name = h.get("hostname", "?")
                    user = h.get("user", "")
                    print(f"{MARGIN}    {C.C_IP}{ip:<15}{C.RS} {C.C_MAC}{mac:<18}{C.RS} {C.C_HOST}{name:<20}{C.RS} {C.C_USER}{user}{C.RS}")

        ua_list = extra.get("user_agents", [])
        if ua_list:
            print()
            separator("User-Agents suspects (Top 10)")
            suspects = [ua for ua in ua_list if "Windows NT" not in ua.get("user_agent", "") and "Macintosh" not in ua.get("user_agent", "")]
            for ua in suspects:
                print(f"{MARGIN}    {C.C_DANGER}[!]{C.RS} {C.C_RESULT}{ua.get('user_agent', '')[:75]}{C.RS}")

    elif finding.type == "ioc" and "iocs" in extra:
        iocs = extra["iocs"]
        if isinstance(iocs, dict):
            print()
            separator("IOC detectes")
            for ioc_type, items in iocs.items():
                for item in (items if isinstance(items, list) else [items]):
                    print(f"{MARGIN}    {C.G}{ioc_type:<14}{C.RS} {C.W}{item}{C.RS}")

    elif finding.type == "timeline" and "events" in extra:
        events = extra["events"]
        if events:
            print()
            separator("Timeline")
            for e in events:
                ts = e.get("timestamp", "?")
                src = e.get("source", "")
                detail = e.get("detail", "")[:50]
                print(f"{MARGIN}    {C.D}{ts:<26}{C.RS} {C.G}{src:<6}{C.RS} {C.W}{detail}{C.RS}")

    elif finding.type in ("carving", "stego"):
        for extra_key in ("embedded_files", "polyglots", "lsb_data", "matches"):
            items = extra.get(extra_key)
            if items and isinstance(items, list):
                print()
                separator(extra_key.replace("_", " ").title())
                for item in items:
                    if isinstance(item, dict):
                        for ik, iv in item.items():
                            print(f"{MARGIN}    {C.G}{ik:<20}{C.RS} {C.W}{str(iv)[:60]}{C.RS}")
                    else:
                        print(f"{MARGIN}    {C.W}{item}{C.RS}")

    print()


def render_summary(report) -> None:
    """Affiche le resume final de la session."""
    n = report.total
    if n == 0:
        warning("Aucun resultat trouve.")
        return

    type_counts: dict[str, int] = {}
    for f in report.findings:
        type_counts[f.type] = type_counts.get(f.type, 0) + 1

    print()
    separator("STATISTIQUES")
    print()

    for ftype, count in sorted(type_counts.items()):
        tag = MODULE_TAGS.get(ftype, "???")
        name = MODULE_NAMES.get(ftype, ftype)
        print(f"{MARGIN}    {C.VB}[{tag}]{C.RS} {C.W}{C.BD}{count:<4}{C.RS} {C.G}{name}{C.RS}")

    print()
    print(f"{MARGIN}{C.G}[+]{C.RS} {C.W}{n} resultat{'s' if n > 1 else ''}{C.RS}  {C.D}|{C.RS}  {C.D}{report.timestamp}{C.RS}")
    print()


# Utilitaire interne


def _strip_ansi(text: str) -> str:
    """Supprime les codes ANSI pour calculer la longueur visible."""
    import re
    return re.sub(r'\033\[[0-9;]*m', '', text)


def wait_for_key() -> None:
    """Attend que l'utilisateur appuie sur Entree."""
    try:
        print()
        input(f"{MARGIN}{C.D}[Appuyez sur Entree pour continuer]{C.MG4}")
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        print(C.RS, end="")
