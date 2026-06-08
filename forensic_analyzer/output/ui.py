"""
ui.py - Systeme de design terminal pur ANSI pour Forensic Analyzer.
Style hacker : double-lignes rouges, titres vert hacker et valeurs rouge hacker.
"""
from __future__ import annotations
import os
import shutil


# Codes couleur ANSI

# Constantes de couleurs ANSI 256 de WebMapper
CRIMSON   = "\033[38;5;196m"
EMERALD   = "\033[38;5;46m"
GOLD      = "\033[38;5;220m"
SKY_BLUE  = "\033[38;5;39m"
PURPLE    = "\033[38;5;141m"
MAGENTA   = "\033[38;5;201m"
DARK_GREY = "\033[38;5;243m"
WHITE     = "\033[97m"

class C:
    """Palette premium de WebMapper."""
    R   = CRIMSON
    G   = EMERALD
    Y   = GOLD
    B   = SKY_BLUE
    VB  = SKY_BLUE
    M   = MAGENTA
    P   = PURPLE
    W   = WHITE
    D   = DARK_GREY
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
    except Exception:
        return 80


def clear_screen() -> None:
    """Efface completement le terminal."""
    os.system('cls' if os.name == 'nt' else 'clear')


# Banniere ASCII Art

BANNER = f"""
{c(SKY_BLUE, bold=True)}{c(C.RS)}{c(MAGENTA, "    ______ ____   ____   ______ _   __ _____  ____ ______  ", bold=True)}
{c(SKY_BLUE, bold=True)}{c(C.RS)}{c(MAGENTA, "   / ____// __ \\ / __ \\ / ____// | / // ___/ /  _// ____/ ", bold=True)}
{c(SKY_BLUE, bold=True)}{c(C.RS)}{c(PURPLE,  "  / /_   / / / // /_/ // /_   /  |/ / \\__ \\  / / / /      ", bold=True)}
{c(SKY_BLUE, bold=True)}{c(C.RS)}{c(PURPLE,  " / __/  / /_/ // _, _// /___ / /|  / ___/ /_/ / / /___    ", bold=True)}
{c(SKY_BLUE, bold=True)}{c(C.RS)}{c(SKY_BLUE,"/_/     \\____//_/ |_|/_____//_/ |_|/____//___/ \\____/    ", bold=True)}
"""

def banner() -> None:
    """Efface l'ecran et affiche le bandeau principal."""
    clear_screen()
    for line in BANNER.split("\n"):
        print(f"{MARGIN}{line}")

    print(f"{MARGIN}                                © 2026 Félix TOVIGNAN")
    print(f"{MARGIN}                      https://github.com/VISCHENZISCH/ForensicTool.git")
    print()

    # Usage & options
    print(f"{MARGIN}  {c(C.W, 'usage:', bold=True)} {c(C.D, './run.sh --help')}")
    print(f"{MARGIN}  {c(C.W, 'exemple :', bold=True)} {c(C.D, '$')} {c(C.G, 'python3 main.py')} {c(C.Y, '--scan ./evidence')} {c(C.VB, '--export-html rapport.html')}")
  



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
        (f" {C.G}[01]{C.RS} PDF - Metadonnees", None),
        (f" {C.G}[02]{C.RS} Image / EXIF", None),
        (f" {C.G}[03]{C.RS} Coordonnees GPS", None),
        (f" {C.G}[04]{C.RS} Extraction Strings", None),
        (f" {C.G}[05]{C.RS} Historique Firefox", None),
        (f" {C.G}[06]{C.RS} Cookies Firefox", None),
        ("", None),
        (f"{C.VB}{C.BD}Analyse Avancée{C.RS}", None),
        (f" {C.G}[07]{C.RS} Steganographie", None),
        (f" {C.G}[08]{C.RS} File Carving", None),
        (f" {C.G}[09]{C.RS} Analyse PCAP", None),
    ]

    right = [
        (f"{C.VB}{C.BD}Analyse Système{C.RS}", None),
        (f" {C.G}[10]{C.RS} Windows Event Logs", None),
        (f" {C.G}[11]{C.RS} Registre Windows", None),
        (f" {C.G}[12]{C.RS} Artefacts Linux", None),
        (f" {C.G}[13]{C.RS} Analyse Memoire", None),
        (f" {C.G}[14]{C.RS} Forensique Disque", None),
        ("", None),
        (f"{C.VB}{C.BD}Threat Hunting{C.RS}", None),
        (f" {C.G}[15]{C.RS} Scan YARA", None),
        (f" {C.G}[16]{C.RS} Extraction IOC", None),
        (f" {C.G}[17]{C.RS} Timeline DFIR", None),
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
    print(f"{MARGIN}    {C.Y}[88]{C.RS} Scan Automatique")
    print(f"{MARGIN}    {C.Y}[99]{C.RS} Exporter Rapport")
    print(f"{MARGIN}    {C.R}[00]{C.RS} Quitter")
    print()


def export_menu() -> None:
    """Affiche le sous-menu d'export avec double-lignes rouges."""
    print()
    print(f"{MARGIN}   {C.VB}{C.BD}Export{C.RS}")
    print(f"{MARGIN}    {C.G}[J]{C.RS}  Export JSON")
    print(f"{MARGIN}    {C.G}[H]{C.RS}  Export HTML (interactif)")
    print(f"{MARGIN}    {C.G}[C]{C.RS}  Export CSV Timeline")
    print(f"{MARGIN}    {C.G}[P]{C.RS}  Export PDF")
    print(f"{MARGIN}    {C.D}[R]{C.RS}  Retour")
    print()


# Prompt

def prompt(label: str = "forensic-analyzer") -> str:
    """Affiche le prompt style hacker ┌─[forensic-analyzer]─[label] └──╼ $"""
    try:
        line1 = (
            f"{MARGIN}"
            f"{C.R}┌─[{C.RS}"
            f"{C.VB}{C.BD}forensic-analyzer{C.RS}"
            f"{C.R}]─[{C.RS}"
            f"{C.G}{label}{C.RS}"
            f"{C.R}]{C.RS}"
        )
        line2 = f"{MARGIN}{C.R}└──╼{C.RS} {C.W}${C.RS} "
        print(line1)
        return input(line2).strip()
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
    print(f"{MARGIN}{C.R}[!]{C.RS} {C.Y}{msg}{C.RS}")


def error(msg: str) -> None:
    print(f"{MARGIN}{C.R}[-]{C.RS} {C.R}{msg}{C.RS}")


def status(msg: str) -> None:
    print(f"{MARGIN}{C.D}[~]{C.RS} {C.D}{msg}{C.RS}")


# Affichage des resultats

MODULE_TAGS = {
    "pdf": "PDF", "image": "IMG", "gps": "GPS", "strings": "STR",
    "firefox_history": "FHX", "firefox_cookies": "FCK",
    "stego": "SGO", "carving": "CRV", "pcap": "NET", "memory": "MEM",
    "disk": "DSK", "evtx": "EVT", "registry": "REG",
    "linux_artifacts": "LNX", "yara": "YRA", "ioc": "IOC", "timeline": "TML",
}

MODULE_NAMES = {
    "pdf": "Analyse PDF", "image": "Analyse Image / EXIF",
    "gps": "Coordonnees GPS", "strings": "Extraction Strings",
    "firefox_history": "Historique Firefox", "firefox_cookies": "Cookies Firefox",
    "stego": "Steganographie", "carving": "File Carving",
    "pcap": "Analyse Reseau PCAP", "memory": "Analyse Memoire",
    "disk": "Forensique Disque", "evtx": "Windows Event Logs",
    "registry": "Registre Windows", "linux_artifacts": "Artefacts Linux",
    "yara": "Scan YARA", "ioc": "Extraction IOC", "timeline": "Timeline DFIR",
}


def separator(label: str = "") -> None:
    """Separateur double-ligne rouge style hacker [ ✓✗!?→ ] avec label optionnel."""
    w = _width() - 8
    decor_l = f"{C.VB}[ {C.G}✓{C.R}✗{C.Y}!{C.B}?{C.R}→{C.VB} ]{C.RS}"
    decor_r = f"{C.VB}[ {C.G}✓{C.R}✗{C.Y}!{C.B}?{C.R}→{C.VB} ]{C.RS}"
    
    if label:
        text = f" {C.G}{label}{C.RS} "
        label_visible_len = len(label) + 2
        # Les décors font 13 caractères de longueur visible chacun
        remaining = w - 26 - label_visible_len
        if remaining < 4:
            remaining = 4
        half = remaining // 2
        print(f"{MARGIN}{decor_l} {C.R}{'═' * half}{C.RS}{text}{C.R}{'═' * (remaining - half)}{C.RS} {decor_r}")
    else:
        remaining = w - 26
        if remaining < 4:
            remaining = 4
        print(f"{MARGIN}{decor_l} {C.R}{'═' * remaining}{C.RS} {decor_r}")


def finding_header(finding_type: str, filename: str) -> None:
    """Affiche l'entete d'un finding."""
    tag = MODULE_TAGS.get(finding_type, "???")
    name = MODULE_NAMES.get(finding_type, finding_type)
    print()
    separator(f"{tag} | {name}")
    print(f"{MARGIN}   {C.G}Fichier                      :{C.RS} {C.W}{filename}{C.RS}")
    print()


def kv(key: str, value, indent: int = 3) -> None:
    """Affiche une paire cle-valeur en vert hacker et rouge hacker."""
    pad = " " * indent
    val_str = str(value)

    # Titre du parametre en vert hacker (G) et resultat en rouge (R)
    key_display = f"{C.G}{key:<28}{C.RS}"
    val_display = f"{C.W}{val_str}{C.RS}"

    print(f"{MARGIN}{pad} {key_display} : {val_display}")


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
        for i, s in enumerate(strings[:100], 1):
            print(f"{MARGIN}    {C.D}{i:>4}.{C.RS} {C.W}{s}{C.RS}")
        if len(strings) > 100:
            print(f"{MARGIN}    {C.D}     ... +{len(strings) - 100} de plus{C.RS}")

    elif finding.type == "firefox_history" and "entries" in extra:
        entries = extra["entries"]
        if entries:
            print()
            separator("Historique")
            for e in entries[:50]:
                date = e.get("date", "?")
                url = e.get("url", "")
                print(f"{MARGIN}    {C.G}{date:<22}{C.RS} {C.W}{url}{C.RS}")

    elif finding.type == "firefox_cookies" and "entries" in extra:
        entries = extra["entries"]
        if entries:
            print()
            separator("Cookies")
            for e in entries[:50]:
                name = e.get("name", "")
                host = e.get("host", "")
                val = e.get("value", "")[:40]
                print(f"{MARGIN}    {C.G}{name}{C.RS} @ {C.VB}{host:<30}{C.RS} {C.W}{val}{C.RS}")

    elif finding.type == "pcap" and "credentials" in extra:
        creds = extra["credentials"]
        if creds:
            print()
            separator("Credentials detectes")
            for c_item in creds[:20]:
                proto = c_item.get("protocol", "?")
                data = c_item.get("data", c_item.get("user", str(c_item)))
                print(f"{MARGIN}    {C.G}{proto:<14}{C.RS} {C.W}{data}{C.RS}")

    elif finding.type == "ioc" and "iocs" in extra:
        iocs = extra["iocs"]
        if isinstance(iocs, dict):
            print()
            separator("IOC detectes")
            for ioc_type, items in iocs.items():
                for item in (items[:10] if isinstance(items, list) else [items]):
                    print(f"{MARGIN}    {C.G}{ioc_type:<14}{C.RS} {C.W}{item}{C.RS}")

    elif finding.type == "timeline" and "events" in extra:
        events = extra["events"]
        if events:
            print()
            separator("Timeline")
            for e in events[:30]:
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
                for item in items[:20]:
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
    separator("RESUME")
    print()

    for ftype, count in sorted(type_counts.items()):
        tag = MODULE_TAGS.get(ftype, "???")
        name = MODULE_NAMES.get(ftype, ftype)
        print(f"{MARGIN}    {C.VB}[{tag}]{C.RS} {C.G}{name:<30}{C.RS} {C.W}{C.BD}{count}{C.RS}")

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
        input(f"{MARGIN}{C.D}[Appuyez sur Entree pour continuer]{C.RS}")
    except (EOFError, KeyboardInterrupt):
        pass
