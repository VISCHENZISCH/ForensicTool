"""Reconstruction des appels sensibles d'un binaire x86 / x86-64 par désassemblage (capstone).

Pour chaque appel à une fonction connue (connect, sleep, open, execve, CreateProcess...),
on retrouve les arguments constants préparés juste avant l'appel : chaîne pointée en
mémoire, entier immédiat, ou structure sockaddr_in construite sur la pile.
Analyse statique uniquement : le binaire n'est jamais exécuté.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Callable

try:
    import capstone
    from capstone import x86_const
    HAS_CAPSTONE = True
except ImportError:
    capstone = None
    HAS_CAPSTONE = False

# Convention d'appel : registres des premiers arguments
_SYSV_ARGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_WIN64_ARGS = ("rcx", "rdx", "r8", "r9")
# Registres non préservés par un appel (System V : rsi/rdi inclus ; Windows x64 : préservés)
_VOLATILE_SYSV = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
_VOLATILE_WIN64 = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
_ALIASES = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi", "edi": "rdi", "ebp": "rbp",
    "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11", "r12d": "r12", "r13d": "r13",
    "r14d": "r14", "r15d": "r15", "cx": "rcx", "dx": "rdx", "di": "rdi", "si": "rsi",
}

# Fonction normalisée → (catégorie, index de l'argument intéressant, nature de l'argument)
APIS = {
    "connect": ("réseau", None, "sockaddr"),
    "inet_pton": ("réseau", 1, "string"), "inet_addr": ("réseau", 0, "string"),
    "gethostbyname": ("réseau", 0, "string"), "getaddrinfo": ("réseau", 0, "string"),
    "htons": ("réseau", 0, "port"),
    "sleep": ("temporisation", 0, "seconds"), "usleep": ("temporisation", 0, "microseconds"),
    "Sleep": ("temporisation", 0, "milliseconds"),
    "open": ("fichiers", 0, "string"), "open64": ("fichiers", 0, "string"), "fopen": ("fichiers", 0, "string"),
    "creat": ("fichiers", 0, "string"), "unlink": ("fichiers", 0, "string"),
    "CreateFileA": ("fichiers", 0, "string"), "CreateFileW": ("fichiers", 0, "wstring"),
    "execve": ("exécution", 0, "string"), "execl": ("exécution", 0, "string"), "execvp": ("exécution", 0, "string"),
    "system": ("exécution", 0, "string"), "popen": ("exécution", 0, "string"),
    "WinExec": ("exécution", 0, "string"), "ShellExecuteA": ("exécution", 2, "string"),
    "CreateProcessA": ("exécution", 1, "string"), "CreateProcessW": ("exécution", 1, "wstring"),
    "URLDownloadToFileA": ("réseau", 1, "string"), "InternetOpenUrlA": ("réseau", 1, "string"),
    "RegSetValueExA": ("registre", 1, "string"), "RegCreateKeyExA": ("registre", 1, "string"),
    "ptrace": ("anti-analyse", None, None), "IsDebuggerPresent": ("anti-analyse", None, None),
    "daemon": ("furtivité", None, None), "setsid": ("furtivité", None, None),
}


def normalize(name: str) -> str:
    return name.split("@", 1)[0].lstrip("_").removeprefix("libc_").removeprefix("imp_")


class _Reader:
    """Lecture de chaînes à une adresse virtuelle, à partir des sections du binaire."""

    def __init__(self, data: bytes, sections: list[dict]):
        self.data = data
        self.sections = [s for s in sections if s["addr"] and s["size"]]

    def string(self, vaddr: int, wide: bool = False) -> str:
        for s in self.sections:
            if s["addr"] <= vaddr < s["addr"] + s["size"]:
                off = s["offset"] + vaddr - s["addr"]
                raw = self.data[off:off + 512]
                if wide:
                    stop = raw.find(b"\x00\x00")
                    text = raw[:stop + (stop % 2)].decode("utf-16le", "replace") if stop > 0 else ""
                else:
                    text = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
                return text if text and text.isprintable() else ""
        return ""


def _port_from_sockaddr(imm: int) -> int | None:
    """Premier dword d'un sockaddr_in (AF_INET = 2, port en ordre réseau) → numéro de port."""
    if imm & 0xFFFF != 2 or imm >> 16 == 0 or imm > 0xFFFFFFFF:
        return None
    return ((imm >> 16) & 0xFF) << 8 | (imm >> 24) & 0xFF


def analyze_code(code_ranges: list[tuple[int, bytes]], reader: _Reader, resolve: Callable[[object], str | None],
                 is64: bool = True, windows: bool = False, function_starts: set[int] = frozenset(),
                 import_at: Callable[[int], str | None] = lambda addr: None) -> list[dict]:
    """
    Désassemble les plages de code et reconstruit les appels sensibles.

    `resolve(insn)` renvoie le nom de la fonction appelée par une instruction call/jmp ;
    `import_at(adresse)` le nom de l'import stocké à une adresse (IAT / GOT), pour suivre
    les appels indirects « mov reg, [import] ; call reg ».
    """
    if not HAS_CAPSTONE:
        return []
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
    md.detail = True
    arg_regs = _WIN64_ARGS if windows else _SYSV_ARGS
    volatile = _VOLATILE_WIN64 if windows else _VOLATILE_SYSV
    calls: list[dict] = []

    for base, code in code_ranges:
        regs: dict[str, tuple[str, int]] = {}
        immediates: deque = deque(maxlen=512)  # immédiats de la fonction courante
        for insn in md.disasm(code, base):
            if insn.address in function_starts:
                regs.clear()
                immediates.clear()
            mnem = insn.mnemonic.removeprefix("bnd ").removeprefix("notrack ")  # préfixes CET / MPX
            ops = insn.operands
            immediates.extend(op.imm for op in ops if op.type == x86_const.X86_OP_IMM)

            if mnem == "call":
                name = resolve(insn)
                if not name and ops and ops[0].type == x86_const.X86_OP_REG:
                    held = regs.get(_ALIASES.get(insn.reg_name(ops[0].reg), insn.reg_name(ops[0].reg)))
                    name = held[1] if held and held[0] == "func" else None
                api = normalize(name) if name else ""
                if api in APIS:
                    calls.append(_describe_call(insn.address, api, regs, immediates, reader, arg_regs))
                for r in volatile:
                    regs.pop(r, None)
                continue

            if len(ops) < 2 or ops[0].type != x86_const.X86_OP_REG:
                continue
            dst = insn.reg_name(ops[0].reg)
            dst = _ALIASES.get(dst, dst)
            src = ops[1]
            if mnem == "mov" and src.type == x86_const.X86_OP_IMM:
                regs[dst] = ("imm", src.imm & 0xFFFFFFFFFFFFFFFF)
            elif mnem == "lea" and src.type == x86_const.X86_OP_MEM and src.mem.base == x86_const.X86_REG_RIP:
                regs[dst] = ("addr", insn.address + insn.size + src.mem.disp)
            elif mnem == "lea" and src.type == x86_const.X86_OP_MEM and src.mem.base == 0 and src.mem.index == 0:
                regs[dst] = ("addr", src.mem.disp)
            elif mnem == "mov" and src.type == x86_const.X86_OP_REG:
                origin = _ALIASES.get(insn.reg_name(src.reg), insn.reg_name(src.reg))
                if origin in regs:
                    regs[dst] = regs[origin]
                else:
                    regs.pop(dst, None)
            elif mnem == "mov" and src.type == x86_const.X86_OP_MEM and import_at(_operand_address(insn, src)):
                regs[dst] = ("func", import_at(_operand_address(insn, src)))
            elif mnem == "xor" and src.type == x86_const.X86_OP_REG and src.reg == ops[0].reg:
                regs[dst] = ("imm", 0)
            else:
                regs.pop(dst, None)
    return calls


def _describe_call(address, api, regs, immediates, reader, arg_regs) -> dict:
    category, index, kind = APIS[api]
    call = {"address": hex(address), "api": api, "category": category}
    if kind == "sockaddr":
        # sockaddr_in préparé dans la fonction : immédiat 32 bits {AF_INET, port en ordre réseau}
        for imm in reversed(immediates):
            port = _port_from_sockaddr(imm & 0xFFFFFFFF)
            if port:
                call["port"] = port
                break
        return call
    if index is None or index >= len(arg_regs):
        return call
    value = regs.get(arg_regs[index])
    if not value:
        return call
    if kind in ("string", "wstring") and value[0] == "addr":
        text = reader.string(value[1], wide=kind == "wstring")
        if text:
            call["argument"] = text
    elif kind == "port" and value[0] == "imm":
        call["port"] = value[1] & 0xFFFF
    elif kind in ("seconds", "milliseconds", "microseconds") and value[0] == "imm":
        divisor = {"seconds": 1, "milliseconds": 1000, "microseconds": 1_000_000}[kind]
        call["seconds"] = value[1] / divisor
    return call


def summarize(calls: list[dict]) -> dict:
    """Synthèse : destinations réseau, intervalle de temporisation, fichiers, commandes."""
    hosts = [c["argument"] for c in calls if c["api"] in ("inet_pton", "inet_addr", "gethostbyname", "getaddrinfo")
             and c.get("argument")]
    ports = sorted({c["port"] for c in calls if c.get("port")})
    endpoints = [{"host": h, "port": p} for h in hosts for p in ports] or \
                [{"host": h, "port": None} for h in hosts] or [{"host": None, "port": p} for p in ports]
    return {
        "endpoints": endpoints,
        "sleep_seconds": sorted({c["seconds"] for c in calls if "seconds" in c}),
        "files": sorted({c["argument"] for c in calls if c["category"] == "fichiers" and c.get("argument")}),
        "commands": sorted({c["argument"] for c in calls if c["category"] == "exécution" and c.get("argument")}),
        "urls": sorted({c["argument"] for c in calls if c["api"].startswith(("URLDownload", "InternetOpen"))
                        and c.get("argument")}),
        "categories": sorted({c["category"] for c in calls}),
    }


# Ports courants : une destination sur un autre port est un « port non standard » (T1571)
_COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080, 8443}


def describe(result: dict | None, meta: dict, techniques: set[str], windows: bool = False) -> dict | None:
    """Ajoute aux métadonnées le comportement reconstruit par désassemblage (commun ELF / PE)."""
    if not result or not result["calls"]:
        return result
    summary = result["summary"]
    endpoints = [e for e in summary["endpoints"] if e["host"] or e["port"]]
    for e in endpoints:
        e["ip"] = e["host"]
    if endpoints:
        meta["[ALERTE] Destination réseau (désassemblage)"] = ", ".join(
            f"{e['host'] or '?'}:{e['port'] or '?'}" for e in endpoints)
        if any(e["port"] and e["port"] not in _COMMON_PORTS for e in endpoints):
            techniques.add("T1571")
    if summary["sleep_seconds"]:
        meta["Temporisation (sleep)"] = ", ".join(f"{s:g} s" for s in summary["sleep_seconds"])
    if summary["files"]:
        meta["Fichiers ouverts (constantes)"] = ", ".join(summary["files"][:10])
    if summary["commands"]:
        meta["[ALERTE] Commandes exécutées"] = ", ".join(summary["commands"][:10])
        techniques.add("T1059.003" if windows else "T1059.004")
    if endpoints and summary["sleep_seconds"] and any(c["api"] == "connect" for c in result["calls"]):
        meta["[ALERTE] Comportement"] = (f"Balise réseau probable : connexion vers "
                                         f"{endpoints[0]['host'] or '?'}:{endpoints[0]['port'] or '?'} "
                                         f"puis attente de {max(summary['sleep_seconds']):g} s")
    return result


# Adaptateurs par format

def analyze_elf(data: bytes) -> dict | None:
    """Appels sensibles d'un ELF x86/x86-64 (symboles statiques ou imports via PLT/GOT)."""
    from forensic_analyzer.analyzers.elf.parser import elf_layout

    if not HAS_CAPSTONE:
        return None
    layout = elf_layout(data)
    if layout["machine"] not in ("x86-64", "x86"):
        return None
    sections = layout["sections"]
    reader = _Reader(data, sections)
    functions, got = layout["functions"], layout["got"]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if layout["is64"] else capstone.CS_MODE_32)
    md.detail = True
    # Entrées PLT : « jmp [GOT] » → nom de l'import. L'entrée commence soit sur ce jmp,
    # soit 4 octets avant (endbr64), soit à l'alignement de 16 octets (.plt classique).
    plt: dict[int, str] = {}
    for sec in sections:
        if sec["name"].startswith(".plt") and sec["size"]:
            code = data[sec["offset"]:sec["offset"] + sec["size"]]
            for insn in md.disasm(code, sec["addr"]):
                if insn.mnemonic.endswith("jmp") and insn.operands and insn.operands[0].type == x86_const.X86_OP_MEM:
                    name = got.get(_mem_target(insn))
                    if name:
                        for start in (insn.address, insn.address - 4, insn.address & ~0xF):
                            plt.setdefault(start, name)

    def resolve(insn):
        op = insn.operands[0]
        if op.type == x86_const.X86_OP_IMM:
            return functions.get(op.imm) or plt.get(op.imm)
        if op.type == x86_const.X86_OP_MEM:
            return got.get(_mem_target(insn))
        return None

    text = [s for s in sections if s["name"] == ".text"]
    ranges = [(s["addr"], data[s["offset"]:s["offset"] + s["size"]]) for s in text]
    calls = analyze_code(ranges, reader, resolve, is64=layout["is64"], function_starts=set(functions),
                         import_at=got.get)
    return {"calls": calls, "summary": summarize(calls)}


def analyze_pe(path: str) -> dict | None:
    """Appels sensibles d'un PE x86-64 (imports via l'IAT)."""
    if not HAS_CAPSTONE:
        return None
    try:
        import pefile
    except ImportError:
        return None
    pe = pefile.PE(path, fast_load=False)
    try:
        is64 = pe.FILE_HEADER.Machine == 0x8664
        base = pe.OPTIONAL_HEADER.ImageBase
        data = pe.__data__
        sections = [{"name": s.Name.rstrip(b"\x00").decode("latin-1"), "addr": base + s.VirtualAddress,
                     "offset": s.PointerToRawData, "size": min(s.SizeOfRawData, s.Misc_VirtualSize or s.SizeOfRawData)}
                    for s in pe.sections]
        iat: dict[int, str] = {}
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                if imp.name:
                    iat[imp.address] = imp.name.decode("latin-1")
        reader = _Reader(bytes(data), sections)

        def resolve(insn):
            op = insn.operands[0]
            if op.type == x86_const.X86_OP_MEM:
                return iat.get(_mem_target(insn))
            return None

        code = [s for s in pe.sections if s.Characteristics & 0x20000000]  # IMAGE_SCN_MEM_EXECUTE
        ranges = [(base + s.VirtualAddress, s.get_data()) for s in code]
        calls = analyze_code(ranges, reader, resolve, is64=is64, windows=True, import_at=iat.get)
        return {"calls": calls, "summary": summarize(calls)}
    finally:
        pe.close()


def _mem_target(insn) -> int | None:
    return _operand_address(insn, insn.operands[0])


def _operand_address(insn, op) -> int | None:
    """Adresse absolue d'un opérande mémoire RIP-relatif ou absolu (None sinon)."""
    if op.mem.base == x86_const.X86_REG_RIP:
        return insn.address + insn.size + op.mem.disp
    if op.mem.base == 0 and op.mem.index == 0:
        return op.mem.disp & 0xFFFFFFFFFFFFFFFF
    return None
