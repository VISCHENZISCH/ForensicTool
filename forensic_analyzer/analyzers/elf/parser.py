"""Parseur ELF en Python pur : en-tête, liaison, symboles et BuildID (lecture seule)."""
from __future__ import annotations

import struct

_MACHINES = {0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64", 0x08: "MIPS", 0xF3: "RISC-V"}
_TYPES = {1: "REL (objet)", 2: "EXEC (exécutable)", 3: "DYN (PIE / bibliothèque)", 4: "CORE"}
_PT_INTERP, _PT_DYNAMIC = 3, 2
_SHT_SYMTAB, _SHT_DYNSYM, _SHT_NOTE, _SHT_RELA, _SHT_REL = 2, 11, 7, 4, 9
_NT_GNU_BUILD_ID = 3

# Symboles révélateurs de capacités (présents si le binaire n'est pas strippé ou s'ils sont importés)
CAPABILITIES = {
    "Réseau sortant": {"socket", "connect", "inet_pton", "inet_addr", "gethostbyname", "getaddrinfo"},
    "Écoute réseau": {"bind", "listen", "accept", "accept4"},
    "Exécution de commandes": {"execve", "execvp", "execl", "system", "popen"},
    "Démonisation": {"daemon", "setsid"},
    "Anti-débogage": {"ptrace", "prctl"},
    "Manipulation de privilèges": {"setuid", "setgid", "setreuid", "capset"},
}


class ELFError(ValueError):
    pass


def parse_elf(data: bytes) -> dict:
    """Analyse un binaire ELF 32/64 bits, little ou big endian."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ELFError("Pas un fichier ELF")
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"

    if is64:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)
    else:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(end + "HHIIIIIHHHHHH", data, 16)

    # Segments : PT_INTERP / PT_DYNAMIC déterminent la liaison dynamique
    interpreter, dynamic = "", False
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        if is64:
            p_type, _f, p_offset, _va, _pa, p_filesz = struct.unpack_from(end + "IIQQQQ", data, off)
        else:
            p_type, p_offset, _va, _pa, p_filesz = struct.unpack_from(end + "IIIII", data, off)
        if p_type == _PT_INTERP:
            interpreter = data[p_offset:p_offset + p_filesz].rstrip(b"\0").decode("utf-8", "replace")
        elif p_type == _PT_DYNAMIC:
            dynamic = True

    sections = _read_sections(data, is64, end, e_shoff, e_shentsize, e_shnum, e_shstrndx)
    names = {s["name"] for s in sections}
    symbols = set()
    for s in sections:
        if s["type"] in (_SHT_SYMTAB, _SHT_DYNSYM) and 0 <= s["link"] < len(sections):
            symbols |= _read_symbols(data, is64, end, s, sections[s["link"]])

    build_id = ""
    for s in sections:
        if s["type"] == _SHT_NOTE and s["name"] == ".note.gnu.build-id":
            build_id = _read_build_id(data, end, s)

    return {
        "class": "ELF64" if is64 else "ELF32",
        "endianness": "little" if end == "<" else "big",
        "type": _TYPES.get(e_type, str(e_type)),
        "machine": _MACHINES.get(e_machine, hex(e_machine)),
        "entry_point": hex(e_entry),
        "linking": "dynamique" if (interpreter or dynamic) else "statique",
        "interpreter": interpreter,
        "stripped": ".symtab" not in names,
        "build_id": build_id,
        "sections": [s["name"] for s in sections if s["name"]],
        "capabilities": {cap: sorted(symbols & syms) for cap, syms in CAPABILITIES.items() if symbols & syms},
        "symbol_count": len(symbols),
    }


def _read_sections(data, is64, end, shoff, shentsize, shnum, shstrndx) -> list[dict]:
    sections = []
    for i in range(shnum):
        off = shoff + i * shentsize
        if off + shentsize > len(data):
            break
        if is64:
            name, typ, _fl, addr, offset, size, link, _info, _al, entsize = struct.unpack_from(end + "IIQQQQIIQQ", data, off)
        else:
            name, typ, _fl, addr, offset, size, link, _info, _al, entsize = struct.unpack_from(end + "IIIIIIIIII", data, off)
        sections.append({"name_off": name, "type": typ, "addr": addr, "offset": offset, "size": size,
                         "link": link, "entsize": entsize, "name": ""})
    if 0 <= shstrndx < len(sections):
        strtab = sections[shstrndx]
        for s in sections:
            s["name"] = _cstr(data, strtab["offset"] + s["name_off"])
    return sections


def normalize_symbol(name: str) -> str:
    """glibc statique préfixe ses alias internes (__libc_connect, __connect) ; on retire aussi @GLIBC_x."""
    return name.split("@", 1)[0].lstrip("_").removeprefix("libc_")


def _iter_symbols(data, is64, end, symtab, strtab):
    """(nom, valeur, type) de chaque entrée d'une table de symboles."""
    entsize = symtab["entsize"] or (24 if is64 else 16)
    for off in range(symtab["offset"], min(symtab["offset"] + symtab["size"], len(data) - entsize + 1), entsize):
        if is64:
            st_name, st_info, _other, _shndx, st_value = struct.unpack_from(end + "IBBHQ", data, off)
        else:
            st_name, st_value = struct.unpack_from(end + "II", data, off)
            st_info = data[off + 12]
        yield (_cstr(data, strtab["offset"] + st_name) if st_name else ""), st_value, st_info & 0xF


def _read_symbols(data, is64, end, symtab, strtab) -> set[str]:
    """Noms normalisés des fonctions (STT_FUNC) d'une table de symboles."""
    return {normalize_symbol(n) for n, _v, t in _iter_symbols(data, is64, end, symtab, strtab) if t == 2 and n}


def elf_layout(data: bytes) -> dict:
    """
    Sections avec adresses virtuelles, fonctions {adresse: nom} et imports {adresse GOT: nom},
    pour le désassemblage.
    """
    if data[:4] != b"\x7fELF":
        raise ELFError("Pas un fichier ELF")
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    if is64:
        e_machine, = struct.unpack_from(end + "H", data, 18)
        e_shoff, = struct.unpack_from(end + "Q", data, 40)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 58)
    else:
        e_machine, = struct.unpack_from(end + "H", data, 18)
        e_shoff, = struct.unpack_from(end + "I", data, 32)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 46)
    sections = _read_sections(data, is64, end, e_shoff, e_shentsize, e_shnum, e_shstrndx)

    functions: dict[int, str] = {}
    for sec in sections:
        if sec["type"] in (_SHT_SYMTAB, _SHT_DYNSYM) and 0 <= sec["link"] < len(sections):
            for name, value, typ in _iter_symbols(data, is64, end, sec, sections[sec["link"]]):
                if typ == 2 and value and name:
                    functions.setdefault(value, name)

    # Relocations vers la table dynamique : adresse de l'entrée GOT → fonction importée
    got: dict[int, str] = {}
    for sec in sections:
        if sec["type"] not in (_SHT_RELA, _SHT_REL) or not 0 <= sec["link"] < len(sections):
            continue
        dynsym = sections[sec["link"]]
        if dynsym["type"] != _SHT_DYNSYM or not 0 <= dynsym["link"] < len(sections):
            continue
        names = [n for n, _v, _t in _iter_symbols(data, is64, end, dynsym, sections[dynsym["link"]])]
        entsize = sec["entsize"] or ((24 if sec["type"] == _SHT_RELA else 16) if is64 else (12 if sec["type"] == _SHT_RELA else 8))
        for off in range(sec["offset"], min(sec["offset"] + sec["size"], len(data) - entsize + 1), entsize):
            if is64:
                r_offset, r_info = struct.unpack_from(end + "QQ", data, off)
                index = r_info >> 32
            else:
                r_offset, r_info = struct.unpack_from(end + "II", data, off)
                index = r_info >> 8
            if 0 < index < len(names) and names[index]:
                got[r_offset] = names[index]

    return {
        "is64": is64,
        "machine": _MACHINES.get(e_machine, hex(e_machine)),
        "sections": [{k: sec[k] for k in ("name", "type", "addr", "offset", "size")} for sec in sections],
        "functions": functions,
        "got": got,
    }


def _read_build_id(data, end, note) -> str:
    off = note["offset"]
    namesz, descsz, ntype = struct.unpack_from(end + "III", data, off)
    if ntype != _NT_GNU_BUILD_ID:
        return ""
    desc = off + 12 + ((namesz + 3) & ~3)
    return data[desc:desc + descsz].hex()


def _cstr(data: bytes, off: int) -> str:
    stop = data.find(b"\0", off)
    return data[off:stop if stop != -1 else off + 256].decode("utf-8", "replace")
