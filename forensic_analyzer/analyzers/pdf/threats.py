"""Analyse de menace d'un PDF : ce qui s'exécute, quand, et depuis quel objet.

Le fichier est découpé en objets sans passer par la table xref (souvent cassée exprès dans les
PDF piégés). Les flux sont décodés (Flate, ASCIIHex, ASCII85, LZW, RunLength, enchaînés), les
chaînes aussi (échappements octaux, hexadécimal, UTF-16). On suit ensuite les déclencheurs depuis
le catalogue jusqu'au code : /OpenAction, /AA, JavaScript de document (/Names), pages, annotations
et champs de formulaire. Chaque point du score cite l'objet en cause.

Le coût reste linéaire : le découpage avance toujours, une recherche qui a échoué (fin de
commentaire, de flux, de chaîne hexadécimale) n'est jamais relancée plus loin, et un budget borne
le travail total sur un fichier hostile. Un test impose un temps maximal sur chacun de ces cas.
"""
from __future__ import annotations

import base64
import binascii
import re
import zlib
from dataclasses import dataclass, field

from forensic_analyzer.analyzers.malware.entropy import calculate_entropy

MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_DECODED = 32 * 1024 * 1024          # par flux : bombe zlib
_MAX_DECODED_TOTAL = 256 * 1024 * 1024
_MAX_DEPTH = 64

_SUSPICIOUS_NAMES = ("JS", "JavaScript", "OpenAction", "AA", "Launch", "SubmitForm", "ImportData",
                     "GoToR", "GoToE", "RichMedia", "EmbeddedFiles", "XFA")
_IMAGE_FILTERS = {"DCTDecode", "DCT", "JPXDecode", "CCITTFaxDecode", "CCF", "JBIG2Decode"}
# Déclencheurs d'annotation qui partent sans clic : ouverture, affichage, apparition de la page
_AUTO_ANNOT_KEYS = {"PO", "PV", "PI"}
# API Acrobat visées par des exploits connus (CVE-2007-5659, 2008-2992, 2009-0927, 2009-4324...)
_EXPLOIT_APIS = ("util.printf", "Collab.collectEmailInfo", "Collab.getIcon", "getAnnots",
                 "spell.customDictionaryOpen", "media.newPlayer", "this.exportDataObject")
_OBFUSCATION = ("eval(", "unescape(", "String.fromCharCode", "\\x", "%u")
# Heap spray encodé dans du JavaScript (des octets 0x90 bruts dans une image ne s'exécutent pas)
_SHELLCODE = (b"%u9090%u9090", b"%U9090%U9090", b"%u0c0c%u0c0c", b"%u0C0C%u0C0C",
              b"\\x90" * 8, b"\\x0c" * 8, b"\\x0C" * 8)

_DELIM = rb"\s()<>\[\]{}/%\x00"
_OBJ = re.compile(rb"(\d+)\s+(\d+)\s+obj(?![^" + _DELIM + rb"])")
_REF = re.compile(rb"(\d+)\s+(\d+)\s+R(?![^" + _DELIM + rb"])")
_NUMBER = re.compile(rb"[+-]?(?:\d+\.?\d*|\.\d+)")
_NAME = re.compile(rb"/[^" + _DELIM + rb"]*")
_TOKEN = re.compile(rb"[^" + _DELIM + rb"]+")
_LITERAL_RUN = re.compile(rb"[^()\\]+")
_HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_OCTAL = re.compile(rb"[0-7]{1,3}")
_EOL = re.compile(rb"[\r\n]")
_HEX_END = re.compile(rb">")
_URL = re.compile(rb"https?://[^\s<>()\[\]{}\"'\\`^|\x00-\x1f\x7f-\xff]+", re.IGNORECASE)
_ESCAPES = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
_ACTION_KINDS = ("JavaScript", "Launch", "URI", "SubmitForm", "GoToR", "GoToE", "ImportData", "RichMediaExecute")
_STRUCTURE_KEYWORDS = (b"obj", b"endobj", b"stream", b"endstream", b"xref", b"trailer")


class Name(str):
    """Nom PDF décodé, sans la barre oblique."""


@dataclass(frozen=True)
class Ref:
    num: int
    gen: int = 0


class _Malformed(ValueError):
    pass


class _Parser:
    """Lecteur d'objets PDF tolérant : dictionnaires, tableaux, chaînes, noms, nombres, références."""

    def __init__(self, data: bytes, names: set[str], obfuscated: set[str]):
        self.data, self.names, self.obfuscated = data, names, obfuscated
        self.furthest = 0
        self._absent_from: dict[bytes, int] = {}

    def _find(self, pattern: re.Pattern, pos: int) -> int:
        """
        Position de fin du prochain motif, ou -1. Un échec est mémorisé : chercher à nouveau la
        fin d'un commentaire sans fin de ligne, objet après objet, relirait tout le fichier à
        chaque fois (coût quadratique).
        """
        if pos >= self._absent_from.get(pattern.pattern, len(self.data) + 1):
            return -1
        m = pattern.search(self.data, pos)
        if not m:
            self._absent_from[pattern.pattern] = pos
            return -1
        return m.end()

    def skip(self, pos: int) -> int:
        data, n = self.data, len(self.data)
        while pos < n:
            c = data[pos]
            if c in b" \t\r\n\f\x00":
                pos += 1
            elif c == 0x25:  # commentaire
                end = self._find(_EOL, pos)
                pos = end if end >= 0 else n
            else:
                break
        return pos

    def value(self, pos: int, depth: int = 0):
        if depth > _MAX_DEPTH:
            raise _Malformed("imbrication trop profonde")
        data = self.data
        pos = self.skip(pos)
        if pos >= len(data):
            raise _Malformed("fin des données")
        c = data[pos]
        if data.startswith(b"<<", pos):
            out, pos = {}, pos + 2
            while True:
                pos = self.skip(pos)
                if data.startswith(b">>", pos):
                    return self._seen(out, pos + 2)
                key, pos = self.value(pos, depth + 1)
                val, pos = self.value(pos, depth + 1)
                if isinstance(key, Name):
                    out[key] = val
        if c == 0x5B:  # [
            out, pos = [], pos + 1
            while True:
                pos = self.skip(pos)
                if data.startswith(b"]", pos):
                    return self._seen(out, pos + 1)
                val, pos = self.value(pos, depth + 1)
                out.append(val)
        if c == 0x28:  # (
            return self._literal(pos)
        if c == 0x3C:  # <
            end = self._find(_HEX_END, pos) - 1
            if end < 0:
                raise _Malformed("chaîne hexadécimale non fermée")
            digits = re.sub(rb"[^0-9A-Fa-f]", b"", data[pos + 1:end])
            return self._seen(binascii.unhexlify(digits + b"0" * (len(digits) % 2)), end + 1)
        if c == 0x2F:  # /
            m = _NAME.match(data, pos)
            raw = m.group()[1:]
            if b"#" in raw:
                raw = _HEX_ESCAPE.sub(lambda h: bytes([int(h.group(1), 16)]), raw)
                if raw.decode("latin-1") in _SUSPICIOUS_NAMES:
                    self.obfuscated.add(raw.decode("latin-1"))
            name = Name(raw.decode("latin-1"))
            self.names.add(name)
            return self._seen(name, m.end())
        m = _REF.match(data, pos)
        if m:
            return self._seen(Ref(int(m.group(1)), int(m.group(2))), m.end())
        m = _NUMBER.match(data, pos)
        if m:
            text = m.group()
            return self._seen(float(text) if b"." in text else int(text), m.end())
        m = _TOKEN.match(data, pos)
        if not m:  # délimiteur isolé : ) > ] { }
            return self._seen(None, pos + 1)
        token = m.group()
        if token in _STRUCTURE_KEYWORDS:
            raise _Malformed(f"objet non terminé avant « {token.decode()} »")
        return self._seen({b"true": True, b"false": False}.get(token), m.end())

    def _literal(self, pos: int):
        data, n, out, depth, i = self.data, len(self.data), bytearray(), 1, pos + 1
        while i < n:
            m = _LITERAL_RUN.match(data, i)
            if m:
                out += m.group()
                i = m.end()
                continue
            c = data[i]
            if c == 0x5C:  # \
                i += 1
                if i >= n:
                    break
                e = data[i]
                if 0x30 <= e <= 0x37:
                    octal = _OCTAL.match(data, i).group()
                    out.append(int(octal, 8) & 0xFF)
                    i += len(octal)
                elif e in (0x0A, 0x0D):  # continuation de ligne
                    i += 2 if data.startswith(b"\r\n", i) else 1
                else:
                    out.append(_ESCAPES.get(e, e))
                    i += 1
                continue
            depth += 1 if c == 0x28 else -1
            if depth == 0:
                return self._seen(bytes(out), i + 1)
            out.append(c)
            i += 1
        self.furthest = max(self.furthest, n)
        raise _Malformed("chaîne non fermée")

    def _seen(self, value, pos: int):
        self.furthest = max(self.furthest, pos)
        return value, pos


@dataclass
class _Obj:
    num: int
    value: object
    stream: bytes | None = None


@dataclass
class Script:
    code: str
    trigger: str
    obj: int | None
    auto: bool


@dataclass
class PdfThreats:
    score: int = 0
    level: str = "Faible"
    reasons: list[tuple[int, str]] = field(default_factory=list)
    scripts: list[Script] = field(default_factory=list)
    launches: list[str] = field(default_factory=list)
    other_actions: list[str] = field(default_factory=list)
    auto_external: list[str] = field(default_factory=list)  # URL ou ressource externe ouverte sans clic
    urls: list[str] = field(default_factory=list)          # cibles d'actions et URLs du JavaScript
    text_urls: list[str] = field(default_factory=list)     # URLs citées dans le texte ou les flux
    embedded: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    obfuscated_names: list[str] = field(default_factory=list)
    shellcode: list[str] = field(default_factory=list)
    high_entropy: list[int] = field(default_factory=list)
    xfa: bool = False
    rich_media: bool = False
    linearized: bool = False
    encrypted: bool = False
    revisions: int = 1
    redefined: int = 0
    info: dict[str, str] = field(default_factory=dict)
    xmp: dict[str, str] = field(default_factory=dict)
    partial: list[str] = field(default_factory=list)


def text_of(raw) -> str:
    """Chaîne PDF -> texte (UTF-16 avec BOM, UTF-8 avec BOM, sinon PDFDocEncoding ~ latin-1)."""
    if not isinstance(raw, bytes):
        return "" if raw is None else str(raw)
    if raw.startswith((b"\xfe\xff", b"\xff\xfe")):
        return raw.decode("utf-16", "replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace")
    return raw.decode("latin-1")


class _Document:
    def __init__(self, data: bytes, reader=None):
        self.data = data
        self.reader = reader                 # pypdf déchiffré (mot de passe vide), sinon None
        self.names: set[str] = set()
        self.obfuscated: set[str] = set()
        self.objects: dict[int, _Obj] = {}
        self.trailers: list[dict] = []
        self.decoded: dict[int, bytes | None] = {}
        self.decoded_total = 0
        self.unsupported: set[str] = set()
        self.result = PdfThreats()
        self._budget = 4 * len(data) + (1 << 20)

    # ── Découpage ─────────────────────────────────────────────────────────────

    def index(self) -> None:
        data, pos = self.data, 0
        parser = _Parser(data, self.names, self.obfuscated)
        while self._budget > 0:
            m = _OBJ.search(data, pos)
            if not m:
                break
            start = parser.furthest = m.end()
            try:
                value, pos = parser.value(start)
            except (_Malformed, binascii.Error, RecursionError):
                self._budget -= parser.furthest - start
                pos = m.end()
                continue
            self._budget -= pos - start
            num, stream = int(m.group(1)), None
            p = parser.skip(pos)
            if data.startswith(b"stream", p):
                stream, pos = self._stream(value, p + 6)
            if num in self.objects:
                self.result.redefined += 1
            self.objects[num] = _Obj(num, value, stream)
            if isinstance(value, dict) and value.get("Type") == "XRef":
                self.trailers.append(value)
        if self._budget <= 0:
            self.result.partial.append("structure anormale : découpage interrompu (budget de lecture épuisé)")
        for m in re.finditer(rb"trailer", data):
            try:
                value, _ = parser.value(m.end())
            except (_Malformed, binascii.Error, RecursionError):
                continue
            if isinstance(value, dict) and ("Root" in value or "Info" in value or "Encrypt" in value):
                self.trailers.append(value)
        self._expand_object_streams()

    def _stream(self, value, start: int) -> tuple[bytes, int]:
        data = self.data
        if data.startswith(b"\r\n", start):
            start += 2
        elif data[start:start + 1] in (b"\n", b"\r"):
            start += 1
        length = value.get("Length") if isinstance(value, dict) else None
        if isinstance(length, int) and 0 <= length <= len(data) - start:
            end = data.find(b"endstream", start + length, start + length + 64)
            if end >= 0:
                return data[start:start + length], end + 9
        end = data.find(b"endstream", start)
        if end < 0:   # aucun endstream plus loin : inutile de le rechercher pour les flux suivants
            self.result.partial.append("flux non terminé (fichier tronqué ou piégé)")
            return data[start:], len(data)
        return data[start:end].rstrip(b"\r\n"), end + 9

    def _expand_object_streams(self) -> None:
        for obj in list(self.objects.values()):
            if not (isinstance(obj.value, dict) and obj.value.get("Type") == "ObjStm"):
                continue
            decoded = self.stream_data(obj)
            first = obj.value.get("First")
            if not decoded or not isinstance(first, int):
                continue
            header = [int(x) for x in re.findall(rb"\d+", decoded[:first])]
            parser, pos = _Parser(decoded, self.names, self.obfuscated), first
            for num in header[0::2]:
                try:
                    value, pos = parser.value(pos)
                except (_Malformed, binascii.Error, RecursionError):
                    break
                if num in self.objects:
                    self.result.redefined += 1
                else:
                    self.objects[num] = _Obj(num, value)

    # ── Accès ─────────────────────────────────────────────────────────────────

    def resolve(self, value, depth: int = 0):
        while isinstance(value, Ref) and depth < 32:
            obj = self.objects.get(value.num)
            value, depth = (obj.value if obj else None), depth + 1
        return value

    def stream_data(self, obj: _Obj) -> bytes | None:
        if obj.num in self.decoded:
            return self.decoded[obj.num]
        data = obj.stream
        filters = self.resolve(obj.value.get("Filter")) if isinstance(obj.value, dict) else None
        filters = [filters] if isinstance(filters, Name) else [self.resolve(f) for f in filters or []]
        for name in filters:
            if data is None:
                break
            if name in _IMAGE_FILTERS:
                data = None
            elif name in ("FlateDecode", "Fl"):
                data = _inflate(data)
            elif name in ("ASCIIHexDecode", "AHx"):
                data = _unhex(data)
            elif name in ("ASCII85Decode", "A85"):
                data = _a85(data)
            elif name in ("LZWDecode", "LZW"):
                data = _lzw(data)
            elif name in ("RunLengthDecode", "RL"):
                data = _run_length(data)
            else:
                self.unsupported.add(str(name))
                data = None
        if data is not None:
            self.decoded_total += len(data)
            if self.decoded_total > _MAX_DECODED_TOTAL:
                self.result.partial.append("volume décompressé total plafonné à 256 Mo")
                data = None
        self.decoded[obj.num] = data
        return data

    def text(self, value, container: int | None = None, keys: tuple[str, ...] = ()) -> str:
        """Texte d'une chaîne ou d'un flux (JavaScript, URL, nom de fichier).

        `container` et `keys` situent une valeur directe (obj 4 -> /OpenAction -> /JS) pour la
        relire déchiffrée.
        """
        if self.result.encrypted:
            return self._decrypted_text(value, container, keys)
        if isinstance(value, Ref):
            obj = self.objects.get(value.num)
            if obj is None:
                return ""
            if obj.stream is not None:
                return text_of(self.stream_data(obj) or b"")
            value = self.resolve(value)
        if isinstance(value, dict):   # spécification de fichier
            return self.text(value.get("UF") or value.get("F") or value.get("Unix") or value.get("DOS"))
        return text_of(value)

    def _decrypted_text(self, value, container, keys) -> str:
        """Chaînes et flux sont chiffrés : seul pypdf (mot de passe vide) sait les lire."""
        if self.reader is None:
            return ""
        try:
            if isinstance(value, Ref):
                obj = self.reader.get_object(value.num)
            elif container is not None and keys:
                obj = self.reader.get_object(container)
                for k in keys:
                    obj = obj[f"/{k}"].get_object()
            else:
                return ""
            if hasattr(obj, "get_data"):
                return text_of(obj.get_data())
            if hasattr(obj, "get"):  # spécification de fichier
                return str(obj.get("/UF") or obj.get("/F") or "")
            return str(obj)
        except Exception:
            return ""

    # ── Déclencheurs ──────────────────────────────────────────────────────────

    def walk(self) -> None:
        self._visited: set[int] = set()
        catalogs = [self.resolve(t.get("Root")) for t in self.trailers]
        catalogs += [o.value for o in self.objects.values()
                     if isinstance(o.value, dict) and o.value.get("Type") == "Catalog"]
        seen_catalogs: set[int] = set()
        for cat in catalogs:
            if isinstance(cat, dict) and id(cat) not in seen_catalogs:
                seen_catalogs.add(id(cat))
                self._catalog(cat, self._num_of(cat))
        self._orphans()

    def _num_of(self, value) -> int | None:
        for obj in self.objects.values():
            if obj.value is value:
                return obj.num
        return None

    def _catalog(self, cat: dict, num: int | None) -> None:
        if isinstance(self.resolve(cat.get("OpenAction")), dict):
            self._action(cat["OpenAction"], "ouverture du document (/OpenAction)", True, num, "OpenAction")
        for key, act in self._dict(cat.get("AA")).items():
            self._action(act, f"événement du document (/AA /{key})", True, num)
        names = self._dict(cat.get("Names"))
        for name, act in self._name_tree(names.get("JavaScript")):
            self._action(act, f"JavaScript de document « {name} » (/Names)", True, None)
        attachments = [self.text(spec) or name for name, spec in self._name_tree(names.get("EmbeddedFiles"))]
        if "EmbeddedFiles" in names and not attachments:
            attachments = ["déclaré(s) dans /Names, arbre illisible"]
        self.result.embedded += attachments
        form = self._dict(cat.get("AcroForm"))
        self.result.xfa = self.result.xfa or "XFA" in form
        for ref in self._list(form.get("Fields")):
            self._widget(ref, set(), 0)
        self._pages(cat.get("Pages"), set(), [0])

    def _pages(self, node, seen: set, counter: list[int], depth: int = 0) -> None:
        d = self.resolve(node)
        if not isinstance(d, dict) or id(d) in seen or depth > _MAX_DEPTH:
            return
        seen.add(id(d))
        if "Kids" in d:
            for kid in self._list(d["Kids"]):
                self._pages(kid, seen, counter, depth + 1)
            return
        counter[0] += 1
        page = counter[0]
        for key, act in self._dict(d.get("AA")).items():
            self._action(act, f"page {page} (/AA /{key})", True, self._ref_num(node))
        for annot in self._list(d.get("Annots")):
            self._widget(annot, set(), 0, page)

    def _widget(self, node, seen: set, depth: int, page: int | None = None) -> None:
        """Annotation ou champ de formulaire (et ses enfants)."""
        d = self.resolve(node)
        if not isinstance(d, dict) or id(d) in seen or depth > _MAX_DEPTH:
            return
        seen.add(id(d))
        label = f"champ « {self.text(d['T'])} »" if "T" in d else f"annotation /{d.get('Subtype', '?')}"
        if page:
            label += f" (page {page})"
        num = self._ref_num(node)
        if d.get("Subtype") == "RichMedia":
            self.result.rich_media = True
        if d.get("Subtype") == "FileAttachment" and "FS" in d:
            self.result.embedded.append(self.text(d["FS"]) or "pièce jointe d'annotation")
        if "A" in d:
            self._action(d["A"], f"{label} (/A, au clic)", False, num, "A")
        for key, act in self._dict(d.get("AA")).items():
            self._action(act, f"{label} (/AA /{key})", key in _AUTO_ANNOT_KEYS, num)
        for kid in self._list(d.get("Kids")):
            self._widget(kid, seen, depth + 1, page)

    def _action(self, node, trigger: str, auto: bool, container: int | None,
                key: str = "", depth: int = 0) -> None:
        act = self.resolve(node)
        if not isinstance(act, dict) or depth > 32:
            return
        if id(act) in self._visited:
            # Même action atteinte par deux chemins (champ et annotation) : garder le plus grave
            for s in self.result.scripts:
                if s.obj == (self._ref_num(node) or container) and auto and not s.auto:
                    s.auto, s.trigger = True, trigger
            return
        self._visited.add(id(act))
        num = self._ref_num(node) or container
        # Emplacement de l'action pour la relire déchiffrée : son propre objet, ou sa clé dans le parent
        where = (node.num, ()) if isinstance(node, Ref) else (container, (key,) if key else ())
        kind = act.get("S")
        if "JS" in act:
            js = act["JS"]
            code = self.text(js, where[0], where[1] + ("JS",))
            self.result.scripts.append(Script(code, trigger, js.num if isinstance(js, Ref) else num, auto))
        if kind == "Launch":
            win = self._dict(act.get("Win"))
            target = self.text(act.get("F") or win.get("F")) or "cible non lisible"
            params = text_of(win.get("P")) if isinstance(win.get("P"), bytes) else ""
            self.result.launches.append(f"{target}{' ' + params if params else ''} - {trigger}, obj {num}")
        elif kind == "URI":
            url = self.text(act.get("URI"), where[0], where[1] + ("URI",))
            self._url(url)
            if auto:
                self.result.auto_external.append(f"/URI {url or 'cible illisible'} - {trigger}, obj {num}")
        elif kind in ("SubmitForm", "GoToR", "GoToE", "ImportData", "RichMediaExecute"):
            target = self.text(act.get("F")) if "F" in act else ""
            self.result.other_actions.append(f"/{kind} {target} - {trigger}".replace("  ", " "))
            self._url(target)
            if auto:
                self.result.auto_external.append(f"/{kind} {target or 'cible illisible'} - {trigger}, obj {num}")
        nxt = act.get("Next")
        for n in self._list(nxt) if isinstance(self.resolve(nxt), list) else ([nxt] if nxt else []):
            self._action(n, trigger, auto, num, "Next", depth + 1)

    def _orphans(self) -> None:
        """Actions qu'aucun déclencheur connu n'atteint (JavaScript, /Launch, URL...)."""
        for obj in list(self.objects.values()):
            for d in _dicts(obj.value):
                if id(d) not in self._visited and ("JS" in d or d.get("S") in _ACTION_KINDS):
                    self._action(d, "déclencheur non identifié", False, obj.num)
        loose = sum(isinstance(o.value, dict) and o.value.get("Type") == "EmbeddedFile" for o in self.objects.values())
        if loose and not self.result.embedded:
            self.result.embedded.append(f"{loose} flux /EmbeddedFile non référencé(s)")

    def _name_tree(self, node, depth: int = 0, seen: set | None = None):
        seen = set() if seen is None else seen
        d = self.resolve(node)
        if not isinstance(d, dict) or id(d) in seen or depth > _MAX_DEPTH:
            return
        seen.add(id(d))
        pairs = self._list(d.get("Names"))
        for i in range(0, len(pairs) - 1, 2):
            yield ("nom chiffré" if self.result.encrypted else text_of(self.resolve(pairs[i]))), pairs[i + 1]
        for kid in self._list(d.get("Kids")):
            yield from self._name_tree(kid, depth + 1, seen)

    def _dict(self, value) -> dict:
        value = self.resolve(value)
        return value if isinstance(value, dict) else {}

    def _list(self, value) -> list:
        value = self.resolve(value)
        return value if isinstance(value, list) else []

    @staticmethod
    def _ref_num(node) -> int | None:
        return node.num if isinstance(node, Ref) else None

    def _url(self, url: str) -> None:
        url = url.strip()
        if re.match(r"(?i)(https?|ftp|file|smb)://|\\\\", url) and url not in self.result.urls:
            self.result.urls.append(url)


def _dicts(value, depth: int = 0):
    if depth > _MAX_DEPTH:
        return
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from _dicts(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            yield from _dicts(v, depth + 1)


# ── Filtres ───────────────────────────────────────────────────────────────────

def _inflate(data: bytes) -> bytes | None:
    for wbits in (15, -15):
        try:
            return zlib.decompressobj(wbits).decompress(data, _MAX_DECODED)
        except zlib.error:
            continue
    return None


def _unhex(data: bytes) -> bytes | None:
    data = data.split(b">", 1)[0]
    digits = re.sub(rb"[^0-9A-Fa-f]", b"", data)
    try:
        return binascii.unhexlify(digits + b"0" * (len(digits) % 2))
    except binascii.Error:
        return None


def _a85(data: bytes) -> bytes | None:
    data = re.sub(rb"\s", b"", data)
    data = data[2:] if data.startswith(b"<~") else data
    data = data.split(b"~>", 1)[0]
    try:
        return base64.a85decode(data)
    except ValueError:
        return None


def _lzw(data: bytes) -> bytes:
    table = [bytes([i]) for i in range(256)] + [b"", b""]
    out, prev, width, buf, nbits = bytearray(), None, 9, 0, 0
    for byte in data:
        buf, nbits = (buf << 8) | byte, nbits + 8
        while nbits >= width:
            nbits -= width
            code, buf = (buf >> nbits) & ((1 << width) - 1), buf & ((1 << nbits) - 1)
            if code == 256:
                table, width, prev = table[:258], 9, None
                continue
            if code == 257:
                return bytes(out)
            if code < len(table):
                entry = table[code]
            elif prev is not None and code == len(table):
                entry = prev + prev[:1]
            else:
                return bytes(out)
            out += entry
            if len(out) > _MAX_DECODED:
                return bytes(out[:_MAX_DECODED])
            if prev is not None:
                table.append(prev + entry[:1])
            prev = entry
            if len(table) + 1 >= (1 << width) and width < 12:
                width += 1
    return bytes(out)


def _run_length(data: bytes) -> bytes:
    out, i = bytearray(), 0
    while i < len(data) and len(out) <= _MAX_DECODED:
        n = data[i]
        if n == 128:
            break
        if n < 128:
            out += data[i + 1:i + 2 + n]
            i += n + 2
        else:
            out += data[i + 1:i + 2] * (257 - n)
            i += 2
    return bytes(out)


# ── Analyse ───────────────────────────────────────────────────────────────────

def _xmp(doc: _Document) -> dict[str, str]:
    for obj in doc.objects.values():
        if isinstance(obj.value, dict) and obj.value.get("Subtype") == "XML" and obj.stream is not None:
            xml = doc.stream_data(obj) or b""
            found = {}
            for m in re.finditer(rb"(xmp:CreateDate|xmp:ModifyDate|xmp:MetadataDate|xmp:CreatorTool|"
                                 rb"pdf:Producer|xmpMM:DocumentID|xmpMM:InstanceID)"
                                 rb"(?:\s*=\s*\"([^\"]*)\"|>([^<]*)<)", xml):
                found.setdefault(m.group(1).decode(), (m.group(2) or m.group(3) or b"").decode("utf-8", "replace"))
            if found:
                return found
    return {}


def analyze_pdf(path: str, reader=None) -> PdfThreats:
    """Analyse de menace d'un PDF ; `reader` : lecteur pypdf déjà déchiffré, s'il existe."""
    with open(path, "rb") as fh:
        data = fh.read(MAX_FILE_BYTES + 1)
    doc = _Document(data[:MAX_FILE_BYTES], reader)
    r = doc.result
    if len(data) > MAX_FILE_BYTES:
        r.partial.append(f"fichier tronqué à {MAX_FILE_BYTES // 2**20} Mo pour l'analyse")
    doc.index()
    if not doc.objects:
        r.partial.append("aucun objet PDF reconnu : fichier corrompu ou pas un PDF")
    r.encrypted = any("Encrypt" in t for t in doc.trailers)
    if r.encrypted and reader is None:
        r.partial.append("PDF chiffré (mot de passe requis) : chaînes et flux illisibles, "
                         "le code éventuel n'a pas pu être lu")
    doc.walk()

    info = next((doc._dict(t["Info"]) for t in reversed(doc.trailers) if "Info" in t), {})
    if not r.encrypted:
        r.info = {str(k): text_of(doc.resolve(v)) for k, v in info.items()
                  if isinstance(doc.resolve(v), (bytes, str))}
    r.xmp = _xmp(doc)
    r.linearized = "Linearized" in doc.names
    eofs = data.count(b"%%EOF")
    r.revisions = max(1, eofs - (1 if r.linearized and eofs > 1 else 0))

    # Flux décodés : shellcode, entropie anormale, URLs citées
    js_objects = {s.obj for s in r.scripts}
    for obj in list(doc.objects.values()):
        if obj.stream is None or r.encrypted:
            continue
        decoded = doc.stream_data(obj)
        if not decoded:
            continue
        kind = obj.value.get("Type") if isinstance(obj.value, dict) else None
        if any(m in decoded for m in _SHELLCODE):
            r.shellcode.append(f"obj {obj.num}")
        if kind != "EmbeddedFile" and len(decoded) >= 1024 and calculate_entropy(decoded[:256 * 1024]) > 7.5:
            r.high_entropy.append(obj.num)
        if obj.num not in js_objects:
            for u in _URL.findall(decoded):
                url = u.decode("ascii", "ignore").rstrip(".,;:!?")
                if url not in r.text_urls:
                    r.text_urls.append(url)
    for s in r.scripts:
        for u in _URL.findall(s.code.encode("latin-1", "ignore")):
            doc._url(u.decode("ascii", "ignore").rstrip(".,;:!?'\""))
        if any(m in s.code.encode("latin-1", "ignore") for m in _SHELLCODE) and f"obj {s.obj}" not in r.shellcode:
            r.shellcode.append(f"obj {s.obj}")
    r.text_urls = [u for u in r.text_urls if u not in r.urls]
    if doc.unsupported:
        r.partial.append("filtre(s) non décodé(s) : " + ", ".join(sorted(doc.unsupported)))
    r.tags = ["/" + n for n in _SUSPICIOUS_NAMES if n in doc.names]
    r.obfuscated_names = sorted("/" + n for n in doc.obfuscated)
    r.score, r.level, r.reasons = _score(r)
    return r


def _score(r: PdfThreats) -> tuple[int, str, list[tuple[int, str]]]:
    reasons: list[tuple[int, str]] = []
    auto = [s for s in r.scripts if s.auto]
    if auto:
        s = auto[0]
        reasons.append((80, f"JavaScript exécuté sans clic : {s.trigger}, obj {s.obj}"))
    elif any(s.trigger == "déclencheur non identifié" for s in r.scripts):
        s = next(s for s in r.scripts if s.trigger == "déclencheur non identifié")
        reasons.append((25, f"JavaScript présent, déclencheur non identifié (obj {s.obj})"))
    elif r.scripts:
        s = r.scripts[0]
        reasons.append((15, f"JavaScript déclenché par l'utilisateur : {s.trigger}, obj {s.obj}"))
    if r.launches:
        reasons.append((50, f"/Launch : lancement de programme ({r.launches[0]})"))
    if r.auto_external:   # hameçonnage : le navigateur s'ouvre sur l'URL dès l'ouverture du PDF
        reasons.append((30, f"ressource externe ouverte sans clic : {r.auto_external[0]}"))
    if r.shellcode:
        reasons.append((50, f"shellcode / heap spray encodé ({', '.join(r.shellcode[:3])})"))
    codes = [s.code for s in r.scripts]
    apis = sorted({a for a in _EXPLOIT_APIS for c in codes if a in c})
    if apis:
        reasons.append((20, f"API Acrobat visées par des exploits connus : {', '.join(apis)}"))
    tricks = sorted({t for t in _OBFUSCATION for c in codes if t in c})
    if tricks:
        reasons.append((10, f"JavaScript obfusqué ({', '.join(tricks)})"))
    if r.obfuscated_names:
        reasons.append((20, f"noms PDF encodés en #xx pour échapper à la détection ({', '.join(r.obfuscated_names)})"))
    if r.embedded:
        reasons.append((15, f"fichier(s) joint(s) : {', '.join(r.embedded[:3])}"))
    if r.rich_media:
        reasons.append((15, "contenu /RichMedia (Flash ou vidéo embarqués)"))
    if r.xfa:
        reasons.append((10, "formulaire XFA (scripts XML, vecteur d'exploits)"))
    if r.high_entropy:
        reasons.append((10, f"flux encore aléatoire(s) après décodage : obj {', '.join(map(str, r.high_entropy[:5]))}"))
    if r.other_actions:
        reasons.append((5, f"action vers l'extérieur : {r.other_actions[0]}"))
    score = min(100, sum(p for p, _ in reasons))
    if score >= 50:
        level = "Critique"
    elif score >= 30:
        level = "Élevé"
    elif score >= 15:
        level = "Moyen"
    elif score > 0:
        level = "Faible"
    else:
        level = "Indéterminé" if r.partial else "Faible"
    return score, level, reasons
