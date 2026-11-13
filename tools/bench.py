#!/usr/bin/env python3
"""Banc de mesure du scan automatique sur un corpus synthétique (aucun accès réseau).

Génère un dossier de preuves réaliste (journaux, PDF, PE, ELF, images, CSV, binaires, archive),
chronomètre auto_scan, compte les ouvertures de fichiers par preuve (hook d'audit `open`) et le
temps d'import du CLI. Une empreinte des résultats permet de vérifier qu'une optimisation ne
change rien au rapport.

    venv/bin/python tools/bench.py                 # 2 000 fichiers, 3 passes
    venv/bin/python tools/bench.py --files 500 --runs 1 --profile
    venv/bin/python tools/bench.py --keep /chemin/corpus   # garder le corpus pour comparer
"""

from __future__ import annotations

import argparse
import cProfile
import glob
import hashlib
import io
import json
import os
import pstats
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_SEED = 20261112
_IPS = ["10.0.0.5", "192.168.1.23", "203.0.113.7", "198.51.100.42", "185.220.101.4"]
_PATHS = ["/", "/login", "/wp-admin/", "/index.php?id=1' OR '1'='1", "/../../etc/passwd", "/api/v1/users"]


# ── Génération du corpus ─────────────────────────────────────────────────────


def _auth_log(rng: random.Random, lines: int) -> bytes:
    out = []
    for i in range(lines):
        ip = rng.choice(_IPS)
        sec = i % 60
        if rng.random() < 0.6:
            out.append(f"Nov 12 10:{i % 60:02d}:{sec:02d} srv sshd[{1000 + i}]: Failed password for root from {ip} port 22 ssh2")
        else:
            out.append(f"Nov 12 10:{i % 60:02d}:{sec:02d} srv sshd[{1000 + i}]: Accepted password for admin from {ip} port 22")
    return ("\n".join(out) + "\n").encode()


def _access_log(rng: random.Random, lines: int) -> bytes:
    out = []
    for i in range(lines):
        ip, path = rng.choice(_IPS), rng.choice(_PATHS)
        out.append(f'{ip} - - [12/Nov/2026:10:{i % 60:02d}:00 +0000] "GET {path} HTTP/1.1" 200 {rng.randint(100, 9000)} "-" "curl/8"')
    return ("\n".join(out) + "\n").encode()


def _pdf(rng: random.Random) -> bytes:
    js = b"/OpenAction << /S /JavaScript /JS (app.alert(1)) >>" if rng.random() < 0.2 else b""
    body = b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R " + js + b" >> endobj\n"
    body += b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
    body += b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj\n"
    return body + b"trailer << /Root 1 0 R >>\n%%EOF\n"


def _png(rng: random.Random, size: int = 32) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    raw = b"".join(b"\x00" + bytes(rng.getrandbits(8) for _ in range(size * 3)) for _ in range(size))
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def _jpeg(rng: random.Random) -> bytes:
    try:
        from PIL import Image

        img = Image.frombytes("RGB", (32, 32), rng.randbytes(32 * 32 * 3))
        buf = io.BytesIO()
        img.save(buf, "JPEG")
        return buf.getvalue()
    except ImportError:
        return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + rng.randbytes(2048) + b"\xff\xd9"


def _csv(rng: random.Random, rows: int) -> bytes:
    lines = ["hote,ip,utilisateur,service"]
    lines += [f"srv{i},{rng.choice(_IPS)},user{i},web" for i in range(rows)]
    return ("\n".join(lines) + "\n").encode()


def _real_binaries() -> tuple[list[bytes], list[bytes]]:
    """Vrais PE (lanceurs pip/distlib) et ELF (outils système) quand ils existent, sinon factices."""
    pes = [open(p, "rb").read() for p in sorted(glob.glob(os.path.join(ROOT, "venv/lib/*/site-packages/pip/_vendor/distlib/*.exe")))[:3]]
    elfs = []
    for p in ("/bin/true", "/bin/false", "/usr/bin/env"):
        if os.path.isfile(p) and os.path.getsize(p) < 200_000:
            with open(p, "rb") as fh:
                elfs.append(fh.read())
    pes = pes or [b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + b"\x00" * 200]
    elfs = elfs or [b"\x7fELF\x02\x01\x01" + b"\x00" * 300]
    return pes, elfs


def build_corpus(dest: str, n_files: int) -> dict[str, int]:
    """Écrit `n_files` preuves dans `dest` (déterministe). Retourne le nombre par catégorie."""
    rng = random.Random(_SEED)
    pes, elfs = _real_binaries()
    kinds = Counter()
    makers = [
        ("logs", 0.18, lambda i: (f"var/log/app{i}.log", _auth_log(rng, rng.randint(20, 400)))),
        ("logs", 0.07, lambda i: (f"web/site{i}/access.log", _access_log(rng, rng.randint(50, 600)))),
        ("pdf", 0.10, lambda i: (f"docs/rapport_{i}.pdf", _pdf(rng))),
        ("pe", 0.05, lambda i: (f"bin/outil_{i}.exe", rng.choice(pes))),
        ("elf", 0.05, lambda i: (f"usr/bin/prog_{i}", rng.choice(elfs))),
        ("image", 0.08, lambda i: (f"photos/img_{i}.jpg", _jpeg(rng))),
        ("image", 0.07, lambda i: (f"photos/capture_{i}.png", _png(rng))),
        ("csv", 0.10, lambda i: (f"inventaires/parc_{i}.csv", _csv(rng, rng.randint(5, 200)))),
        ("texte", 0.10, lambda i: (f"notes/note_{i}.md", f"# Note {i}\nContact {rng.choice(_IPS)}\n".encode() * 5)),
        ("binaire", 0.20, lambda i: (f"divers/blob_{i}.bin", rng.randbytes(rng.randint(1_000, 200_000)))),
    ]
    weights = [m[1] for m in makers]
    for i in range(n_files - 1):
        kind, _, make = rng.choices(makers, weights)[0]
        rel, data = make(i)
        _write(dest, rel, data)
        kinds[kind] += 1
    # Une archive : ses fichiers sont extraits et analysés comme les autres
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for j in range(20):
            zf.writestr(f"collecte/auth_{j}.log", _auth_log(rng, 50))
        zf.writestr("collecte/outil.exe", pes[0])
    _write(dest, "archives/collecte.zip", buf.getvalue())
    kinds["archive"] += 1
    return dict(kinds)


def _write(dest: str, rel: str, data: bytes) -> None:
    path = os.path.join(dest, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


# ── Mesures ──────────────────────────────────────────────────────────────────

_OPENS: Counter = Counter()
_CORPUS = [""]


def _audit(event: str, args: tuple) -> None:
    if event == "open" and isinstance(args[0], str) and args[0].startswith(_CORPUS[0]):
        _OPENS[args[0]] += 1


def _volatile(value):
    """Retire ce qui varie d'une exécution à l'autre (dates de session, dossiers temporaires)."""
    if isinstance(value, dict):
        return {k: _volatile(v) for k, v in value.items() if k not in ("timestamp", "hashed_at", "tool")}
    if isinstance(value, list):
        return [_volatile(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"/tmp/[^\s'\":,]*?(?=/|$)", "<tmp>", value)
    return value


def normalized(report) -> str:
    """Rapport sans les champs propres à la session : identique si l'analyse donne les mêmes résultats."""
    return json.dumps(_volatile(json.loads(report.model_dump_json())), sort_keys=True, indent=1, default=str)


_MODULE_TIME: Counter = Counter()


def _timed(analyzer) -> None:
    """Chronomètre chaque module (temps CPU du thread : distingue calcul Python et attente d'E/S)."""
    original = analyzer.analyze

    def analyze(path, **kwargs):
        start = time.thread_time()
        try:
            return original(path, **kwargs)
        finally:
            _MODULE_TIME[analyzer.name] += time.thread_time() - start

    analyzer.analyze = analyze


def run_scan(corpus: str, profile: str | None):
    import logging

    from forensic_analyzer.core.scanner import auto_scan, default_registry
    from forensic_analyzer.utils.exports import set_export_root

    set_export_root(os.path.join(os.path.dirname(corpus), "export_bench"))  # extractions hors du dépôt
    logging.disable(logging.CRITICAL)  # le banc mesure l'analyse, pas l'affichage du journal
    registry = default_registry()
    for analyzer in registry.analyzers:
        _timed(analyzer)
    _MODULE_TIME.clear()
    _OPENS.clear()
    _CORPUS[0] = corpus
    prof = cProfile.Profile() if profile else None
    start = time.perf_counter()
    if prof:
        prof.enable()
    report = auto_scan(corpus, registry)
    if prof:
        prof.disable()
    elapsed = time.perf_counter() - start
    _CORPUS[0] = "\0"
    if prof and profile:
        prof.dump_stats(profile)
    return report, elapsed


def import_time(module: str, runs: int = 3) -> float:
    """Meilleur temps (s) d'un interpréteur neuf qui importe `module`."""
    best = float("inf")
    for _ in range(runs):
        start = time.perf_counter()
        subprocess.run([sys.executable, "-c", f"import {module}"], cwd=ROOT, check=True)
        best = min(best, time.perf_counter() - start)
    return best


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--files", type=int, default=2000)
    parser.add_argument("--runs", type=int, default=3, help="passes de scan (le meilleur temps est retenu)")
    parser.add_argument("--keep", help="dossier où (re)créer le corpus et le garder")
    parser.add_argument("--profile", action="store_true", help="profil cProfile de la 1re passe (top 25)")
    parser.add_argument("--json", help="écrire les mesures dans ce fichier")
    parser.add_argument("--dump", help="écrire le rapport normalisé (pour comparer avant/après)")
    args = parser.parse_args()

    workdir = tempfile.mkdtemp(prefix="fa_bench_")
    corpus = os.path.abspath(args.keep or os.path.join(workdir, "preuves"))
    shutil.rmtree(corpus, ignore_errors=True)
    kinds = build_corpus(corpus, args.files)
    size = sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(corpus) for f in fs)
    print(f"Corpus : {args.files} fichiers, {size / 1e6:.1f} Mo — {kinds}")

    sys.addaudithook(_audit)
    times, digest, opens = [], "", Counter()
    for i in range(args.runs):
        prof_path = os.path.join(workdir, "scan.prof") if args.profile and i == 0 else None
        report, elapsed = run_scan(corpus, prof_path)
        times.append(elapsed)
        dump = normalized(report)
        digest = hashlib.sha256(dump.encode()).hexdigest()[:16]
        if args.dump:
            with open(args.dump, "w", encoding="utf-8") as fh:
                fh.write(dump)
        opens = Counter(_OPENS)
        print(f"  passe {i + 1} : {elapsed:.2f} s, {len(report.findings)} constat(s), empreinte résultats {digest}")
        if prof_path:
            pstats.Stats(prof_path).sort_stats("cumulative").print_stats(25)
            pstats.Stats(prof_path).sort_stats("tottime").print_stats(15)
    per_file = sorted(opens.values()) or [0]
    measures = {
        "fichiers": args.files,
        "scan_meilleur_s": round(min(times), 3),
        "scan_passes_s": [round(t, 3) for t in times],
        "ouvertures_par_fichier_moy": round(sum(per_file) / len(per_file), 2),
        "ouvertures_par_fichier_max": per_file[-1],
        "cpu_par_module_s": {k: round(v, 2) for k, v in _MODULE_TIME.most_common()},
        "constats": len(report.findings),
        "erreurs_modules": len(report.analysis_errors),
        "empreinte_resultats": digest,
        "import_cli_s": round(import_time("forensic_analyzer.cli.main"), 3),
        "import_menu_s": round(import_time("forensic_analyzer.cli.menu"), 3),
        "import_registre_s": round(import_time("forensic_analyzer.core.scanner"), 3),
    }
    print(json.dumps(measures, indent=2, ensure_ascii=False))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(measures, fh, indent=2, ensure_ascii=False)
    if not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
