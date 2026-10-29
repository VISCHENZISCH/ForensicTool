"""Analyzer stéganographie - LSB, DCT, canal alpha, détection chi-square."""
from __future__ import annotations

import math
import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.deps import HAS_PIL, PILImage
from forensic_analyzer.utils.logger import get_logger

log = get_logger("stego")


def _chi_square_test(data: bytes) -> dict:
    """Test du chi-carre sur les LSB pour détecter de la stéganographie."""
    if len(data) < 256:
        return {"detected": False, "score": 0.0, "detail": "Données insuffisantes"}

    observed = [0] * 256
    for b in data:
        observed[b] += 1

    n = len(data)
    expected = n / 256.0
    if expected == 0:
        return {"detected": False, "score": 0.0, "detail": "Données vides"}

    chi2 = sum((obs - expected) ** 2 / expected for obs in observed)

    # Degrés de liberté = 255
    # Valeur critique à 5 % pour 255 ddl ~ 293.2
    critical = 293.2
    p_approx = max(0.0, 1.0 - (chi2 / (critical * 2)))

    detected = chi2 < critical * 0.7
    return {
        "detected": detected,
        "score": round(chi2, 2),
        "critical_value": critical,
        "p_value_approx": round(p_approx, 4),
        "detail": "Anomalie LSB détectée (distribution trop uniforme)" if detected
                  else "Distribution LSB normale"
    }


# Valeur des `bits` bits de poids faible de chaque octet, en binaire sur `bits` caractères
_LSB_TABLES = {bits: [format(v & ((1 << bits) - 1), f"0{bits}b") for v in range(256)] for bits in (1, 2, 4)}


# Un message LSB commence au premier pixel : au-delà, une image piégée (bombe de décompression)
# ferait construire des chaînes de plusieurs Go
_MAX_LSB_PIXELS = 4_000_000


def _extract_lsb(img, bits: int = 1, channels: str = "RGB") -> bytes:
    """Extrait les bits de poids faible d'une image (canaux dans l'ordre demandé, pixel par pixel)."""
    width, height = img.size
    if width * height > _MAX_LSB_PIXELS:
        img = img.crop((0, 0, width, max(1, _MAX_LSB_PIXELS // width)))
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    raw = img.tobytes()
    stride = len(img.mode)
    selected = [ch for ch in ("RGBA".index(c) for c in channels if c in "RGBA") if ch < stride]
    if not selected:
        return b""
    if len(selected) == stride:
        samples = raw
    else:
        samples = bytearray(len(raw) // stride * len(selected))
        for i, ch in enumerate(selected):
            samples[i::len(selected)] = raw[ch::stride]

    bitstring = "".join(map(_LSB_TABLES[bits].__getitem__, samples))
    usable = len(bitstring) - len(bitstring) % 8
    if not usable:
        return b""
    return int(bitstring[:usable], 2).to_bytes(usable // 8, "big")


def _analyze_alpha_channel(img) -> dict:
    """Détecte un payload cache dans le canal alpha d'une image PNG."""
    if img.mode != "RGBA":
        return {"has_alpha": False, "detail": "Pas de canal alpha"}

    alpha = img.getchannel("A").tobytes()
    non_255 = len(alpha) - alpha.count(255)
    non_0_non_255 = non_255 - alpha.count(0)
    suspicious = non_0_non_255 > len(alpha) * 0.01
    entropy = _byte_entropy(bytes(a & 1 for a in alpha[:1024]))

    return {
        "has_alpha": True,
        "total_pixels": len(alpha),
        "non_opaque_pixels": non_255,
        "suspicious_alpha_pixels": non_0_non_255,
        "alpha_lsb_entropy": round(entropy, 4),
        "suspicious": suspicious,
        "detail": "Canal alpha suspect - payload possible" if suspicious
                  else "Canal alpha normal"
    }


def _analyze_dct_jpeg(path: str) -> dict:
    """Analyse les coefficients DCT d'un JPEG pour détecter la stego."""
    try:
        with open(path, "rb") as f:
            data = f.read()

        # Recherche des marqueurs JPEG DHT / DQT
        dqt_count = data.count(b'\xFF\xDB')
        dht_count = data.count(b'\xFF\xC4')

        # Analyse de la distribution des octets dans les segments SOS
        sos_marker = data.find(b'\xFF\xDA')
        if sos_marker == -1:
            return {"analyzed": False, "detail": "Pas de segment SOS trouvé"}

        sos_data = data[sos_marker + 2:]
        eoi = sos_data.find(b'\xFF\xD9')
        if eoi > 0:
            sos_data = sos_data[:eoi]

        if len(sos_data) < 100:
            return {"analyzed": False, "detail": "Segment SOS trop court"}

        chi_result = _chi_square_test(sos_data)
        entropy = _byte_entropy(sos_data[:4096])

        return {
            "analyzed": True,
            "dqt_tables": dqt_count,
            "dht_tables": dht_count,
            "sos_size": len(sos_data),
            "sos_entropy": round(entropy, 4),
            "chi_square": chi_result,
            "detail": "Coefficients DCT suspects" if chi_result["detected"]
                      else "Coefficients DCT normaux"
        }
    except Exception as exc:
        return {"analyzed": False, "detail": str(exc)}

def _extract_jpeg_comments(path: str) -> list[str]:
    """Extrait les segments COM (Commentaires) d'un JPEG."""
    comments = []
    try:
        with open(path, "rb") as f:
            data = f.read()
        idx = 0
        while idx < len(data) - 1:
            if data[idx] == 0xFF and data[idx+1] == 0xFE: # COM marker
                length = int.from_bytes(data[idx+2:idx+4], 'big')
                comment = data[idx+4:idx+2+length]
                comments.append(comment.decode('utf-8', 'ignore'))
                idx += 2 + length
            else:
                idx += 1
    except Exception as exc:
        log.debug("Commentaires JPEG illisibles dans %s : %s", path, exc)
    return comments

def _check_stego_signatures(path: str) -> list[str]:
    """Vérifie la présence d'outils connus via signatures."""
    signatures = (b"OpenStego", b"SilentEye", b"OutGuess")
    overlap = max(len(s) for s in signatures) - 1
    found: list[str] = []
    try:
        with open(path, "rb") as f:
            tail = b""
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                window = tail + chunk
                for sig in signatures:
                    name = sig.decode()
                    if name not in found and sig in window:
                        found.append(name)
                tail = window[-overlap:]
    except OSError as exc:
        log.debug("Lecture impossible pour les signatures stego '%s' : %s", path, exc)
    return found


def _byte_entropy(data: bytes) -> float:
    """Calcule l'entropie de Shannon d'une séquence d'octets."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / n
            entropy -= p * math.log2(p)
    return entropy


class StegoAnalyzer(BaseAnalyzer):
    """Détecte et extrait la stéganographie dans les images et audios."""
    name = "stego"
    supported_extensions = ('.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.wav')

    def analyze(self, path: str) -> FindingModel | None:
        try:
            results: dict = {"file": os.path.basename(path)}
            flat_meta: dict = {}
            suspicion_score = 0
            
            from forensic_analyzer.utils.strings_extractor import extract_strings_with_offsets, categorize_strings
            
            # --- ANALYSE AUDIO (WAV) ---
            if path.lower().endswith('.wav'):
                import wave
                try:
                    with wave.open(path, "rb") as w:
                        width = w.getsampwidth()
                        frames = w.readframes(min(w.getnframes(), 1_000_000))
                        if frames:
                            # LSB de l'octet de poids faible de chaque échantillon (PCM little-endian), 8 par octet
                            bits = [b & 1 for b in frames[::width]]
                            lsb_audio = bytes(int("".join(map(str, bits[i:i + 8])), 2)
                                              for i in range(0, len(bits) - 7, 8))
                            cat_strs = categorize_strings(extract_strings_with_offsets(lsb_audio, min_length=5))
                            
                            flat_meta["Audio LSB"] = "Analysé"
                            flat_meta["Spectrogramme"] = "Vérifier avec Audacity pour patterns visuels"
                            
                            total_iocs = sum(len(items) for items in cat_strs.values())
                            if total_iocs > 0:
                                flat_meta["Strings Audio (LSB)"] = f"{total_iocs} IOCs cachés"
                                suspicion_score += 5
                            hidden = [t for _, t in extract_strings_with_offsets(lsb_audio, min_length=16)]
                            if hidden:
                                flat_meta["Message LSB (audio)"] = " | ".join(t[:80] for t in hidden[:3])
                                suspicion_score += 5
                except Exception as e:
                    flat_meta["Audio LSB"] = f"Erreur: {e}"
                    
                flat_meta["Verdict"] = "STEGO PROBABLE" if suspicion_score >= 3 else "CLEAN"
                return FindingModel(type="stego_audio", file=os.path.abspath(path), metadata=flat_meta, extra={})

            # --- ANALYSE IMAGE ---
            if not HAS_PIL:
                log.error("Pillow requis pour l'analyse stego - pip install Pillow")
                return None

            with PILImage.open(path) as img:
                width, height = img.size
                results["dimensions"] = f"{width}x{height}"
                results["mode"] = img.mode
                results["format"] = str(img.format)

                # 1. Analyse LSB Séparée (zsteg-like)
                lsb_strings_found = {}
                for ch in ("R", "G", "B", "A"):
                    if ch == "A" and img.mode != "RGBA": continue
                    ch_data = _extract_lsb(img, bits=1, channels=ch)
                    ch_strs = extract_strings_with_offsets(ch_data, min_length=6)
                    if len(ch_strs) > 10:
                        lsb_strings_found[ch] = len(ch_strs)
                        suspicion_score += 1
                        
                if lsb_strings_found:
                    flat_meta["Strings LSB (Plans de bits)"] = str(lsb_strings_found)
                    suspicion_score += 3
                    
                lsb_data = _extract_lsb(img, bits=1, channels="RGB")
                # Message entrelace sur R, G et B : invisible canal par canal.
                # 16 caractères imprimables d'affilée n'arrivent pas par hasard (~1e-7 par position)
                rgb_strs = [s for _, s in extract_strings_with_offsets(lsb_data, min_length=16)]
                if rgb_strs:
                    flat_meta["Strings LSB (RGB entrelace)"] = " | ".join(s[:80] for s in rgb_strs[:3])
                    suspicion_score += 5
                lsb_sample = lsb_data[:4096]
                lsb_entropy = _byte_entropy(lsb_sample)
                chi_lsb = _chi_square_test(lsb_sample)

                results["lsb_analysis"] = {
                    "extracted_size": len(lsb_data),
                    "entropy": round(lsb_entropy, 4),
                    "chi_square": chi_lsb,
                    "printable_preview": _safe_preview(lsb_data[:256]),
                }

                # 2. Canal alpha (PNG)
                if img.mode == "RGBA" or img.format == "PNG":
                    try:
                        rgba = img.convert("RGBA")
                        results["alpha_analysis"] = _analyze_alpha_channel(rgba)
                    except Exception as exc:
                        log.debug("Conversion RGBA échouée : %s", exc)
                        results["alpha_analysis"] = {"detail": "Conversion RGBA échouée"}

                # 3. Multi-bit LSB (2 et 4 bits)
                for bits in (2, 4):
                    key = f"lsb_{bits}bit"
                    multi_data = _extract_lsb(img, bits=bits, channels="RGB")
                    multi_entropy = _byte_entropy(multi_data[:4096])
                    results[key] = {
                        "entropy": round(multi_entropy, 4),
                        "printable_preview": _safe_preview(multi_data[:128]),
                    }

            # 4. DCT pour JPEG & Commentaires
            if path.lower().endswith(('.jpg', '.jpeg')):
                results["dct_analysis"] = _analyze_dct_jpeg(path)
                coms = _extract_jpeg_comments(path)
                if coms:
                    flat_meta["JPEG Commentaires (COM)"] = " | ".join(coms)
                    suspicion_score += 1
                
            # 5. Steghide Brute Force & Outils Connus
            sigs = _check_stego_signatures(path)
            if sigs:
                flat_meta["Signatures d'Outils (Clair)"] = ", ".join(sigs)
                suspicion_score += 5
                
            if path.lower().endswith(('.jpg', '.jpeg', '.bmp', '.wav')):
                import subprocess
                wordlist = ["", "password", "123456", "admin", "steghide", "secret", "hidden"]
                for w in wordlist:
                    try:
                        proc = subprocess.run(
                            ["steghide", "info", "-p", w, path], 
                            capture_output=True, text=True, timeout=2
                        )
                        if "format:" in proc.stdout:
                            flat_meta["Outil Détecté"] = f"Steghide (Mot de passe: '{w}') (CRITIQUE)"
                            suspicion_score += 10
                            break
                    except FileNotFoundError:
                        log.debug("steghide non installé, test des mots de passe ignoré.")
                        break
                    except subprocess.TimeoutExpired:
                        continue
                    except Exception as exc:
                        log.debug("steghide en erreur : %s", exc)

            # Verdict global
            if chi_lsb.get("detected"): suspicion_score += 3
            if results.get("alpha_analysis", {}).get("suspicious"): suspicion_score += 2
            if results.get("dct_analysis", {}).get("chi_square", {}).get("detected"): suspicion_score += 3

            if suspicion_score >= 5: verdict = "STEGO CERTAINE (Outil trouvé/Strings LSB)"
            elif suspicion_score >= 3: verdict = "STEGO PROBABLE"
            elif suspicion_score >= 1: verdict = "SUSPECT"
            else: verdict = "CLEAN"

            flat_meta.update({
                "Format": results.get("format", "?"),
                "Dimensions": results.get("dimensions", "?"),
                "Mode": results.get("mode", "?"),
                "Verdict": verdict,
                "Score suspicion": str(suspicion_score),
                "LSB Entropy": str(results.get("lsb_analysis", {}).get("entropy", "0")),
                "LSB Chi2 Detect": str(chi_lsb.get("detected", False)),
            })

            if "alpha_analysis" in results:
                flat_meta["Alpha Suspect"] = str(results["alpha_analysis"].get("suspicious", False))
            if "dct_analysis" in results:
                flat_meta["DCT Suspect"] = str(results["dct_analysis"].get("chi_square", {}).get("detected", False))

            return FindingModel(
                type="stego",
                file=os.path.abspath(path),
                metadata=flat_meta,
                extra=results,
            )
        except Exception as exc:
            log.error("Erreur stego '%s' : %s", os.path.basename(path), exc)
            return None


def _safe_preview(data: bytes, max_len: int = 80) -> str:
    """Renvoie un aperçu ASCII safe des données extraites."""
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:max_len])
    return printable
