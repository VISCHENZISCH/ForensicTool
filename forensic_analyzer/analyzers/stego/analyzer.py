"""Analyzer steganographie - LSB, DCT, canal alpha, detection chi-square."""
from __future__ import annotations

import math
import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.deps import HAS_PIL, PILImage
from forensic_analyzer.utils.logger import get_logger

log = get_logger("stego")


def _chi_square_test(data: bytes, threshold: float = 0.05) -> dict:
    """Test du chi-carre sur les LSB pour detecter de la steganographie."""
    if len(data) < 256:
        return {"detected": False, "score": 0.0, "detail": "Donnees insuffisantes"}

    observed = [0] * 256
    for b in data:
        observed[b] += 1

    n = len(data)
    expected = n / 256.0
    if expected == 0:
        return {"detected": False, "score": 0.0, "detail": "Donnees vides"}

    chi2 = sum((obs - expected) ** 2 / expected for obs in observed)

    # Degres de liberte = 255
    # Valeur critique a 5% pour 255 ddl ~ 293.2
    critical = 293.2
    p_approx = max(0.0, 1.0 - (chi2 / (critical * 2)))

    detected = chi2 < critical * 0.7
    return {
        "detected": detected,
        "score": round(chi2, 2),
        "critical_value": critical,
        "p_value_approx": round(p_approx, 4),
        "detail": "Anomalie LSB detectee (distribution trop uniforme)" if detected
                  else "Distribution LSB normale"
    }


def _extract_lsb(img, bits: int = 1, channels: str = "RGB") -> bytes:
    """Extrait les bits de poids faible d'une image."""
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")

    pixels = list(img.getdata())
    channel_map = {"R": 0, "G": 1, "B": 2, "A": 3}
    target_channels = [channel_map[c] for c in channels if c in channel_map]

    extracted_bits = []
    mask = (1 << bits) - 1

    for pixel in pixels:
        for ch in target_channels:
            if ch < len(pixel):
                extracted_bits.append(pixel[ch] & mask)

    # Reconstituer les octets
    result = bytearray()
    bit_buffer = 0
    bit_count = 0
    for val in extracted_bits:
        bit_buffer = (bit_buffer << bits) | val
        bit_count += bits
        while bit_count >= 8:
            bit_count -= 8
            result.append((bit_buffer >> bit_count) & 0xFF)

    return bytes(result)


def _analyze_alpha_channel(img) -> dict:
    """Detecte un payload cache dans le canal alpha d'une image PNG."""
    if img.mode != "RGBA":
        return {"has_alpha": False, "detail": "Pas de canal alpha"}

    pixels = list(img.getdata())
    alpha_values = [p[3] for p in pixels]

    set(alpha_values)
    non_255 = sum(1 for a in alpha_values if a != 255)
    non_0_non_255 = sum(1 for a in alpha_values if a not in (0, 255))

    suspicious = non_0_non_255 > len(alpha_values) * 0.01

    # Extraire les LSB du canal alpha
    alpha_lsb = bytes([a & 1 for a in alpha_values[:1024]])
    entropy = _byte_entropy(alpha_lsb)

    return {
        "has_alpha": True,
        "total_pixels": len(alpha_values),
        "non_opaque_pixels": non_255,
        "suspicious_alpha_pixels": non_0_non_255,
        "alpha_lsb_entropy": round(entropy, 4),
        "suspicious": suspicious,
        "detail": "Canal alpha suspect - payload possible" if suspicious
                  else "Canal alpha normal"
    }


def _analyze_dct_jpeg(path: str) -> dict:
    """Analyse les coefficients DCT d'un JPEG pour detecter la stego."""
    try:
        with open(path, "rb") as f:
            data = f.read()

        # Recherche des marqueurs JPEG DHT / DQT
        dqt_count = data.count(b'\xFF\xDB')
        dht_count = data.count(b'\xFF\xC4')

        # Analyse de la distribution des octets dans les segments SOS
        sos_marker = data.find(b'\xFF\xDA')
        if sos_marker == -1:
            return {"analyzed": False, "detail": "Pas de segment SOS trouve"}

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
    except Exception: pass
    return comments

def _check_stego_signatures(path: str) -> list[str]:
    """Vérifie la présence d'outils connus via signatures."""
    found = []
    try:
        with open(path, "rb") as f:
            data = f.read()
            if b"OpenStego" in data: found.append("OpenStego")
            if b"SilentEye" in data: found.append("SilentEye")
            if b"OutGuess" in data: found.append("OutGuess")
    except Exception: pass
    return found


def _byte_entropy(data: bytes) -> float:
    """Calcule l'entropie de Shannon d'une sequence d'octets."""
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
    """Detecte et extrait la steganographie dans les images et audios."""
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
                        frames = w.readframes(w.getnframes()[:1000000]) # 1MB max pour perfs
                        if frames:
                            lsb_audio = bytes([b & 1 for b in frames])
                            cat_strs = categorize_strings(extract_strings_with_offsets(lsb_audio, min_length=5))
                            
                            flat_meta["Audio LSB"] = "Analysé"
                            flat_meta["Spectrogramme"] = "Vérifier avec Audacity pour patterns visuels"
                            
                            total_iocs = sum(len(items) for items in cat_strs.values())
                            if total_iocs > 0:
                                flat_meta["Strings Audio (LSB)"] = f"{total_iocs} IOCs cachés"
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
                    # Strings dans les pixels de ce canal
                    ch_strs = extract_strings_with_offsets(ch_data, min_length=6)
                    if len(ch_strs) > 10: # On cherche vraiment s'il y a de la data
                        lsb_strings_found[ch] = len(ch_strs)
                        suspicion_score += 1
                        
                if lsb_strings_found:
                    flat_meta["Strings LSB (Plans de bits)"] = str(lsb_strings_found)
                    suspicion_score += 3
                    
                lsb_data = _extract_lsb(img, bits=1, channels="RGB")
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
                    except Exception:
                        pass  # TODO: log.debug(exc)
                        results["alpha_analysis"] = {"detail": "Conversion RGBA echouee"}

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
                    except Exception:
                        pass  # TODO: log.debug(exc)
                        pass # Steghide non installé ou erreur

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
    """Renvoie un apercu ASCII safe des donnees extraites."""
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:max_len])
    return printable
