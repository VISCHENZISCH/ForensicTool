"""Analyzer steganographie - LSB, DCT, canal alpha, detection chi-square."""
from __future__ import annotations
import os
import struct
import math
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.deps import PILImage, HAS_PIL
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

    unique = set(alpha_values)
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
    """Detecte et extrait la steganographie dans les images."""
    name = "stego"
    supported_extensions = ('.jpg', '.jpeg', '.png', '.bmp', '.tiff')

    def analyze(self, path: str) -> FindingModel | None:
        if not HAS_PIL:
            log.error("Pillow requis pour l'analyse stego - pip install Pillow")
            return None
        try:
            results: dict = {"file": os.path.basename(path)}

            with PILImage.open(path) as img:
                width, height = img.size
                results["dimensions"] = f"{width}x{height}"
                results["mode"] = img.mode
                results["format"] = str(img.format)

                # 1. Analyse LSB
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

            # 4. DCT pour JPEG
            if path.lower().endswith(('.jpg', '.jpeg')):
                results["dct_analysis"] = _analyze_dct_jpeg(path)

            # 5. Verdict global
            suspicion_score = 0
            if chi_lsb.get("detected"):
                suspicion_score += 3
            if results.get("alpha_analysis", {}).get("suspicious"):
                suspicion_score += 2
            if results.get("dct_analysis", {}).get("chi_square", {}).get("detected"):
                suspicion_score += 3

            if suspicion_score >= 3:
                verdict = "STEGO PROBABLE"
            elif suspicion_score >= 1:
                verdict = "SUSPECT"
            else:
                verdict = "CLEAN"

            results["verdict"] = verdict
            results["suspicion_score"] = suspicion_score

            # Construire les metadata plates pour affichage
            flat_meta = {
                "Format": results.get("format", "?"),
                "Dimensions": results.get("dimensions", "?"),
                "Mode": results.get("mode", "?"),
                "Verdict": verdict,
                "Score suspicion": str(suspicion_score),
                "LSB Entropy": str(results["lsb_analysis"]["entropy"]),
                "LSB Chi2": str(chi_lsb.get("score", "N/A")),
                "LSB Chi2 Detect": str(chi_lsb.get("detected", False)),
                "LSB Preview": results["lsb_analysis"]["printable_preview"],
            }

            if "alpha_analysis" in results:
                aa = results["alpha_analysis"]
                flat_meta["Alpha Suspect"] = str(aa.get("suspicious", False))
                flat_meta["Alpha Detail"] = aa.get("detail", "N/A")

            if "dct_analysis" in results:
                da = results["dct_analysis"]
                flat_meta["DCT Analyse"] = str(da.get("analyzed", False))
                flat_meta["DCT Detail"] = da.get("detail", "N/A")

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
