"""Vérification des manifestes d'empreintes des preuves (sha256sum, md5sum...)."""
from __future__ import annotations

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.core.integrity import verify_manifest
from forensic_analyzer.models.finding import FindingModel


class IntegrityAnalyzer(BaseAnalyzer):
    """Recalcule les empreintes listées dans un manifeste et les compare."""
    name = "integrity"
    supported_extensions = (".sha256", ".sha1", ".md5", ".sha512")

    def analyze(self, path: str, phase: str = "", evidence_dir: str | None = None) -> FindingModel | None:
        # Sans phase : manifeste découvert pendant un scan, donc fourni avec les preuves
        res = verify_manifest(path, confined=not phase, evidence_dir=evidence_dir)
        if not res["results"]:
            return None
        meta = {"Phase": f"Vérification {phase}".strip(), "Horodatage (UTC)": res["checked_at"]}
        for r in res["results"]:
            key = f"{r['file']} ({r['algo']})"
            meta[key if r["status"] == "OK" else f"[ALERTE] {key}"] = f"{r['status']} {r['actual'] or r['expected']}"

        results = res["results"]
        ok_count = sum(1 for r in results if r["status"] == "OK")
        diff_count = sum(1 for r in results if r["status"] == "DIFFÉRENT")
        absent_count = sum(1 for r in results if r["status"] == "ABSENT")
        outside_count = sum(1 for r in results if r["status"] == "HORS PÉRIMÈTRE")

        if res["all_ok"]:
            meta["Verdict"] = "Toutes les preuves sont intactes"
        else:
            verdict_parts = []
            if diff_count:
                verdict_parts.append(f"{diff_count} altérée(s)")
            if absent_count:
                verdict_parts.append(f"{absent_count} introuvable(s)")
            if outside_count:
                verdict_parts.append(f"{outside_count} hors périmètre")
            breakdown = ", ".join(verdict_parts)
            meta["Verdict"] = f"[ALERTE] Intégrité non confirmée ({breakdown})"
        return FindingModel(type="evidence_integrity", file=path, metadata=meta, extra=res)
