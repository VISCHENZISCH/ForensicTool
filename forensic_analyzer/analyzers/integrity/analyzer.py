"""Verification des manifestes d'empreintes des preuves (sha256sum, md5sum...)."""
from __future__ import annotations

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.core.integrity import verify_manifest
from forensic_analyzer.models.finding import FindingModel


class IntegrityAnalyzer(BaseAnalyzer):
    """Recalcule les empreintes listees dans un manifeste et les compare."""
    name = "integrity"
    supported_extensions = (".sha256", ".sha1", ".md5", ".sha512")

    def analyze(self, path: str, phase: str = "") -> FindingModel | None:
        res = verify_manifest(path)
        if not res["results"]:
            return None
        meta = {"Phase": f"Verification {phase}".strip(), "Horodatage (UTC)": res["checked_at"]}
        for r in res["results"]:
            key = f"{r['file']} ({r['algo']})"
            meta[key if r["status"] == "OK" else f"[ALERTE] {key}"] = f"{r['status']} {r['actual'] or r['expected']}"
        meta["Verdict"] = "Toutes les preuves sont intactes" if res["all_ok"] else "[ALERTE] Integrite non confirmee"
        return FindingModel(type="evidence_integrity", file=path, metadata=meta, extra=res)
