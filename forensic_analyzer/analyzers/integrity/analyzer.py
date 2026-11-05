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
        return integrity_finding(path, res, phase) if res["results"] else None


def integrity_finding(path: str, res: dict, phase: str = "") -> FindingModel:
    """Constat d'intégrité à partir du résultat de verify_manifest (complété ou non par locate_in_evidence)."""
    meta = {"Phase": f"Vérification {phase}".strip(), "Horodatage (UTC)": res["checked_at"]}
    if res.get("base_label"):
        meta["Racine retrouvée"] = f"{res['base_label']} (chemins du manifeste relatifs à ce dossier, pas au sien)"
    for r in res["results"]:
        key = f"{r['file']} ({r['algo']})"
        value = f"{r['status']} {r['actual'] or r['expected']}"
        if r.get("lookalike"):
            value += f" (attendu : {r['path']} ; homonyme non vérifié : {r['lookalike']})"
        meta[f"[ALERTE] {key}" if r["status"] == "DIFFÉRENT" else key] = value

    results = res["results"]
    diff_count = sum(1 for r in results if r["status"] == "DIFFÉRENT")
    absent_count = sum(1 for r in results if r["status"] == "ABSENT")
    outside_count = sum(1 for r in results if r["status"] == "HORS PÉRIMÈTRE")
    uncovered = res.get("uncovered", [])

    # Une empreinte différente prouve une altération ; un fichier introuvable empêche seulement de conclure
    others = ", ".join(
        part
        for part in (
            f"{absent_count} introuvable(s)" if absent_count else "",
            f"{outside_count} hors périmètre" if outside_count else "",
        )
        if part
    )
    if res["all_ok"]:
        meta["Verdict"] = (
            f"Les {len(results)} fichier(s) du manifeste sont intacts ; {len(uncovered)} autre(s) du même dossier non couvert(s)"
            if uncovered
            else "Toutes les preuves sont intactes"
        )
    elif diff_count:
        meta["Verdict"] = f"[ALERTE] Preuves altérées : {diff_count} empreinte(s) différente(s)" + (
            f", {others}" if others else ""
        )
    else:
        meta["Verdict"] = (
            f"Vérification incomplète : {others} (aucune empreinte différente ; "
            "vérifier les chemins du manifeste ou --evidence-dir)"
        )
    if uncovered:
        meta["[ATTENTION] Hors manifeste"] = ", ".join(uncovered)
    unverified = [f"{r['file']} : {r['status'].lower()}" for r in results if r["status"] in ("ABSENT", "HORS PÉRIMÈTRE")]
    if uncovered:
        unverified.append(f"{len(uncovered)} fichier(s) sans empreinte attendue, intégrité non attestée")
    return FindingModel(
        type="evidence_integrity",
        file=path,
        metadata=meta,
        extra=res,
        severity="critique" if diff_count else "info",
        incomplete=unverified,
    )
