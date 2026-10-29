"""Corrélation des indicateurs entre sources (disque, mémoire, réseau, journaux, navigateurs...).

Un indicateur vu par au moins deux sources indépendantes (ex : un chemin trouvé sur le
disque et dans un processus en mémoire) relie ces artefacts dans la chaîne de compromission.
"""
from __future__ import annotations

from forensic_analyzer.core import iocs as ioc_mod
from forensic_analyzer.core import mitre
from forensic_analyzer.models.finding import FindingModel

# Libellés lisibles des sources
SOURCE_LABELS = {
    "disk": "Disque", "linux_artifacts": "Artefacts Linux", "memory": "Mémoire", "elf_analysis": "Binaire ELF",
    "malware_analysis": "Binaire PE", "pdf_analysis": "PDF", "pcap": "Réseau (PCAP)", "evtx": "Journaux Windows",
    "registry": "Registre", "chromium_artifacts": "Navigateur Chromium", "firefox_places": "Navigateur Firefox",
    "prefetch": "Prefetch", "lnk_shortcut": "Raccourci LNK", "ids_alerts": "IDS", "ioc": "Extraction IOC",
}
# Poids des types d'indicateurs pour classer les corrélations
_KIND_WEIGHT = {"sha256": 5, "md5": 5, "ipv4": 4, "domain": 4, "url": 4, "ja3": 4,
                "path": 3, "service": 3, "filename": 2}


def correlate(findings: list[FindingModel]) -> FindingModel | None:
    """Résultat « correlation » : indicateurs partagés, graphe et techniques ATT&CK consolidées."""
    findings = [f for f in findings if f.type not in ("correlation", "timeline")]
    all_iocs = ioc_mod.collect(findings)
    shared = [i for i in all_iocs if len(i.sources) >= 2]
    # Un chemin implique son nom de fichier : on n'affiche pas les doublons nom/chemin
    shared_paths = {i.value.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower() for i in shared if i.kind == "path"}
    shared = [i for i in shared if not (i.kind == "filename" and i.value in shared_paths
                                        and _same_sources(i, shared))]
    shared.sort(key=lambda i: (-len(i.sources), -_KIND_WEIGHT.get(i.kind, 1), i.value))

    techniques = set()
    for f in findings:
        techniques.update(t["id"] for t in f.extra.get("mitre", []) if isinstance(t, dict))
        if isinstance(f.metadata.get("MITRE ATT&CK"), str):
            techniques.update(part.split(" ", 1)[0] for part in f.metadata["MITRE ATT&CK"].split(", "))

    if not all_iocs and not techniques:
        return None

    meta: dict = {
        "Indicateurs extraits": f"{len(all_iocs)} ({_count_by_kind(all_iocs)})",
        "Indicateurs partagés par plusieurs sources": str(len(shared)),
    }
    for i in shared[:25]:
        sources = ", ".join(SOURCE_LABELS.get(s, s) for s in sorted(i.sources))
        meta[f"[CORRÉLATION] {i.value} ({i.kind})"] = sources
    if techniques:
        meta["MITRE ATT&CK (toutes sources)"] = mitre.summary(techniques)

    return FindingModel(
        type="correlation",
        file="multi-source",
        metadata=meta,
        extra={
            "iocs": [_ioc_dict(i) for i in all_iocs],
            "shared": [_ioc_dict(i) for i in shared],
            "graph": build_graph(findings, shared),
            "mitre": mitre.describe(techniques),
        },
    )


def build_graph(findings: list[FindingModel], shared: list[ioc_mod.IOC]) -> dict:
    """Graphe artefacts ↔ indicateurs partagés (nœuds et arêtes sérialisables)."""
    nodes, edges = {}, []
    for i in shared:
        ioc_id = f"ioc:{i.kind}:{i.value}"
        nodes[ioc_id] = {"id": ioc_id, "label": i.value if len(i.value) < 48 else "…" + i.value[-45:],
                         "group": "ioc", "kind": i.kind, "title": f"{i.kind} : {i.value}"}
        for obs in i.observations:
            art_id = f"art:{obs.source}:{obs.artifact}"
            nodes.setdefault(art_id, {"id": art_id, "label": f"{SOURCE_LABELS.get(obs.source, obs.source)}\n{obs.artifact[-40:]}",
                                      "group": obs.source, "kind": "artifact", "title": obs.artifact})
            edge = {"from": art_id, "to": ioc_id, "title": obs.context}
            if edge not in edges:
                edges.append(edge)
    return {"nodes": list(nodes.values()), "edges": edges}


def _same_sources(filename_ioc, shared) -> bool:
    return any(i.kind == "path" and i.value.lower().endswith(filename_ioc.value) and i.sources >= filename_ioc.sources
               for i in shared)


def _count_by_kind(all_iocs) -> str:
    counts: dict[str, int] = {}
    for i in all_iocs:
        counts[i.kind] = counts.get(i.kind, 0) + 1
    return ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))


def _ioc_dict(i: ioc_mod.IOC) -> dict:
    return {"kind": i.kind, "value": i.value, "sources": sorted(i.sources),
            "observations": [{"source": o.source, "artifact": o.artifact, "context": o.context}
                             for o in i.observations]}
