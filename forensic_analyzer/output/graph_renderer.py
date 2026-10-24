"""Graphe interactif de la chaîne de compromission (artefacts ↔ indicateurs partagés)."""
from __future__ import annotations

from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("graph")

try:
    from pyvis.network import Network
    HAS_PYVIS = True
except ImportError:
    HAS_PYVIS = False

_GROUP_COLORS = {
    "ioc": "#ff4d4d", "disk": "#8c8c8c", "linux_artifacts": "#f5a623", "memory": "#6fa8ff",
    "elf_analysis": "#d0021b", "malware_analysis": "#d0021b", "pcap": "#00c2a8", "evtx": "#4ac0ff",
    "registry": "#9b6bff", "chromium_artifacts": "#2f80ed", "firefox_places": "#ff7a00",
    "prefetch": "#e0c341", "lnk_shortcut": "#b8962e", "ids_alerts": "#ff2d55",
}


def render_correlation_graph(correlation: FindingModel, output_path: str) -> str | None:
    """Écrit un HTML autonome (JS embarqué : pas de dossier lib/, pas de CDN)."""
    if not HAS_PYVIS:
        log.warning("pyvis absent : graphe non généré (pip install pyvis).")
        return None
    graph = correlation.extra.get("graph", {})
    if not graph.get("edges"):
        log.info("Aucun indicateur partagé entre sources : pas de graphe.")
        return None

    net = Network(height="800px", width="100%", bgcolor="#14161a", font_color="#e8e8e8",
                  directed=False, cdn_resources="in_line")
    net.barnes_hut(gravity=-6000, spring_length=160)
    for node in graph["nodes"]:
        is_ioc = node["group"] == "ioc"
        net.add_node(node["id"], label=node["label"], title=node["title"],
                     color=_GROUP_COLORS.get(node["group"], "#bbbbbb"),
                     shape="diamond" if is_ioc else "box", size=18 if is_ioc else 25)
    for edge in graph["edges"]:
        net.add_edge(edge["from"], edge["to"], title=edge["title"], color="#666666")

    net.write_html(output_path, notebook=False)
    log.info("Graphe de corrélation généré : %s", output_path)
    return output_path
