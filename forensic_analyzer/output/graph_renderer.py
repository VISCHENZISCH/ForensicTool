from forensic_analyzer.utils.logger import get_logger

log = get_logger("pcap.graph")

try:
    from pyvis.network import Network
    HAS_PYVIS = True
except ImportError:
    HAS_PYVIS = False

def generate_network_graph(output_path: str, pcap_summary: dict):
    """Génère un graphe HTML interactif des communications réseau via PyVis."""
    if not HAS_PYVIS:
        log.warning("PyVis n'est pas installé. Ignorer la génération du graphe.")
        return None
        
    try:
        net = Network(height='750px', width='100%', bgcolor='#222222', font_color='white')
        net.barnes_hut() # Algorithme de physique
        
        # Le noeud central (La victime / Les cibles)
        # On va créer le graphe en utilisant les informations de la timeline et des identités
        
        added_nodes = set()
        
        def add_node(node_id, label, group, color):
            if node_id not in added_nodes:
                net.add_node(node_id, label=label, group=group, color=color, shape='dot' if group != 'victim' else 'diamond', size=20 if group != 'victim' else 35)
                added_nodes.add(node_id)
                
        # On ajoute un noeud victime si on l'a (via Asset & Identity)
        # Mais pour simplifier, on boucle sur timeline ou ipsource/dest
        
        if "timeline" in pcap_summary and pcap_summary["timeline"]:
            for event in pcap_summary["timeline"]:
                desc = event["desc"]
                if "suspect:" in desc or "C2:" in desc or "Payload:" in desc:
                    # Extraction grossière du domaine/IP
                    parts = desc.split(':')
                    if len(parts) > 1:
                        target = parts[-1].strip()
                        add_node("Victim", "Victim Host", "victim", "#00ffcc")
                        
                        color = "#ff3333" if "C2" in desc else "#ffaa00"
                        group = "c2" if "C2" in desc else "malicious_domain"
                        
                        add_node(target, target, group, color)
                        net.add_edge("Victim", target, title=event["type"], color=color)
        
        if len(added_nodes) < 2:
            log.warning("Pas assez d'événements suspects pour tracer un graphe.")
            return None
            
        net.save_graph(output_path)
        log.info(f"Graphe réseau généré : {output_path}")
        return output_path
    except Exception as e:
        log.error(f"Erreur lors de la création du graphe : {e}")
        return None
