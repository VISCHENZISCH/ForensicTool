#!/usr/bin/env python3
# coding: utf-8
"""
Forensic Analyzer - Point d'entree principal.
Lance le menu interactif (sans arguments) ou le mode CLI (avec arguments).
"""

from forensic_analyzer.cli.main import main
from forensic_analyzer.output.graph_renderer import generate_network_graph

if __name__ == "__main__":
    import sys
    # Injection pour generer le graphe si on analyse un pcap
    # Note: On devrait idealement le faire dans cli.main, mais on l'ajoute comme patch post-analyse
    # main() gere sa propre boucle, donc c'est une option meilleur
    main()
