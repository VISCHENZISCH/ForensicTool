"""Helpers d'affichage partagés entre les renderers."""
from forensic_analyzer.utils.deps import HAS_RICH, Console


class ANSI:
    """Codes couleur ANSI de secours pour les terminaux sans Rich."""
    BLUE   = "\033[94m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


ansi: ANSI = ANSI()
console = Console() if HAS_RICH else None
