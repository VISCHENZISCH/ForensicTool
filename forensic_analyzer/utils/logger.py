"""Logging structuré et coloré en ANSI pour Forensic Analyzer."""
import logging
import re
import sys

# Constantes de couleurs Matrix Theme
MG1 = "\033[38;5;22m"  # Très sombre
MG2 = "\033[38;5;28m"  # Sombre
MG3 = "\033[38;5;34m"  # Hacker Green
MG4 = "\033[38;5;40m"  # Vert clair
MG5 = "\033[38;5;46m"  # Émeraude vif
MG6 = "\033[38;5;118m" # Vert-Jaune intense
COLOR_RESET = "\033[0m"

HR = "\033[38;5;196m"  # Hacker Red
HY = "\033[38;5;226m"  # Hacker Yellow

PURPLE = MG3  
COLOR_TIME = MG5
COLOR_MUTED = MG1
COLOR_CYAN = MG4
COLOR_BRIGHT_BLUE = MG4
COLOR_YELLOW = HY
COLOR_RED = HR

LEVEL_COLORS = {
    "DEBUG": COLOR_MUTED,
    "INFO": COLOR_BRIGHT_BLUE,
    "WARNING": COLOR_YELLOW,
    "ERROR": COLOR_RED,
    "CRITICAL": COLOR_RED,
}

TAG_RE = re.compile(r"^\[([A-Z0-9_ -]+)\]")

class ColoredFormatter(logging.Formatter):
    """Formatter logging personnalisé colorant chaque élément du log."""

    def format(self, record: logging.LogRecord) -> str:
        # 1. Horodatage (Vert émeraude)
        time_str = f"{COLOR_TIME}{self.formatTime(record, '%H:%M:%S')}{COLOR_RESET}"

        # 2. Niveau (Couleur correspondante)
        level_raw = record.levelname
        lvl_color = LEVEL_COLORS.get(level_raw, COLOR_MUTED)
        level_str = f"{lvl_color}[{level_raw:<5}]{COLOR_RESET}"

        # 3. Logger name (Sky Blue / Muted) — padé à 24 chars pour alignement
        logger_name = f"{COLOR_CYAN}{record.name:<24}{COLOR_RESET}"

        # 4. Message
        msg = record.getMessage()

        # Coloration des tags comme [PDF]
        tag_match = TAG_RE.match(msg)
        if tag_match:
            tag = tag_match.group(1)
            msg = msg.replace(f"[{tag}]", f"{PURPLE}[{tag}]{MG3}")

        # Coloration de la flèche
        msg = msg.replace("→", f"{COLOR_RED}→{MG3}")

        # Le séparateur '-' en jaune, le message en Hacker Green
        return f"{time_str} {level_str} {logger_name} {HY}-{COLOR_RESET} {MG3}{msg}{COLOR_RESET}"


class DynamicStreamHandler(logging.StreamHandler):
    """Handler qui résout sys.stdout de manière dynamique au moment du log."""
    def __init__(self):
        super().__init__()

    @property
    def stream(self):
        return sys.stdout

    @stream.setter
    def stream(self, value):
        pass


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Retourne un logger configuré sous l'espace de noms `forensic.<name>`."""
    logger = logging.getLogger(f"forensic.{name}")
    if not logger.handlers:
        h = DynamicStreamHandler() # Utilise le handler dynamique pour bénéficier du wrapper de marge
        h.setFormatter(ColoredFormatter())
        logger.addHandler(h)
    logger.setLevel(level)
    logger.propagate = False
    return logger
