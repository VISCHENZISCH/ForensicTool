"""Logging structuré et coloré en ANSI pour Forensic Analyzer."""
import logging
import sys
import re

# Constantes de couleurs ANSI 256 de WebMapper
CRIMSON   = "\033[38;5;196m"
EMERALD   = "\033[38;5;46m"
GOLD      = "\033[38;5;220m"
SKY_BLUE  = "\033[38;5;39m"
PURPLE    = "\033[38;5;141m"
DARK_GREY = "\033[38;5;243m"
COLOR_RESET = "\033[0m"

COLOR_TIME = EMERALD
COLOR_MUTED = DARK_GREY
COLOR_CYAN = SKY_BLUE
COLOR_BRIGHT_BLUE = SKY_BLUE
COLOR_YELLOW = GOLD
COLOR_RED = CRIMSON

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
        level_str = f"{lvl_color}[{level_raw:<8}]{COLOR_RESET}"

        # 3. Logger name (Sky Blue / Muted)
        logger_name = f"{COLOR_CYAN}{record.name}{COLOR_RESET}"

        # 4. Message
        msg = record.getMessage()

        # Coloration des tags comme [PDF]
        tag_match = TAG_RE.match(msg)
        if tag_match:
            tag = tag_match.group(1)
            msg = msg.replace(f"[{tag}]", f"{PURPLE}[{tag}]{COLOR_RESET}")

        # Coloration de la flèche
        msg = msg.replace("→", f"{COLOR_RED}→{COLOR_RESET}")

        # Pas de marge ici : elle est déléguée au wrapper de flux global
        return f"{time_str} {level_str} {logger_name} — {msg}"


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Retourne un logger configuré sous l'espace de noms `forensic.<name>`."""
    logger = logging.getLogger(f"forensic.{name}")
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout) # Redirige vers stdout pour bénéficier du wrapper
        h.setFormatter(ColoredFormatter())
        logger.addHandler(h)
    logger.setLevel(level)
    logger.propagate = False
    return logger
