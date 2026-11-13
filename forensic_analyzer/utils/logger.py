"""Logging structuré et coloré en ANSI pour Forensic Analyzer."""

import json
import logging
import os
import re
import sys
from datetime import datetime, UTC

from forensic_analyzer.utils.terminal import neutralize

# Couleurs ANSI 256
MG1 = "\033[38;5;28m"  # Vert sombre (Hacker)
MG2 = "\033[38;5;34m"  # Vert moyen (Hacker)
MG3 = "\033[38;5;75m"  # Bleu ciel / Cyan
MG4 = "\033[38;5;141m"  # Violet clair
MG5 = "\033[38;5;46m"  # Vert vif (Hacker)
MG6 = "\033[38;5;220m"  # Or / Jaune

COLOR_RESET = "\033[0m"

HR = "\033[38;5;196m"  # Hacker Red / Alert
HY = "\033[38;5;220m"  # Gold

PURPLE = MG4
COLOR_TIME = MG2
COLOR_MUTED = MG1
COLOR_CYAN = MG3
COLOR_YELLOW = HY
COLOR_RED = HR

LEVEL_COLORS = {
    "DEBUG": COLOR_MUTED,
    "INFO": COLOR_CYAN,
    "WARNING": COLOR_YELLOW,
    "ERROR": COLOR_RED,
    "CRITICAL": COLOR_RED,
}

TAG_RE = re.compile(r"^\[([A-Z0-9_ -]+)\]")


class ColoredFormatter(logging.Formatter):
    """Formatter logging personnalisé colorant chaque élément du log."""

    def format(self, record: logging.LogRecord) -> str:
        time_str = f"{COLOR_TIME}{self.formatTime(record, '%H:%M:%S')}{COLOR_RESET}"

        level_raw = record.levelname
        lvl_color = LEVEL_COLORS.get(level_raw, COLOR_MUTED)
        level_str = f"{lvl_color}[{level_raw:<5}]{COLOR_RESET}"

        # 3. Logger name (Sky Blue / Muted) - padé à 24 chars pour alignement
        logger_name = f"{COLOR_CYAN}{record.name:<24}{COLOR_RESET}"

        msg = neutralize(record.getMessage())

        # Coloration des tags comme [PDF]
        tag_match = TAG_RE.match(msg)
        if tag_match:
            tag = tag_match.group(1)
            msg = msg.replace(f"[{tag}]", f"{PURPLE}[{tag}]{MG3}")

        # Coloration de la flèche
        msg = msg.replace("→", f"{COLOR_CYAN}→{COLOR_RESET}")

        # Le séparateur '-' en gris, le message en clair
        return f"{time_str} {level_str} {logger_name} {COLOR_MUTED}-{COLOR_RESET} {MG5}{msg}{COLOR_RESET}"


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


# Journal d'exécution JSON lines (--log-json) : ajouté à tous les loggers, présents et futurs
_json_handlers: list[logging.Handler] = []
_console_level = logging.NOTSET  # --quiet : WARNING

# Secrets jamais écrits : « api_key=… », « token: … » et la valeur des clés connues de l'environnement
_SECRET_RE = re.compile(r"(?i)\b((?:api|auth)[_-]?key|token|password|passwd|secret|x-apikey)(\s*[=:]\s*)(\S+)")
_SECRET_ENV = ("VT_API_KEY", "ABUSECH_AUTH_KEY")
_MIN_SECRET_LEN = 6  # une valeur plus courte masquerait des mots ordinaires


def redact(text: str) -> str:
    """Masque les secrets d'un message avant écriture dans un journal."""
    text = _SECRET_RE.sub(r"\1\2***", text)
    for var in _SECRET_ENV:
        value = os.environ.get(var)
        if value and len(value) >= _MIN_SECRET_LEN:
            text = text.replace(value, "***")
    return text


def _redact_value(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list | tuple):
        return [_redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    return value


class JSONLinesFormatter(logging.Formatter):
    """Une ligne JSON par message, champs à la manière ECS (@timestamp, log.level, event.action)."""

    def format(self, record: logging.LogRecord) -> str:
        moment = datetime.fromtimestamp(record.created, UTC)
        doc = {
            "@timestamp": moment.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "log.level": record.levelname.lower(),
            "log.logger": record.name,
            "process.pid": record.process,
            "message": redact(record.getMessage()),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            doc.update(_redact_value(fields))
        return json.dumps(doc, ensure_ascii=False, default=str)


def _forensic_loggers() -> list[logging.Logger]:
    names = [n for n in logging.Logger.manager.loggerDict if n.startswith("forensic.")]
    return [logging.getLogger(n) for n in names]


def enable_json_log(path: str) -> logging.Handler:
    """Ajoute le journal JSON lines (mode ajout : plusieurs exécutions dans le même fichier)."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    handler = logging.FileHandler(path, mode="a", encoding="utf-8")
    handler.setFormatter(JSONLinesFormatter())
    _json_handlers.append(handler)
    for logger in [*_forensic_loggers(), run_logger()]:
        logger.addHandler(handler)
    return handler


def disable_json_log(handler: logging.Handler) -> None:
    if handler in _json_handlers:
        _json_handlers.remove(handler)
    for logger in [*_forensic_loggers(), run_logger()]:
        logger.removeHandler(handler)
    handler.close()


def set_console_level(level: int) -> None:
    """--quiet : seuls avertissements et erreurs des modules restent à l'écran."""
    global _console_level
    _console_level = level
    for logger in _forensic_loggers():
        for h in logger.handlers:
            if isinstance(h, DynamicStreamHandler):
                h.setLevel(level)


def run_logger() -> logging.Logger:
    """Logger des événements d'exécution : uniquement dans le journal JSON, jamais à l'écran."""
    logger = logging.getLogger("forensic_run")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def log_event(action: str, message: str, level: int = logging.INFO, **fields) -> None:
    """Événement d'orchestration (début, export, fin...) ; sans journal JSON, ne fait rien."""
    if _json_handlers:
        run_logger().log(level, message, extra={"fields": {"event.action": action, **fields}})


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Retourne un logger configuré sous l'espace de noms `forensic.<name>`."""
    logger = logging.getLogger(f"forensic.{name}")
    if not logger.handlers:
        h = DynamicStreamHandler()
        h.setFormatter(ColoredFormatter())
        h.setLevel(_console_level)
        logger.addHandler(h)
    for jh in _json_handlers:
        if jh not in logger.handlers:
            logger.addHandler(jh)
    logger.setLevel(level)
    logger.propagate = False
    return logger
