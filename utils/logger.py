"""
utils/logger.py — Centralised logging configuration.
Each subsystem gets its own log file + shared console output.
"""

import logging
import os
import sys

# Create logs directory if absent
os.makedirs("logs", exist_ok=True)

_FMT = "%(asctime)s | %(levelname)-8s | %(name)-10s | %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


def _build_logger(name: str, log_file: str, level: int = logging.INFO) -> logging.Logger:
    formatter = logging.Formatter(_FMT, datefmt=_DATE_FMT)

    file_handler = logging.FileHandler(f"logs/{log_file}", encoding="utf-8")
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:  # Prevent duplicate handlers on reimport
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger


# ── Public logger instances ───────────────────────────────────
system_logger   = _build_logger("SYSTEM",   "system.log")
feed_logger     = _build_logger("FEEDS",    "feeds.log")
enforcer_logger = _build_logger("FIREWALL", "firewall.log")
alert_logger    = _build_logger("ALERTS",   "alerts.log")
dashboard_logger= _build_logger("DASHBOARD","dashboard.log")
