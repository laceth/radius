# myframework/logger.py

import logging
import sys
from logging.handlers import RotatingFileHandler

log = logging.getLogger("myframework")

if not log.handlers:
    log.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_fmt = logging.Formatter(
        "[%(levelname)s] %(message)s"
    )
    console_handler.setFormatter(console_fmt)

    # --- File handler ---
    file_handler = RotatingFileHandler(
        "framework.log", maxBytes=2_000_000, backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_fmt)

    # --- Add handlers ---
    log.addHandler(console_handler)
    log.addHandler(file_handler)

    # Optional: avoid propagating to root logger
    log.propagate = False
