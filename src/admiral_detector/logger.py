import logging
import os
import sys
from typing import Optional


def setup_logger(level_name: str, log_file: Optional[str] = None) -> logging.Logger:
    level = getattr(logging, level_name.upper(), logging.INFO)

    logger = logging.getLogger("AdmiralDetector")
    logger.setLevel(level)
    logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if(log_file):
        try:
            parent = os.path.dirname(os.path.abspath(log_file))
            if(parent):
                os.makedirs(parent, exist_ok=True)
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:
            logger.warning(f"Could not setup file logging to {log_file}: {e}")

    return logger
