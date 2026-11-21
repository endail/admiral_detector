import json
import logging
import os
import subprocess
import sys
from typing import Any, Dict

from .config import STDOUT_TARGET

logger = logging.getLogger("AdmiralDetector")


def write_json_output(data: Dict[str, Any], filepath: str) -> None:
    serialised = json.dumps(data, indent=2) + "\n"

    if(filepath == STDOUT_TARGET):
        sys.stdout.write(serialised)
        sys.stdout.flush()
        return

    try:
        abs_path = os.path.abspath(filepath)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        temp_path = f"{abs_path}.tmp.{os.getpid()}"
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(serialised)
        os.replace(temp_path, abs_path)
        logger.info(f"Wrote JSON payload to {filepath}")
    except Exception as e:
        logger.error(f"Failed to write JSON output to {filepath}: {e}")


def run_post_scripts(script_dir: str, payload_path: str) -> None:
    if(not script_dir or not os.path.exists(script_dir)):
        logger.info("No post-script directory configured or found. Skipping.")
        return

    if(not payload_path or payload_path == STDOUT_TARGET):
        logger.warning("Skipping post-scripts because output_file is set to stdout.")
        return

    logger.info(f"Scanning for executable post-scripts in: {script_dir}")
    try:
        scripts = sorted(os.listdir(script_dir))
        for script in scripts:
            script_path = os.path.join(script_dir, script)
            if(os.path.isfile(script_path) and os.access(script_path, os.X_OK)):
                logger.info(f"Executing: {script_path}")
                try:
                    result = subprocess.run(
                        [script_path, payload_path],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    if(result.stdout):
                        logger.info(f"Output ({script}):\n{result.stdout.strip()}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed ({script}): {e.stderr.strip()}")
    except Exception as e:
        logger.error(f"Error processing post-scripts: {e}")