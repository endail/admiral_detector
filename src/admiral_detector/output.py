import json
import logging
import os
import subprocess
from typing import Any, Dict

logger = logging.getLogger("AdmiralDetector")


def write_json_output(data: Dict[str, Any], filepath: str) -> None:
    try:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Wrote JSON payload to {filepath}")
    except Exception as e:
        logger.error(f"Failed to write JSON output to {filepath}: {e}")


def run_post_scripts(script_dir: str, payload_path: str) -> None:
    if(not script_dir or not os.path.exists(script_dir)):
        logger.info("No post-script directory configured or found. Skipping.")
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
