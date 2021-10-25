#!/usr/bin/env python3
import json
import sys
import os
import logging

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from vat_container_status import is_approved  # noqa E402


def main():
    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")

    vat_response = {}
    with open(f"{os.environ['ARTIFACT_STORAGE']}/vat/vat_response.json", "r") as f:
        vat_response = json.load(f)

    exit_code, _, _ = is_approved(vat_response, True)
    logging.debug(f"EXIT CODE returned from is_approved function: {exit_code}")
    if exit_code == 0:
        logging.info("This pipeline passed the Check CVEs job")
    else:
        logging.error("This pipeline failed the Check CVEs job")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
